"""
内网端口发现系统 - 后端服务
多线程扫描引擎 + WebSocket实时推送 + REST API

架构：
  - 扫描引擎使用 ThreadPoolExecutor 多线程并发 socket 连接
  - Web 层使用 aiohttp 异步处理 HTTP/WS
  - 线程与协程之间通过 asyncio.Queue + run_in_executor 桥接
  - 线程安全：结果写入使用锁，进度更新使用线程安全计数器
"""
import os
import sys
import json
import time
import asyncio
import socket
import struct
import platform
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from queue import Queue as ThreadQueue

from aiohttp import web, WSMsgType
import aiohttp_cors


# ═══════════════════════════════════════
#  数据模型
# ═══════════════════════════════════════

@dataclass
class PortInfo:
    ip: str
    port: int
    status: str = "open"
    service: str = ""
    version: str = ""
    protocol: str = "tcp"
    banner: str = ""
    discovered_at: float = 0.0


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    mac: str = ""
    is_alive: bool = False
    os_hint: str = ""
    open_ports: List[PortInfo] = field(default_factory=list)
    last_seen: float = 0.0


@dataclass
class ScanTask:
    task_id: str
    targets: str
    ports: str
    status: str = "pending"  # pending | running | paused | completed | stopped
    progress: float = 0.0
    total_hosts: int = 0
    scanned_hosts: int = 0
    total_ports: int = 0
    scanned_ports: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    found_count: int = 0


# ═══════════════════════════════════════
#  服务指纹库
# ═══════════════════════════════════════

SERVICE_FINGERPRINTS = {
    21: ("ftp", "FTP"),
    22: ("ssh", "SSH"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "SMTP"),
    53: ("dns", "DNS"),
    80: ("http", "HTTP"),
    110: ("pop3", "POP3"),
    111: ("rpcbind", "RPCBind"),
    135: ("msrpc", "Microsoft RPC"),
    139: ("netbios-ssn", "NetBIOS Session"),
    143: ("imap", "IMAP"),
    443: ("https", "HTTPS"),
    445: ("microsoft-ds", "Microsoft DS (SMB)"),
    993: ("imaps", "IMAPS"),
    995: ("pop3s", "POP3S"),
    1433: ("mssql", "Microsoft SQL Server"),
    1521: ("oracle", "Oracle DB"),
    2181: ("zookeeper", "ZooKeeper"),
    2375: ("docker", "Docker API"),
    2376: ("docker-tls", "Docker TLS"),
    3306: ("mysql", "MySQL"),
    3389: ("ms-wbt-server", "RDP (Remote Desktop)"),
    5432: ("postgresql", "PostgreSQL"),
    5672: ("amqp", "RabbitMQ"),
    5900: ("vnc", "VNC"),
    6379: ("redis", "Redis"),
    6443: ("kubernetes-api", "Kubernetes API"),
    8080: ("http-proxy", "HTTP Proxy / Web App"),
    8443: ("https-alt", "HTTPS Alt"),
    8888: ("sun-answerbook", "Web App / Jupyter"),
    9000: ("php-fpm", "PHP-FPM / Portainer"),
    9090: ("zeus-admin", "Web Console"),
    9200: ("elasticsearch", "Elasticsearch"),
    9300: ("elasticsearch-transport", "ES Transport"),
    11211: ("memcached", "Memcached"),
    15672: ("rabbitmq-mgmt", "RabbitMQ Management"),
    27017: ("mongodb", "MongoDB"),
    27018: ("mongodb", "MongoDB Shard"),
    2888: ("kafka", "Kafka JMX"),
    9092: ("kafka", "Kafka Broker"),
}

BANNER_PROBES = {
    "http": b"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    "smtp": b"EHLO scan\r\n",
    "redis": b"INFO\r\n",
    "ftp": b"",
    "ssh": b"",
    "pop3": b"",
    "imap": b"",
}

BANNER_PATTERNS = {
    "ssh": [b"SSH-"],
    "ftp": [b"FTP", b"ftp", b"vsftpd", b"ProFTPD", b"FileZilla", b"220 "],
    "http": [b"HTTP/", b"Server:", b"<html", b"<!DOCTYPE"],
    "https": [b"HTTP/", b"Server:"],
    "smtp": [b"SMTP", b"ESMTP", b"Postfix", b"Exim"],
    "pop3": [b"POP3", b"+OK"],
    "imap": [b"IMAP", b"OK "],
    "mysql": [b"mysql", b"MariaDB", b"5.5.", b"8.0."],
    "redis": [b"redis_version", b"# Server"],
    "mongodb": [b"MongoDB"],
    "vnc": [b"RFB "],
    "telnet": [b"Telnet"],
    "microsoft-ds": [b"SMB", b"\x00\x00\x00"],
    "msrpc": [b"\x05\x00"],
}


# ═══════════════════════════════════════
#  多线程扫描引擎
# ═══════════════════════════════════════

class PortScanner:
    """
    多线程端口扫描引擎

    核心设计：
    - ThreadPoolExecutor 管理线程池，默认线程数 = CPU核心数 * 4（上限64）
    - 每个端口探测在独立线程中执行，用同步 socket 连接
    - 线程安全的进度计数器和结果收集
    - 通过 ThreadQueue 将发现结果传递到异步层进行 WebSocket 广播
    - 支持暂停/继续/停止（通过 threading.Event 控制）
    """

    def __init__(self, thread_count: int = None, timeout: float = 1.5):
        self.timeout = timeout
        # 线程数：默认 CPU*4，上限64
        cpu = os.cpu_count() or 4
        self.thread_count = min(thread_count or cpu * 4, 64)

        # ── 线程安全状态 ──
        self._lock = threading.Lock()          # 保护 results / scan_task
        self._stop_event = threading.Event()   # 停止信号
        self._pause_event = threading.Event()  # 暂停信号（set=运行, clear=暂停）
        self._pause_event.set()
        self._scanned_counter = 0              # 已扫描端口数（原子操作由 GIL 保护）
        self._found_counter = 0                # 已发现开放端口数

        # ── 数据 ──
        self.results: Dict[str, HostInfo] = {}
        self.scan_task: Optional[ScanTask] = None

        # ── 线程池（延迟初始化，按需创建）──
        self._executor: Optional[ThreadPoolExecutor] = None

        # ── 异步桥接 ──
        self._ws_clients: Set[web.WebSocketResponse] = set()
        self._notify_queue: Optional[asyncio.Queue] = None
        self._notify_task: Optional[asyncio.Task] = None

    def _get_executor(self) -> ThreadPoolExecutor:
        """懒初始化线程池"""
        if self._executor is None or self._executor._broken:
            self._executor = ThreadPoolExecutor(
                max_workers=self.thread_count,
                thread_name_prefix="scanner"
            )
        return self._executor

    # ──────────────── 目标解析 ────────────────

    def parse_targets(self, target_str: str) -> List[str]:
        """解析目标：192.168.1.1 | 192.168.1.0/24 | 192.168.1.1-100"""
        targets = set()
        for part in target_str.replace('\n', ',').split(','):
            part = part.strip()
            if not part:
                continue
            try:
                if '/' in part:
                    network = ipaddress.ip_network(part, strict=False)
                    for host in network.hosts():
                        targets.add(str(host))
                elif '-' in part and not part.startswith('-'):
                    base, end = part.rsplit('-', 1)
                    prefix = base.rsplit('.', 1)[0]
                    start = int(base.rsplit('.', 1)[1])
                    end_n = int(end)
                    for i in range(start, min(end_n + 1, start + 256)):
                        targets.add(f"{prefix}.{i}")
                else:
                    ipaddress.ip_address(part)
                    targets.add(part)
            except ValueError:
                continue
        return sorted(targets)

    def parse_ports(self, port_str: str) -> List[int]:
        """解析端口：80 | 1-1024 | 80,443,8080"""
        ports = set()
        for part in port_str.replace('\n', ',').split(','):
            part = part.strip()
            if not part:
                continue
            try:
                if '-' in part:
                    start, end = part.split('-', 1)
                    for p in range(int(start), min(int(end) + 1, 65536)):
                        ports.add(p)
                else:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                continue
        return sorted(ports)

    # ──────────────── 线程工作函数 ────────────────

    def _tcp_connect(self, ip: str, port: int) -> Optional[PortInfo]:
        """
        在线程中执行 TCP 连接探测（同步 socket）
        返回 PortInfo 如果端口开放，否则 None
        """
        # 检查控制信号
        if self._stop_event.is_set():
            return None
        # 暂停等待
        while not self._pause_event.is_set():
            if self._stop_event.is_set():
                return None
            time.sleep(0.1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                info = PortInfo(
                    ip=ip, port=port, status="open",
                    discovered_at=time.time()
                )
                # 服务识别
                svc = SERVICE_FINGERPRINTS.get(port, ("unknown", "Unknown"))
                info.service = svc[0]
                # Banner 抓取
                banner = self._grab_banner_thread(sock, ip, port, info.service)
                if banner:
                    info.banner = banner[:256]
                    info.version = self._parse_version(banner, info.service)
                return info
            return None
        except (OSError, socket.error):
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass
            self._scanned_counter += 1

    def _grab_banner_thread(self, sock: socket.socket, ip: str, port: int, service: str) -> str:
        """在线程中抓取 Banner（同步 socket 操作）"""
        try:
            # 发送探测包
            probe_key = service if service in BANNER_PROBES else None
            if probe_key:
                probe = BANNER_PROBES[probe_key].replace(b"{host}", ip.encode())
                if probe:
                    sock.sendall(probe)

            # 读取响应
            sock.settimeout(2.0)
            try:
                data = sock.recv(1024)
                if data:
                    try:
                        return data.decode('utf-8', errors='replace').strip()
                    except Exception:
                        return data.hex()[:64]
            except (socket.timeout, OSError):
                pass
        except (OSError, socket.error):
            pass
        return ""

    def _parse_version(self, banner: str, service: str) -> str:
        """从 Banner 解析版本"""
        if not banner:
            return ""
        banner_lower = banner.lower()
        version_patterns = {
            "ssh": ["ssh-"],
            "ftp": ["vsftpd", "proftpd", "filezilla", "pure-ftpd"],
            "http": ["server:"],
            "smtp": ["postfix", "exim", "sendmail"],
            "mysql": ["5.", "8.", "mariadb"],
            "redis": ["redis_version="],
        }
        patterns = version_patterns.get(service, [])
        for pat in patterns:
            idx = banner_lower.find(pat)
            if idx >= 0:
                line = banner[idx:idx + 64].split('\n')[0].split('\r')[0]
                return line.strip()
        first_line = banner.split('\n')[0].split('\r')[0][:64]
        return first_line.strip() if len(first_line) > 3 else ""

    def _check_alive_thread(self, ip: str, ping_ports: List[int]) -> bool:
        """在线程中探测主机是否存活（TCP ping + ICMP）"""
        # 先尝试 TCP ping 常见端口
        for p in ping_ports:
            if self._stop_event.is_set():
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout * 0.8)
            try:
                if sock.connect_ex((ip, p)) == 0:
                    sock.close()
                    return True
            except (OSError, socket.error):
                pass
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        # ICMP 回退
        try:
            if platform.system() == 'Windows':
                cmd = ['ping', '-n', '1', '-w', '500', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', ip]
            result = subprocess.run(
                cmd, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=2.0
            )
            return result.returncode == 0
        except Exception:
            return False

    def _resolve_hostname_thread(self, ip: str) -> str:
        """在线程中反向 DNS 解析"""
        try:
            name = socket.gethostbyaddr(ip)
            return name[0] if name[0] != ip else ""
        except (socket.herror, socket.gaierror, OSError):
            return ""

    # ──────────────── 扫描主流程 ────────────────

    async def scan(self, targets_str: str, ports_str: str, task_id: str):
        """
        执行完整扫描流程（三阶段）

        阶段1: 主机发现 — 多线程 TCP+ICMP ping
        阶段2: 端口扫描 — 多线程并发 TCP connect
        阶段3: 服务分析 — 汇总指纹、OS推断
        """
        targets = self.parse_targets(targets_str)
        ports = self.parse_ports(ports_str)
        if not targets or not ports:
            return

        # 初始化扫描任务
        with self._lock:
            self.scan_task = ScanTask(
                task_id=task_id,
                targets=targets_str,
                ports=ports_str,
                total_hosts=len(targets),
                total_ports=len(ports) * len(targets),
                start_time=time.time(),
                status="running"
            )
            self.results.clear()
            self._scanned_counter = 0
            self._found_counter = 0
            self._stop_event.clear()
            self._pause_event.set()

        await self._broadcast_ws({
            "type": "scan_start",
            "task": asdict(self.scan_task)
        })

        # 启动通知消费者
        self._start_notify_consumer()

        executor = self._get_executor()
        loop = asyncio.get_event_loop()

        # ── 阶段 1: 主机发现 ──
        await self._broadcast_ws({
            "type": "phase", "phase": "discovery",
            "message": "🔍 正在发现存活主机（多线程探测）..."
        })

        ping_ports = [22, 80, 443, 445, 3389]
        alive_hosts: List[str] = []

        # 多线程主机发现：每次提交全部目标到线程池
        host_futures = {
            executor.submit(self._check_alive_thread, ip, ping_ports): ip
            for ip in targets
        }

        discovered = 0
        for future in as_completed(host_futures):
            if self._stop_event.is_set():
                break
            ip = host_futures[future]
            try:
                is_alive = future.result(timeout=5.0)
            except Exception:
                is_alive = False

            discovered += 1
            if is_alive:
                alive_hosts.append(ip)

            # 更新进度
            with self._lock:
                if self.scan_task:
                    self.scan_task.scanned_hosts = discovered
                    self.scan_task.progress = (discovered / len(targets)) * 10

            await self._broadcast_ws({
                "type": "progress",
                "task": asdict(self.scan_task) if self.scan_task else None
            })

        await self._broadcast_ws({
            "type": "discovery_done",
            "alive_count": len(alive_hosts),
            "alive_hosts": sorted(alive_hosts)
        })

        if not alive_hosts or self._stop_event.is_set():
            await self._finish_scan()
            return

        # ── 阶段 2: 多线程端口扫描 ──
        await self._broadcast_ws({
            "type": "phase", "phase": "scanning",
            "message": f"🔌 正在扫描 {len(alive_hosts)} 台主机（{self.thread_count} 线程并发）..."
        })

        total_checks = len(alive_hosts) * len(ports)
        batch_size = self.thread_count * 8  # 每批提交的任务数 = 线程数 * 8

        # 为每台主机生成所有 (ip, port) 任务对
        all_tasks: List[Tuple[str, int]] = []
        for ip in alive_hosts:
            for port in ports:
                all_tasks.append((ip, port))

        # 分批提交到线程池，避免一次性提交过多任务占用内存
        port_futures = {}
        task_idx = 0

        # 预创建所有 HostInfo
        host_infos: Dict[str, HostInfo] = {}
        for ip in alive_hosts:
            host_infos[ip] = HostInfo(ip=ip, is_alive=True)

        # 异步在线程池中执行扫描，同时收集结果
        last_progress_broadcast = time.time()

        # 提交初始批次
        batch_end = min(batch_size, len(all_tasks))
        for i in range(batch_end):
            ip, port = all_tasks[i]
            f = executor.submit(self._tcp_connect, ip, port)
            port_futures[f] = (ip, port)
        task_idx = batch_end

        completed_in_batch = 0
        for future in as_completed(port_futures):
            if self._stop_event.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                break

            ip, port = port_futures[future]
            completed_in_batch += 1

            try:
                port_info = future.result(timeout=5.0)
            except Exception:
                port_info = None

            if port_info and port_info.status == "open":
                with self._lock:
                    host_infos[ip].open_ports.append(port_info)
                    self._found_counter += 1
                # 通知前端
                await self._notify({
                    "type": "port_found",
                    "ip": ip,
                    "port": asdict(port_info)
                })

            # 补充新任务到线程池
            if task_idx < len(all_tasks) and not self._stop_event.is_set():
                new_ip, new_port = all_tasks[task_idx]
                new_f = executor.submit(self._tcp_connect, new_ip, new_port)
                port_futures[new_f] = (new_ip, new_port)
                task_idx += 1

            # 节流进度广播（每 0.3s 或每批结束时）
            now = time.time()
            if now - last_progress_broadcast > 0.3 or completed_in_batch >= batch_size:
                last_progress_broadcast = now
                with self._lock:
                    if self.scan_task:
                        self.scan_task.scanned_ports = self._scanned_counter
                        self.scan_task.progress = 10 + (self._scanned_counter / max(total_checks, 1)) * 85
                        self.scan_task.found_count = self._found_counter

                await self._broadcast_ws({
                    "type": "progress",
                    "task": asdict(self.scan_task) if self.scan_task else None
                })
                completed_in_batch = 0

        # ── 阶段 3: 服务分析 ──
        await self._broadcast_ws({
            "type": "phase", "phase": "analysis",
            "message": "📊 正在分析服务指纹与操作系统..."
        })

        # 并行解析主机名
        hostname_futures = {}
        for ip in alive_hosts:
            if ip in host_infos:
                f = executor.submit(self._resolve_hostname_thread, ip)
                hostname_futures[f] = ip

        for future in as_completed(hostname_futures):
            ip = hostname_futures[future]
            try:
                hostname = future.result(timeout=3.0)
                host_infos[ip].hostname = hostname
            except Exception:
                pass

        # OS 推断
        for ip, host in host_infos.items():
            if not host.open_ports:
                continue
            port_numbers = {p.port for p in host.open_ports}
            if 445 in port_numbers or 3389 in port_numbers or 1433 in port_numbers:
                host.os_hint = "Windows"
            elif 22 in port_numbers:
                host.os_hint = "Linux/Unix"
            host.last_seen = time.time()

        # 写入最终结果
        with self._lock:
            self.results = {ip: h for ip, h in host_infos.items() if h.open_ports}

        await self._finish_scan()

    async def _finish_scan(self):
        """完成扫描，发送最终状态"""
        with self._lock:
            if self.scan_task:
                if self._stop_event.is_set():
                    self.scan_task.status = "stopped"
                else:
                    self.scan_task.status = "completed"
                self.scan_task.progress = 100
                self.scan_task.end_time = time.time()
                self.scan_task.found_count = self._found_counter

        await self._broadcast_ws({
            "type": "scan_complete",
            "task": asdict(self.scan_task) if self.scan_task else None,
            "summary": self._get_summary()
        })

        # 停止通知消费者
        if self._notify_queue:
            await self._notify_queue.put(None)

    # ──────────────── 通知机制 ────────────────

    def _start_notify_consumer(self):
        """启动异步通知消费者，将线程中的发现事件通过 WS 广播"""
        if self._notify_queue is None:
            self._notify_queue = asyncio.Queue()

        async def _consumer():
            while True:
                try:
                    msg = await asyncio.wait_for(self._notify_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                if msg is None:
                    break
                await self._broadcast_ws(msg)

        if self._notify_task and not self._notify_task.done():
            self._notify_task.cancel()
        self._notify_task = asyncio.create_task(_consumer())

    async def _notify(self, data: dict):
        """线程安全地将消息推送到异步队列"""
        if self._notify_queue:
            await self._notify_queue.put(data)

    # ──────────────── 扫描控制 ────────────────

    def stop_scan(self):
        self._stop_event.set()
        self._pause_event.set()  # 解除暂停，让线程能退出
        with self._lock:
            if self.scan_task:
                self.scan_task.status = "stopped"
                self.scan_task.end_time = time.time()

    def pause_scan(self):
        self._pause_event.clear()
        with self._lock:
            if self.scan_task:
                self.scan_task.status = "paused"

    def resume_scan(self):
        self._pause_event.set()
        with self._lock:
            if self.scan_task:
                self.scan_task.status = "running"

    # ──────────────── 统计摘要 ────────────────

    def _get_summary(self) -> dict:
        """生成扫描摘要统计"""
        with self._lock:
            total_hosts = len(self.results)
            total_ports = sum(len(h.open_ports) for h in self.results.values())
            service_dist = defaultdict(int)
            port_dist = defaultdict(int)
            os_dist = defaultdict(int)

            for host in self.results.values():
                if host.os_hint:
                    os_dist[host.os_hint] += 1
                for p in host.open_ports:
                    service_dist[p.service or "unknown"] += 1
                    port_dist[p.port] += 1

        top_ports = sorted(port_dist.items(), key=lambda x: -x[1])[:20]
        top_services = sorted(service_dist.items(), key=lambda x: -x[1])[:20]

        duration = 0
        if self.scan_task and self.scan_task.end_time and self.scan_task.start_time:
            duration = self.scan_task.end_time - self.scan_task.start_time

        return {
            "total_hosts": total_hosts,
            "total_open_ports": total_ports,
            "os_distribution": dict(os_dist),
            "top_ports": [{"port": p, "count": c} for p, c in top_ports],
            "top_services": [{"service": s, "count": c} for s, c in top_services],
            "scan_duration": duration,
            "thread_count": self.thread_count,
        }

    def get_results(self) -> dict:
        with self._lock:
            results = {}
            for ip, host in self.results.items():
                results[ip] = {
                    **asdict(host),
                    "open_ports": [asdict(p) for p in host.open_ports]
                }
            return results

    # ──────────────── WebSocket 管理 ────────────────

    async def register_ws(self, ws: web.WebSocketResponse):
        self._ws_clients.add(ws)

    async def unregister_ws(self, ws: web.WebSocketResponse):
        self._ws_clients.discard(ws)

    async def _broadcast_ws(self, data: dict):
        """广播消息到所有 WebSocket 客户端"""
        msg = json.dumps(data, ensure_ascii=False)
        dead = set()
        for ws in self._ws_clients:
            try:
                await ws.send_str(msg)
            except Exception:
                dead.add(ws)
        self._ws_clients -= dead


# ═══════════════════════════════════════
#  HTTP API
# ═══════════════════════════════════════

scanner = PortScanner()


async def handle_index(request):
    return web.FileResponse(
        os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    )


async def api_start_scan(request):
    data = await request.json()
    targets = data.get('targets', '127.0.0.1')
    ports = data.get('ports', '1-1024')
    task_id = f"scan_{int(time.time())}"

    asyncio.create_task(scanner.scan(targets, ports, task_id))
    return web.json_response({
        "task_id": task_id,
        "status": "started",
        "thread_count": scanner.thread_count
    })


async def api_stop_scan(request):
    scanner.stop_scan()
    return web.json_response({"status": "stopped"})


async def api_pause_scan(request):
    scanner.pause_scan()
    return web.json_response({"status": "paused"})


async def api_resume_scan(request):
    scanner.resume_scan()
    return web.json_response({"status": "resumed"})


async def api_status(request):
    task = scanner.scan_task
    if task:
        resp = asdict(task)
        resp["thread_count"] = scanner.thread_count
        return web.json_response(resp)
    return web.json_response({"status": "idle"})


async def api_results(request):
    return web.json_response(scanner.get_results())


async def api_summary(request):
    return web.json_response(scanner._get_summary())


async def api_export_csv(request):
    import io
    output = io.StringIO()
    output.write("IP,主机名,操作系统,端口,状态,服务,版本,Banner,发现时间\n")
    for ip, host in scanner.results.items():
        for p in host.open_ports:
            banner_clean = p.banner.replace('"', '""').replace('\n', ' ').replace('\r', '')
            output.write(f'{ip},{host.hostname},{host.os_hint},{p.port},{p.status},'
                         f'{p.service},{p.version},"{banner_clean}",{p.discovered_at}\n')
        if not host.open_ports:
            output.write(f'{ip},{host.hostname},{host.os_hint},-,-,-,-,-,-\n')

    resp = web.Response(text=output.getvalue(), content_type='text/csv')
    resp.headers['Content-Disposition'] = 'attachment; filename=port_scan_results.csv'
    return resp


async def api_export_json(request):
    data = json.dumps(scanner.get_results(), ensure_ascii=False, indent=2)
    resp = web.Response(text=data, content_type='application/json')
    resp.headers['Content-Disposition'] = 'attachment; filename=port_scan_results.json'
    return resp


async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await scanner.register_ws(ws)

    # 发送当前状态
    if scanner.scan_task:
        await ws.send_str(json.dumps({
            "type": "scan_status",
            "task": asdict(scanner.scan_task)
        }))
    if scanner.results:
        await ws.send_str(json.dumps({
            "type": "existing_results",
            "results": scanner.get_results()
        }))

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                data = json.loads(msg.data)
                if data.get('action') == 'ping':
                    await ws.send_str(json.dumps({"type": "pong"}))
            elif msg.type == WSMsgType.ERROR:
                break
    finally:
        await scanner.unregister_ws(ws)
    return ws


async def handle_static(request):
    file_path = request.match_info.get('file', 'index.html')
    full_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', file_path)
    if os.path.exists(full_path) and os.path.isfile(full_path):
        return web.FileResponse(full_path)
    return web.Response(status=404)


# ═══════════════════════════════════════
#  应用入口
# ═══════════════════════════════════════

def create_app():
    app = web.Application()

    # CORS
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
            allow_methods="*"
        )
    })

    # API 路由
    routes = [
        web.post('/api/scan/start', api_start_scan),
        web.post('/api/scan/stop', api_stop_scan),
        web.post('/api/scan/pause', api_pause_scan),
        web.post('/api/scan/resume', api_resume_scan),
        web.get('/api/scan/status', api_status),
        web.get('/api/results', api_results),
        web.get('/api/summary', api_summary),
        web.get('/api/export/csv', api_export_csv),
        web.get('/api/export/json', api_export_json),
        web.get('/ws', websocket_handler),
        web.get('/', handle_index),
        web.get('/{file}', handle_static),
    ]

    for route in routes:
        cors.add(app.router.add_route(route.method, route.path, route.handler))

    return app


if __name__ == '__main__':
    cpu = os.cpu_count() or 4
    print(f"🚀 内网端口发现系统启动")
    print(f"   CPU 核心数: {cpu}")
    print(f"   扫描线程数: {min(cpu * 4, 64)}")
    print(f"   默认超时: 1.5s")
    app = create_app()
    port = int(os.environ.get('PORT', 8088))
    print(f"   访问地址: http://0.0.0.0:{port}")
    web.run_app(app, host='0.0.0.0', port=port)

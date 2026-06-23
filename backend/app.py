"""
内网端口发现系统 - 后端服务
多线程扫描引擎 + WebSocket实时推送 + REST API

架构：
  - 扫描引擎使用 ThreadPoolExecutor 多线程并发 socket 连接
  - Web 层使用 aiohttp 异步处理 HTTP/WS
  - 线程与协程之间通过 asyncio.Queue 桥接
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
import subprocess
import threading
import ipaddress
import logging
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict

from aiohttp import web, WSMsgType
import aiohttp_cors

# ═══════════════════════════════════════
#  日志配置
# ═══════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('netscope')


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
#  服务指纹库（扩展版）
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
    1080: ("socks", "SOCKS Proxy"),
    1433: ("mssql", "Microsoft SQL Server"),
    1521: ("oracle", "Oracle DB"),
    1883: ("mqtt", "MQTT"),
    2181: ("zookeeper", "ZooKeeper"),
    2375: ("docker", "Docker API"),
    2376: ("docker-tls", "Docker TLS"),
    3000: ("nodejs-app", "Node.js App"),
    3306: ("mysql", "MySQL"),
    3389: ("ms-wbt-server", "RDP (Remote Desktop)"),
    5000: ("flask", "Flask / Python App"),
    5432: ("postgresql", "PostgreSQL"),
    5672: ("amqp", "RabbitMQ"),
    5900: ("vnc", "VNC"),
    6379: ("redis", "Redis"),
    6443: ("kubernetes-api", "Kubernetes API"),
    7001: ("weblogic", "WebLogic"),
    8000: ("django", "Django / Python App"),
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
    50000: ("sap", "SAP"),
}

# 高危端口定义（含风险说明）
HIGH_RISK_PORTS = {
    21: "FTP 匿名访问风险",
    23: "Telnet 明文传输",
    445: "SMB 漏洞利用 (MS17-010等)",
    3389: "RDP 暴力破解",
    6379: "Redis 未授权访问",
    27017: "MongoDB 未授权访问",
    9200: "Elasticsearch 未授权",
    5900: "VNC 弱口令",
    11211: "Memcached UDP 反射",
    2375: "Docker API 未授权",
    5000: "开发服务暴露",
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
    - 通过 asyncio.Queue 将发现结果传递到 WS 广播层
    - 支持暂停/继续/停止（通过 threading.Event 控制）
    - UDP 端口探测支持
    - 扫描历史记录（最近10次）
    """

    MAX_HISTORY = 10

    def __init__(self, thread_count: int = None, timeout: float = 1.5):
        self.timeout = timeout
        cpu = os.cpu_count() or 4
        self.thread_count = min(thread_count or cpu * 4, 64)

        # ── 线程安全状态 ──
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._scanned_counter = 0
        self._found_counter = 0

        # ── 数据 ──
        self.results: Dict[str, HostInfo] = {}
        self.scan_task: Optional[ScanTask] = None
        self._history: List[dict] = []  # 扫描历史

        # ── 线程池 ──
        self._executor: Optional[ThreadPoolExecutor] = None

        # ── 异步桥接 ──
        self._ws_clients: Set[web.WebSocketResponse] = set()
        self._ws_lock = threading.Lock()
        self._notify_queue: Optional[asyncio.Queue] = None
        self._notify_task: Optional[asyncio.Task] = None

    def _get_executor(self) -> ThreadPoolExecutor:
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
                    count = network.num_addresses - 2  # 排除网络和广播
                    if count > 4096:
                        logger.warning(f"目标网段 {part} 包含 {count} 个主机，限制为前 4096 个")
                    for i, host in enumerate(network.hosts()):
                        if i >= 4096:
                            break
                        targets.add(str(host))
                elif '-' in part and not part.startswith('-'):
                    base, end = part.rsplit('-', 1)
                    prefix = base.rsplit('.', 1)[0]
                    start = int(base.rsplit('.', 1)[1])
                    end_n = int(end)
                    for i in range(start, min(end_n + 1, start + 4096)):
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
                    s, e = int(start), int(end)
                    if e - s > 65535:
                        logger.warning(f"端口范围 {part} 过大，已截断")
                    for p in range(s, min(e + 1, 65536)):
                        ports.add(p)
                else:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                continue
        if len(ports) > 65535:
            logger.warning(f"端口数 {len(ports)} 超限，截断为前 65535 个")
            ports = set(sorted(ports)[:65535])
        return sorted(ports)

    # ──────────────── 线程工作函数 ────────────────

    def _tcp_connect(self, ip: str, port: int) -> Optional[PortInfo]:
        """TCP 连接探测（同步 socket，在线程中执行）"""
        if self._stop_event.is_set():
            return None
        while not self._pause_event.is_set():
            if self._stop_event.is_set():
                return None
            time.sleep(0.1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # TCP Fast Open（如果系统支持）
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                info = PortInfo(
                    ip=ip, port=port, status="open",
                    discovered_at=time.time()
                )
                svc = SERVICE_FINGERPRINTS.get(port, ("unknown", "Unknown"))
                info.service = svc[0]
                banner = self._grab_banner_thread(sock, ip, port, info.service)
                if banner:
                    info.banner = banner[:512]
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

    def _udp_probe(self, ip: str, port: int) -> Optional[PortInfo]:
        """UDP 探测（针对 DNS/SNMP 等常见 UDP 服务）"""
        if self._stop_event.is_set():
            return None
        while not self._pause_event.is_set():
            if self._stop_event.is_set():
                return None
            time.sleep(0.1)

        UDP_PROBES = {
            53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
            123: b"\xe3\x00\x04\xfa\x00\x01\x00\x00" + b"\x00" * 40,
            1900: b"M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nMan:\"ssdp:discover\"\r\nST:ssdp:all\r\nMX:1\r\n\r\n",
        }

        if port not in UDP_PROBES:
            self._scanned_counter += 1
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout * 1.5)
        try:
            sock.sendto(UDP_PROBES[port], (ip, port))
            data, _ = sock.recvfrom(1024)
            if data:
                info = PortInfo(
                    ip=ip, port=port, status="open",
                    protocol="udp",
                    discovered_at=time.time()
                )
                svc_map = {53: "dns", 161: "snmp", 123: "ntp", 1900: "ssdp"}
                info.service = svc_map.get(port, "unknown")
                try:
                    info.banner = data.decode('utf-8', errors='replace').strip()[:256]
                except Exception:
                    info.banner = data.hex()[:64]
                return info
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
            self._scanned_counter += 1
        return None

    def _grab_banner_thread(self, sock: socket.socket, ip: str, port: int, service: str) -> str:
        """Banner 抓取（同步 socket）"""
        try:
            probe_key = service if service in BANNER_PROBES else None
            if probe_key:
                probe = BANNER_PROBES[probe_key].replace(b"{host}", ip.encode())
                if probe:
                    sock.sendall(probe)

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
        """主机存活探测（TCP ping 并行 + ICMP 回退）"""
        # TCP ping：并行尝试所有端口，任一成功即存活
        for p in ping_ports:
            if self._stop_event.is_set():
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout * 0.6)
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
        """反向 DNS 解析"""
        try:
            name = socket.gethostbyaddr(ip)
            return name[0] if name[0] != ip else ""
        except (socket.herror, socket.gaierror, OSError):
            return ""

    # ──────────────── 扫描主流程 ────────────────

    async def scan(self, targets_str: str, ports_str: str, task_id: str,
                   scan_mode: str = "tcp"):
        """
        执行完整扫描流程

        Args:
            scan_mode: "tcp" | "hybrid"（TCP + 常见UDP）
        """
        targets = self.parse_targets(targets_str)
        ports = self.parse_ports(ports_str)
        if not targets or not ports:
            return

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

        self._start_notify_consumer()
        executor = self._get_executor()

        # ── 阶段 1: 主机发现 ──
        await self._broadcast_ws({
            "type": "phase", "phase": "discovery",
            "message": "🔍 正在发现存活主机（多线程探测）..."
        })

        ping_ports = [22, 80, 443, 445, 3389]
        alive_hosts: List[str] = []

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
                await self._notify({
                    "type": "host_found",
                    "ip": ip
                })

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
        batch_size = self.thread_count * 8

        all_tasks: List[Tuple[str, int, str]] = []  # (ip, port, protocol)
        for ip in alive_hosts:
            for port in ports:
                all_tasks.append((ip, port, "tcp"))

        # 混合模式：追加常见 UDP 探测
        if scan_mode == "hybrid":
            udp_ports = [53, 161, 123, 1900]
            for ip in alive_hosts:
                for port in udp_ports:
                    if port not in ports:
                        all_tasks.append((ip, port, "udp"))
                    total_checks += 1

        host_infos: Dict[str, HostInfo] = {}
        for ip in alive_hosts:
            host_infos[ip] = HostInfo(ip=ip, is_alive=True)

        last_progress_broadcast = time.time()

        # 提交初始批次
        port_futures: Dict[Future, Tuple[str, int]] = {}
        batch_end = min(batch_size, len(all_tasks))
        for i in range(batch_end):
            ip, port, proto = all_tasks[i]
            fn = self._udp_probe if proto == "udp" else self._tcp_connect
            f = executor.submit(fn, ip, port)
            port_futures[f] = (ip, port)
        task_idx = batch_end

        completed_in_batch = 0
        for future in as_completed(port_futures):
            if self._stop_event.is_set():
                break

            ip, port = port_futures[future]
            completed_in_batch += 1

            try:
                port_info = future.result(timeout=8.0)
            except Exception:
                port_info = None

            if port_info and port_info.status == "open":
                with self._lock:
                    host_infos[ip].open_ports.append(port_info)
                    self._found_counter += 1
                await self._notify({
                    "type": "port_found",
                    "ip": ip,
                    "port": asdict(port_info)
                })

            # 动态补充任务
            if task_idx < len(all_tasks) and not self._stop_event.is_set():
                new_ip, new_port, new_proto = all_tasks[task_idx]
                fn = self._udp_probe if new_proto == "udp" else self._tcp_connect
                new_f = executor.submit(fn, new_ip, new_port)
                port_futures[new_f] = (new_ip, new_port)
                task_idx += 1

            # 节流进度广播
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

        # 并行反向 DNS
        hostname_futures = {}
        for ip in alive_hosts:
            if ip in host_infos and host_infos[ip].open_ports:
                f = executor.submit(self._resolve_hostname_thread, ip)
                hostname_futures[f] = ip

        for future in as_completed(hostname_futures):
            ip = hostname_futures[future]
            try:
                hostname = future.result(timeout=3.0)
                host_infos[ip].hostname = hostname
            except Exception:
                pass

        # OS 推断 + 风险评估
        risk_alerts = []
        for ip, host in host_infos.items():
            if not host.open_ports:
                continue
            port_numbers = {p.port for p in host.open_ports}
            # OS 推断
            if 445 in port_numbers or 3389 in port_numbers or 1433 in port_numbers:
                host.os_hint = "Windows"
            elif 22 in port_numbers:
                host.os_hint = "Linux/Unix"
            # 风险告警
            for p in port_numbers:
                if p in HIGH_RISK_PORTS:
                    risk_alerts.append({
                        "ip": ip, "port": p,
                        "risk": HIGH_RISK_PORTS[p]
                    })
            host.last_seen = time.time()

        # 写入最终结果
        with self._lock:
            self.results = {ip: h for ip, h in host_infos.items() if h.open_ports}

        # 保存到历史
        await self._finish_scan(risk_alerts=risk_alerts)

    async def _finish_scan(self, risk_alerts: List[dict] = None):
        """完成扫描"""
        with self._lock:
            if self.scan_task:
                if self._stop_event.is_set():
                    self.scan_task.status = "stopped"
                else:
                    self.scan_task.status = "completed"
                self.scan_task.progress = 100
                self.scan_task.end_time = time.time()
                self.scan_task.found_count = self._found_counter

                # 保存历史
                self._history.append({
                    "task_id": self.scan_task.task_id,
                    "targets": self.scan_task.targets,
                    "ports": self.scan_task.ports,
                    "status": self.scan_task.status,
                    "found_count": self.scan_task.found_count,
                    "duration": self.scan_task.end_time - self.scan_task.start_time,
                    "timestamp": self.scan_task.start_time,
                })
                if len(self._history) > self.MAX_HISTORY:
                    self._history = self._history[-self.MAX_HISTORY:]

        summary = self._get_summary()
        summary["risk_alerts"] = risk_alerts or []

        await self._broadcast_ws({
            "type": "scan_complete",
            "task": asdict(self.scan_task) if self.scan_task else None,
            "summary": summary
        })

        if self._notify_queue:
            await self._notify_queue.put(None)

    # ──────────────── 通知机制 ────────────────

    def _start_notify_consumer(self):
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
        if self._notify_queue:
            await self._notify_queue.put(data)

    # ──────────────── 扫描控制 ────────────────

    def stop_scan(self):
        self._stop_event.set()
        self._pause_event.set()
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
        with self._lock:
            total_hosts = len(self.results)
            total_ports = sum(len(h.open_ports) for h in self.results.values())
            service_dist = defaultdict(int)
            port_dist = defaultdict(int)
            os_dist = defaultdict(int)
            risk_summary = []

            for host in self.results.values():
                if host.os_hint:
                    os_dist[host.os_hint] += 1
                for p in host.open_ports:
                    service_dist[p.service or "unknown"] += 1
                    port_dist[p.port] += 1
                    if p.port in HIGH_RISK_PORTS:
                        risk_summary.append({
                            "ip": host.ip, "port": p.port,
                            "risk": HIGH_RISK_PORTS[p.port]
                        })

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
            "risk_summary": risk_summary,
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

    def get_history(self) -> List[dict]:
        with self._lock:
            return list(self._history)

    # ──────────────── WebSocket 管理 ────────────────

    async def register_ws(self, ws: web.WebSocketResponse):
        with self._ws_lock:
            self._ws_clients.add(ws)

    async def unregister_ws(self, ws: web.WebSocketResponse):
        with self._ws_lock:
            self._ws_clients.discard(ws)

    async def _broadcast_ws(self, data: dict):
        msg = json.dumps(data, ensure_ascii=False)
        dead = set()
        with self._ws_lock:
            clients = list(self._ws_clients)
        for ws in clients:
            try:
                await ws.send_str(msg)
            except Exception:
                dead.add(ws)
        if dead:
            with self._ws_lock:
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
    scan_mode = data.get('mode', 'tcp')  # tcp | hybrid
    task_id = f"scan_{int(time.time() * 1000)}"

    # 防止重复扫描
    if scanner.scan_task and scanner.scan_task.status in ("running", "paused"):
        return web.json_response({"error": "已有扫描任务进行中"}, status=409)

    asyncio.create_task(scanner.scan(targets, ports, task_id, scan_mode))
    logger.info(f"扫描已启动: {task_id}, 目标={targets}, 端口={ports}, 模式={scan_mode}")
    return web.json_response({
        "task_id": task_id,
        "status": "started",
        "thread_count": scanner.thread_count,
        "scan_mode": scan_mode
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


async def api_history(request):
    """扫描历史记录"""
    return web.json_response(scanner.get_history())


async def api_config(request):
    """获取当前配置"""
    return web.json_response({
        "thread_count": scanner.thread_count,
        "timeout": scanner.timeout,
        "high_risk_ports": HIGH_RISK_PORTS,
        "service_count": len(SERVICE_FINGERPRINTS),
    })


async def api_export_csv(request):
    import io as _io
    output = _io.StringIO()
    output.write("IP,主机名,操作系统,端口,协议,状态,服务,版本,Banner,风险,发现时间\n")
    for ip, host in scanner.results.items():
        for p in host.open_ports:
            banner_clean = p.banner.replace('"', '""').replace('\n', ' ').replace('\r', '')
            risk = HIGH_RISK_PORTS.get(p.port, "")
            output.write(f'{ip},{host.hostname},{host.os_hint},{p.port},{p.protocol},'
                         f'{p.status},{p.service},{p.version},"{banner_clean}",{risk},{p.discovered_at}\n')
        if not host.open_ports:
            output.write(f'{ip},{host.hostname},{host.os_hint},-,-,-,-,-,-,-,-\n')

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

    # 优雅关闭
    async def on_shutdown(app):
        scanner.stop_scan()
        with scanner._ws_lock:
            for ws in list(scanner._ws_clients):
                await ws.close(code=1001, message=b'server shutdown')

    app.on_shutdown.append(on_shutdown)

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
        web.get('/api/history', api_history),
        web.get('/api/config', api_config),
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
    print(f"🚀 NetScope 内网端口发现系统")
    print(f"   CPU 核心: {cpu}")
    print(f"   扫描线程: {min(cpu * 4, 64)}")
    print(f"   默认超时: 1.5s")
    print(f"   服务指纹: {len(SERVICE_FINGERPRINTS)} 条")
    print(f"   高危端口: {len(HIGH_RISK_PORTS)} 个")
    app = create_app()
    port = int(os.environ.get('PORT', 8088))
    print(f"   访问地址: http://0.0.0.0:{port}")
    web.run_app(app, host='0.0.0.0', port=port)

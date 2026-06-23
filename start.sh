#!/bin/bash
# NetScope - 内网端口发现系统启动脚本
cd "$(dirname "$0")/backend"

# 检查依赖
if ! python3 -c "import aiohttp" 2>/dev/null; then
    echo "📦 正在安装依赖..."
    pip3 install aiohttp aiohttp-cors --break-system-packages -q
fi

PORT=${PORT:-8088}
echo "🚀 NetScope 启动于 http://0.0.0.0:$PORT"
python3 app.py

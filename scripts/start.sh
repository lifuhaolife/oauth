#!/bin/bash
# scripts/start.sh - 生产启动脚本
set -e

APP_BIN="${APP_BIN:-./bin/auth-service}"
LOG_DIR="${LOG_DIR:-logs}"
PID_FILE="${PID_FILE:-auth-service.pid}"

# ── 1. 检查二进制文件 ─────────────────────────────────────────────────────────
if [ ! -f "$APP_BIN" ]; then
    echo "错误：未找到可执行文件 $APP_BIN，请先运行 make build" >&2
    exit 1
fi

# ── 2. 创建日志目录 ───────────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"

# ── 3. 优雅停止旧进程 ─────────────────────────────────────────────────────────
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "停止旧进程（PID=$OLD_PID）..."
        kill -SIGTERM "$OLD_PID" 2>/dev/null
        sleep 3
        # 强制杀死残留进程
        if kill -0 "$OLD_PID" 2>/dev/null; then
            kill -SIGKILL "$OLD_PID" 2>/dev/null
        fi
    fi
    rm -f "$PID_FILE"
fi

# ── 4. 启动新进程（后台，stdout/stderr 写日志）────────────────────────────────
nohup "$APP_BIN" >> "$LOG_DIR/app.log" 2>&1 &
NEW_PID=$!
echo $NEW_PID > "$PID_FILE"
echo "启动成功，PID=$NEW_PID，日志：$LOG_DIR/app.log"

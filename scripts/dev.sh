#!/bin/bash
# scripts/dev.sh - 本地开发启动脚本
set -e

# ── 1. 检查 Go 版本 ───────────────────────────────────────────────────────────
if ! command -v go >/dev/null 2>&1; then
    echo "错误：未找到 go 命令，请安装 Go 1.21+" >&2
    exit 1
fi
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED="1.21"
if [ "$(printf '%s\n' "$REQUIRED" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED" ]; then
    echo "警告：Go 版本 $GO_VERSION 低于推荐版本 $REQUIRED" >&2
fi

# ── 2. 检查 .env 文件 ─────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    echo "错误：未找到 .env 文件" >&2
    echo "请参考 .env.example 创建 .env：cp .env.example .env" >&2
    exit 1
fi

# ── 3. 检查 JWT 密钥文件（不存在则生成）──────────────────────────────────────
PRIVATE_KEY_PATH="${JWT_PRIVATE_KEY_PATH:-./cmd/server/keys/jwt_private.pem}"
if [ ! -f "$PRIVATE_KEY_PATH" ]; then
    echo "未找到 JWT 密钥，正在生成..."
    make generate-keys
fi

# ── 4. 创建日志目录 ───────────────────────────────────────────────────────────
mkdir -p logs

# ── 5. 检查数据库连接 ─────────────────────────────────────────────────────────
set -a; source .env; set +a
if command -v mysql >/dev/null 2>&1; then
    if ! mysql -h"${DB_HOST:-localhost}" -P"${DB_PORT:-3306}" \
               -u"${DB_USER:-root}" -p"${DB_PASSWORD}" \
               -e "SELECT 1" "${DB_NAME:-auth_service}" >/dev/null 2>&1; then
        echo "错误：数据库连接失败，请检查 .env 中的 DB_* 配置" >&2
        exit 1
    fi
    echo "数据库连接正常"
else
    echo "警告：未找到 mysql 客户端，跳过数据库连接检查"
fi

# ── 6. 启动服务 ───────────────────────────────────────────────────────────────
echo "启动开发服务器..."
go run ./cmd/server

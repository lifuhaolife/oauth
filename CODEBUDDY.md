# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Go + Gin 鉴权管理后端服务，核心特性：
- RSA 动态密钥池（一次一密，使用后销毁）
- JWT RS256 非对称加密签名
- BCrypt 密码哈希 + AES-GCM 敏感数据加密
- 微信登录（预留配置接口）

## 常用命令

```bash
# 安装依赖
go mod download

# 运行服务（需要先配置 .env 和 MySQL）
go run cmd/server/main.go

# 编译
go build -o auth-service cmd/server/main.go

# 运行所有测试
go test -v ./...

# 运行测试并生成覆盖率报告
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# 竞态检测
go test -race -v ./...

# Docker 部署 (使用独立 MySQL)
docker-compose -f docker-compose.standalone.yml up -d
docker logs -f auth_service
docker-compose -f docker-compose.standalone.yml down

# 或使用包含 MySQL 的 docker-compose (开发环境)
docker-compose up -d
docker-compose logs -f auth-service
docker-compose down

# 初始化数据库 (如果使用 docker-compose.yml 中的 MySQL)
docker-compose up -d mysql
# 或手动执行
mysql -h localhost -P 3306 -u root -p < scripts/init.sql

# 使用 Makefile
make build         # 编译
make test          # 运行测试
make run           # 运行服务
make docker-up     # Docker 启动
make init-db       # 初始化数据库
```

## 架构结构

```
cmd/server/main.go (入口)
    │
    ├── internal/config      # 配置加载、MASTER_KEY 管理、JWT 密钥对生成
    ├── internal/keystore    # RSA 密钥池管理（内存缓存、自动维护）
    ├── internal/crypto      # 加密原语（RSA/AES/BCrypt/HMAC）
    │   ├── crypto.go
    │   └── crypto_test.go
    ├── internal/model       # GORM 模型 + 数据传输结构
    │   └── model.go
    ├── internal/handler     # HTTP Handler
    │   ├── auth_handler.go  # 认证相关
    │   └── admin_handler.go # 管理相关
    ├── internal/middleware  # 中间件（CORS/RateLimit/Auth/Admin）
    ├── internal/service     # 业务逻辑（AuthService）
    └── internal/jwt         # JWT 服务（签发/验证/黑名单）
        ├── jwt.go
        └── jwt_test.go
```

## 核心流程

### 登录流程
1. `GET /api/v1/auth/pubkey` → 返回未使用的 RSA 公钥 + key_id
2. 客户端 RSA 加密 `{username, password}` + HMAC 签名
3. `POST /api/v1/auth/login` → 服务端用 key_id 获取私钥解密 → 验证密码 → 签发 JWT
4. RSA 密钥对使用后立即销毁（`InvalidateKey`）

### JWT 机制
- Access Token: 15 分钟，Refresh Token: 7 天
- RS256 签名，私钥存 `keys/jwt_private.pem`，公钥存 `keys/jwt_public.pem`
- 登出时 Token 加入黑名单（内存 + 数据库双存储）

### 密钥管理
| 密钥 | 存储 | 生命周期 |
|------|------|----------|
| RSA 密钥对 | 内存缓存 | 一次一密 |
| JWT 密钥对 | 文件 (`keys/`) | 长期 |
| MASTER_KEY | 环境变量 | 长期（首次启动自动生成） |

## 配置说明

`.env` 必要配置：
```bash
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=xxx
MASTER_KEY=  # 首次启动自动生成，需备份
WECHAT_APP_ID=  # 可选，留空禁用微信登录
```

默认管理员：`admin / Admin@123`

## 扩展开发

- **微信登录**: 在 `internal/service/auth_service.go` 的 `WechatLogin` 方法中实现
- **新增接口**: `internal/handler/auth_handler.go` 添加 Handler，`main.go` 注册路由
- **自定义中间件**: `internal/middleware/middleware.go`


## 注意事项
本项目面向中文开发者，所有文档描述使用中文
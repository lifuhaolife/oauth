# Go 项目结构详解指南

## 概述

这是一个使用 Go 语言开发的鉴权管理后端服务，采用了标准的 Go 项目布局结构。本文档将详细解释各个目录的作用以及整个项目的组织方式。

## Go 项目标准结构

```
auth-service/                    # 项目根目录
├── cmd/                        # 应用入口目录
│   └── server/                 # 服务器应用入口
│       └── main.go             # 主程序入口文件
├── internal/                   # 私有应用程序代码 (对外不可见)
│   ├── config/                 # 配置管理
│   ├── crypto/                 # 加密相关工具
│   ├── handler/                # HTTP 请求处理函数
│   ├── jwt/                    # JWT 认证相关功能
│   ├── keystore/               # 密钥管理
│   ├── middleware/             # 中间件
│   ├── model/                  # 数据模型
│   └── service/                # 业务逻辑
├── scripts/                    # 脚本文件
├── keys/                       # 密钥文件
├── logs/                       # 日志文件
├── api/                        # API 相关定义
├── docs/                       # 文档
├── tests/                      # 测试文件
├── configs/                    # 配置文件
├── deployments/                # 部署相关文件
├── Dockerfile                  # Docker 镜像构建文件
├── docker-compose.yml          # Docker Compose 配置
├── Makefile                    # 构建脚本
├── go.mod                      # Go 模块定义
├── go.sum                      # Go 依赖校验
├── .env                        # 环境变量配置
├── README.md                   # 项目说明文档
└── CLAUDE.md                   # 开发指南文档
```

## 目录和文件详细说明

### 1. `cmd/` 目录 - 应用程序入口

**作用**：存放可执行程序的入口文件。

- `cmd/server/main.go`：这是整个应用的入口点，Go 程序从这里开始执行。
- 在 Go 中，每个可执行程序都需要一个 `main` 包，这个包就在 `cmd/` 目录下。

### 2. `internal/` 目录 - 内部代码

**作用**：存放项目的私有代码，这些代码不会被外部项目引用。

> **注意**：Go 语言会阻止其他项目导入 `internal` 目录下的代码。

#### 2.1 `internal/config/` - 配置管理
- 负责加载和管理应用程序的配置信息
- 读取 `.env` 环境变量文件
- 设置数据库连接参数、JWT 密钥等配置项

#### 2.2 `internal/crypto/` - 加密工具
- 提供各种加密算法的实现
- RSA 加密/解密
- AES 加密/解密
- BCrypt 密码哈希
- HMAC 签名验证
- Base64 编解码

#### 2.3 `internal/handler/` - HTTP 处理器
- 处理 HTTP 请求和响应
- `auth_handler.go`：认证相关的处理函数
- `admin_handler.go`：管理员相关的处理函数

**主要功能**：
- 登录接口 (`/api/v1/auth/login`)
- 获取 RSA 公钥 (`/api/v1/auth/pubkey`)
- 刷新 Token (`/api/v1/auth/refresh`)
- 获取用户信息 (`/api/v1/user/me`)

#### 2.4 `internal/jwt/` - JWT 服务
- 负责 JWT Token 的生成和验证
- Token 刷新功能
- Token 黑名单管理
- 使用 RS256 非对称加密算法

#### 2.5 `internal/keystore/` - 密钥管理
- 动态管理 RSA 密钥对
- 实现"一次一密"的安全机制
- 密钥池管理（内存缓存）
- 密钥使用后自动销毁

#### 2.6 `internal/middleware/` - 中间件
- 跨域处理 (CORS)
- 速率限制 (防止暴力攻击)
- 请求日志记录
- JWT 认证验证
- 管理员权限验证

#### 2.7 `internal/model/` - 数据模型
- 定义数据库表结构
- 用户表 (users)
- Token 黑名单表 (token_blacklist)
- 登录日志表 (login_logs)
- 密钥记录表 (key_store_record)
- 数据传输对象 (DTOs)

#### 2.8 `internal/service/` - 业务逻辑
- 实现具体的业务功能
- 用户认证逻辑
- 密码修改功能
- 用户管理功能

### 3. `scripts/` 目录 - 脚本文件

**作用**：存放数据库初始化和其他脚本文件。

- `scripts/init.sql`：数据库初始化 SQL 脚本

### 4. `keys/` 目录 - 密钥文件

**作用**：存储 JWT 密钥对。

- `jwt_private.pem`：JWT 私钥
- `jwt_public.pem`：JWT 公钥

### 5. `logs/` 目录 - 日志文件

**作用**：存储应用程序的日志文件。

### 6. 根目录重要文件

#### `go.mod` 和 `go.sum`
- `go.mod`：定义 Go 模块和依赖版本
- `go.sum`：依赖包的校验和

#### `Dockerfile`
- 定义如何构建 Docker 镜像

#### `docker-compose.yml`
- 定义多个容器的 Docker 服务配置

#### `Makefile`
- 提供常用的构建和管理命令

#### `.env`
- 存储环境变量（数据库密码、密钥等敏感信息）

#### `README.md`
- 项目介绍和使用说明

#### `CLAUDE.md`
- 开发指南和常用命令

## 核心功能流程

### 用户登录流程
1. 客户端调用 `/api/v1/auth/pubkey` 获取 RSA 公钥
2. 客户端用公钥加密用户名和密码
3. 客户端发送加密数据到 `/api/v1/auth/login`
4. 服务端用私钥解密（密钥用完立即销毁）
5. 验证用户身份并生成 JWT Token
6. 返回 Access Token 和 Refresh Token

### 认证流程
1. 需要认证的接口使用 `AuthMiddleware`
2. 中间件验证 Authorization 头中的 JWT Token
3. 验证通过后将用户信息注入请求上下文
4. 处理器函数可以直接使用用户信息

## 构建和运行

### 本地开发
```bash
# 安装依赖
go mod download

# 运行服务
go run cmd/server/main.go

# 或使用 Makefile
make run
```

### 构建二进制文件
```bash
# 编译
go build -o auth-service cmd/server/main.go

# 或使用 Makefile
make build
```

### 运行测试
```bash
# 运行所有测试
go test -v ./...

# 或使用 Makefile
make test
```

## 安全特性

1. **RSA 动态密钥池**：每次获取一个独立的 RSA 密钥对，使用后立即销毁
2. **JWT RS256 签名**：使用非对称加密算法
3. **BCrypt 密码哈希**：安全的密码存储
4. **AES-GCM 加密**：敏感数据加密存储
5. **Token 黑名单机制**：登出后使 Token 失效
6. **防重放攻击**：时间戳验证
7. **速率限制**：防暴力破解

## 总结

这个项目结构遵循了 Go 社区的最佳实践，具有良好的可维护性和安全性。每个目录都有明确的职责，代码组织清晰，便于团队协作开发和后期维护。
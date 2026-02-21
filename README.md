# Auth Service - 鉴权管理后端服务

基于 Go + Gin 实现的高性能鉴权管理后端服务，支持微信登录、RSA 加密传输、BCrypt 密码哈希存储。

## 功能特性

- **微信登录** - 支持公众号/小程序/网站扫码登录（需配置）
- **账号密码登录** - RSA 加密传输 + BCrypt 哈希存储
- **JWT 认证** - RS256 非对称加密签名，支持 Token 刷新
- **动态 RSA 密钥池** - 每次获取公钥生成独立密钥对，使用后自动销毁
- ** AES 加密存储** - 敏感字段（手机号）加密存储
- **登录日志** - 完整的登录审计日志
- **速率限制** - 防暴力破解
- **CORS 支持** - 跨域请求支持

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Go 1.21+ |
| Web 框架 | Gin |
| ORM | GORM |
| 数据库 | MySQL 8.0+ |
| JWT | golang-jwt/jwt/v5 |
| 加密 | golang.org/x/crypto |

## 快速开始

### 1. 环境要求

- Go 1.21+
- MySQL 8.0+
- Docker & Docker Compose (可选)

### 2. 配置环境变量

```bash
# 复制配置模板
cp .env.example .env

# 编辑 .env 文件，配置数据库等信息
# 首次启动会自动生成 MASTER_KEY，请务必备份！
```

### 3. 初始化数据库

```bash
# 方法 1：使用 Docker Compose (推荐)
docker-compose up -d mysql

# 方法 2：手动执行 SQL
mysql -u root -p < scripts/init.sql
```

### 4. 运行服务

```bash
# 安装依赖
go mod download

# 运行
go run .

# 或编译后运行
go build -o auth-service .
./auth-service
```

### 5. Docker 部署

```bash
# 一键启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f auth-service

# 停止服务
docker-compose down
```

## API 接口

### 认证接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/v1/auth/pubkey` | GET | 获取 RSA 公钥 |
| `/api/v1/auth/login` | POST | 用户登录 |
| `/api/v1/auth/refresh` | POST | 刷新 Token |
| `/api/v1/auth/logout` | POST | 用户登出 (需认证) |
| `/api/v1/auth/wechat/url` | GET | 获取微信授权 URL |
| `/api/v1/auth/wechat/callback` | GET | 微信登录回调 |

### 用户接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/v1/user/me` | GET | 获取当前用户信息 |
| `/api/v1/user/password` | PUT | 修改密码 |

### 管理接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/v1/admin/users` | GET | 获取用户列表 |
| `/api/v1/admin/users/:id/status` | PUT | 更新用户状态 |
| `/api/v1/admin/login-logs` | GET | 获取登录日志 |
| `/api/v1/admin/keys/stats` | GET | 获取密钥统计 |

## 登录流程

### 账号密码登录

```
1. 客户端获取 RSA 公钥
   GET /api/v1/auth/pubkey
   → 返回：key_id, public_key

2. 客户端用公钥加密 {username, password}
   并计算 HMAC 签名

3. 客户端提交登录请求
   POST /api/v1/auth/login
   Body: {
     "key_id": "xxx",
     "encrypted_data": "RSA 加密数据",
     "signature": "HMAC 签名",
     "timestamp": 1234567890,
     "nonce": "随机字符串"
   }

4. 服务端验证并返回 Token
   → 返回：{
     "access_token": "eyJ...",
     "refresh_token": "eyJ...",
     "token_type": "Bearer",
     "expires_in": 900,
     "user": {...}
   }
```

### JWT Token 说明

- **Access Token**: 有效期 15 分钟，用于业务请求认证
- **Refresh Token**: 有效期 7 天，用于刷新 Access Token
- **签名算法**: RS256 (非对称加密)

## 安全设计

### 密钥管理

| 密钥类型 | 用途 | 存储方式 | 生命周期 |
|----------|------|----------|----------|
| RSA 密钥对 | 传输加密 | 内存缓存 | 一次一密 |
| JWT 密钥对 | Token 签名 | 文件存储 | 长期 |
| AES 密钥 | 敏感数据加密 | 环境变量 | 长期 |
| BCrypt | 密码哈希 | 数据库 | 长期 |

### 安全措施

- ✅ HTTPS 强制（生产环境）
- ✅ RSA 加密传输（登录凭证）
- ✅ BCrypt 密码哈希（cost=10）
- ✅ JWT RS256 签名
- ✅ 登录速率限制（60 次/分钟）
- ✅ Token 黑名单机制
- ✅ 请求时间戳验证（防重放）

## 项目结构

```
.
├── cmd/                    # 应用入口
├── internal/
│   ├── config/            # 配置加载
│   ├── model/             # 数据模型
│   ├── handler/           # HTTP 处理器
│   ├── middleware/        # 中间件
│   ├── service/           # 业务逻辑
│   ├── keystore/          # 密钥管理
│   └── crypto/            # 加密工具
├── pkg/
│   ├── jwt/               # JWT 服务
│   ├── logger/            # 日志服务
│   └── errors/            # 错误定义
├── scripts/
│   └── init.sql           # 数据库初始化脚本
├── keys/                  # JWT 密钥存储
├── logs/                  # 日志文件
├── docker-compose.yml     # Docker 编排
└── .env.example           # 环境变量模板
```

## 默认账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | Admin@123 | 管理员 |

**注意**: 首次启动后请修改默认密码！

## 生产环境部署

### 环境变量

```bash
# 生成主密钥
openssl rand -base64 32

# 生成 JWT 密钥对
openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
```

### Docker 部署

```bash
# 配置环境变量
export MASTER_KEY=$(openssl rand -base64 32)
export DB_PASSWORD=strong_password

# 启动服务
docker-compose up -d
```

### KMS 集成（可选）

生产环境建议使用云 KMS 服务管理密钥：

- 阿里云 KMS
- AWS KMS
- HashiCorp Vault

## License

MIT License

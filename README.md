# 鉴权管理后端服务 (auth-service)

一个 Go + Gin 鉴权管理后端服务，具备 RSA 动态密钥池、JWT 认证等功能。

## 项目结构

```
auth-service/
├── api/                    # API 定义和协议
├── cmd/                    # 应用入口
│   └── server/             # 服务主入口
│       └── main.go         # 服务启动入口
├── configs/                # 配置文件
├── deployments/            # 部署相关文件
├── docs/                   # 文档
├── internal/               # 内部应用代码 (不允许其他项目引用)
│   ├── config/             # 配置管理
│   │   └── config.go
│   ├── handler/            # HTTP handlers
│   │   ├── auth_handler.go # 认证相关处理器
│   │   └── admin_handler.go # 管理相关处理器
│   ├── model/              # 数据模型
│   │   └── model.go
│   ├── middleware/         # 中间件
│   │   └── middleware.go
│   ├── service/            # 业务逻辑
│   │   └── auth_service.go
│   ├── crypto/             # 加密工具
│   │   ├── crypto.go
│   │   └── crypto_test.go
│   ├── keystore/           # 密钥管理
│   │   ├── keystore.go
│   │   └── keystore_test.go
│   └── jwt/                # JWT 服务
│       ├── jwt.go
│       └── jwt_test.go
├── pkg/                    # 可复用的公共包 (可被外部项目引用)
├── scripts/                # 脚本文件
├── tests/                  # 外部测试代码和集成测试
├── keys/                   # 密钥文件
├── logs/                   # 日志文件
├── .env                    # 环境配置
├── .env.example            # 环境配置示例
├── .gitignore
├── CLAUDE.md               # Claude Code 指南
├── API.md                  # API 接口文档
├── REFACTOR_PLAN.md        # 重构计划
├── Dockerfile
├── docker-compose.yml
├── docker-compose.standalone.yml  # 独立部署配置
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

## 主要特性

- RSA 动态密钥池（一次一密，使用后销毁）
- JWT RS256 非对称加密签名
- BCrypt 密码哈希 + AES-GCM 敏感数据加密
- 微信登录（预留配置接口）
- 完整的测试覆盖

## 安装和运行

```bash
# 安装依赖
go mod download

# 运行服务
go run cmd/server/main.go

# 或使用 Makefile
make run

# 运行测试
make test
```

## Docker 部署

项目支持两种 Docker 部署方式：

### 1. 使用独立 MySQL (推荐)
如果您已经有独立部署的 MySQL 数据库：

```bash
# 构建镜像
docker build -t auth-service .

# 运行容器 (请替换环境变量)
docker run -d \
  --name auth-service \
  -p 8080:8080 \
  -e DB_HOST=your_mysql_host \
  -e DB_PORT=3306 \
  -e DB_USER=root \
  -e DB_PASSWORD=your_password \
  -e DB_NAME=auth_service \
  -e MASTER_KEY=your_master_key \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/keys:/app/keys \
  auth-service
```

或者使用 docker-compose.standalone.yml：

```bash
# 使用独立 MySQL 部署
docker-compose -f docker-compose.standalone.yml up -d
```

### 2. 使用 docker-compose (包含 MySQL)
如果需要同时部署 MySQL 和服务：

```bash
# 启动服务和 MySQL
docker-compose up -d

# 查看日志
docker-compose logs -f auth-service

# 停止服务
docker-compose down
```

## API 文档

详见 [API.md](./API.md) 文件。
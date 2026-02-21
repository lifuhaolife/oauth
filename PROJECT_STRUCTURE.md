# 项目目录结构最终确认

## 标准 Go 项目布局

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
│   ├── crypto/             # 加密工具
│   │   ├── crypto.go
│   │   └── crypto_test.go
│   ├── handler/            # HTTP handlers
│   │   ├── auth_handler.go # 认证相关处理器
│   │   └── admin_handler.go # 管理相关处理器
│   ├── keystore/           # 密钥管理
│   │   ├── keystore.go
│   │   └── keystore_test.go
│   ├── jwt/                # JWT 服务
│   │   ├── jwt.go
│   │   └── jwt_test.go
│   ├── middleware/         # 中间件
│   │   └── middleware.go
│   ├── model/              # 数据模型
│   │   ├── model.go
│   │   └── model_test.go
│   └── service/            # 业务逻辑
│       ├── auth_service.go
│       └── service_test.go
├── scripts/                # 脚本文件
│   └── init.sql            # 数据库初始化脚本
├── tests/                  # 外部测试代码和集成测试
├── keys/                   # 密钥文件
├── logs/                   # 日志文件
├── .env                    # 环境配置
├── .env.example            # 环境配置示例
├── .gitignore
├── API.md                  # API 接口文档
├── CLAUDE.md               # Claude Code 指南
├── NEW_README.md           # 重构说明
├── README.md               # 项目说明
├── REFACTOR_PLAN.md        # 重构计划
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

## 重构说明

1. 符合标准 Go 项目布局规范
2. 测试文件与源文件在同一目录（*_test.go）
3. 避免了内部包被外部项目依赖的风险
4. 清晰的分层架构结构
5. 主入口文件放置在 cmd/server/main.go
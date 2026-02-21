# Go 项目标准目录结构

```
auth-service/
├── api/                    # API 定义和协议
│   └── v1/                 # API 版本
├── cmd/                    # 应用入口
│   └── server/             # 服务主入口
│       └── main.go
├── configs/                # 配置文件
├── deployments/            # 部署相关文件
├── docs/                   # 文档
├── internal/               # 内部应用代码 (不允许其他项目引用)
│   ├── config/             # 配置管理
│   ├── handler/            # HTTP handlers
│   ├── model/              # 数据模型
│   ├── middleware/         # 中间件
│   ├── service/            # 业务逻辑
│   ├── crypto/             # 加密工具
│   ├── keystore/           # 密钥管理
│   └── jwt/                # JWT 服务
├── pkg/                    # 可复用的公共包 (可被外部项目引用)
│   └── logger/             # 日志包
├── scripts/                # 脚本文件
├── test/                   # 外部测试代码和集成测试
├── third_party/            # 第三方依赖
├── tools/                  # 开发工具
├── vendor/                 # 依赖包 (可选)
├── web/                    # Web 资源
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

## 重构步骤

1. 将 `internal` 中的组件重新组织
2. 将测试代码移到 `test/` 目录
3. 将 `main.go` 移到 `cmd/server/`
4. 保持 `pkg/` 目录的公共包概念

## 当前文件迁移

- `main.go` → `cmd/server/main.go`
- `internal/config/` → `internal/config/` (保持)
- `internal/handler/` → `internal/handler/` (保持)
- `internal/model/` → `internal/model/` (保持)
- `internal/middleware/` → `internal/middleware/` (保持)
- `internal/service/` → `internal/service/` (保持)
- `internal/crypto/` → `internal/crypto/` (保持)
- `internal/keystore/` → `internal/keystore/` (保持)
- `internal/jwt/` → `internal/jwt/` (保持)
- `*_test.go` → `test/` 目录对应子目录
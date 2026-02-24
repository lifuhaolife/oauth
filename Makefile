# Makefile for Auth Service

.PHONY: help build test clean run docker-build docker-up docker-down lint \
        generate-keys generate-master-key health-check dev

# 默认目标
.DEFAULT_GOAL := help

# 变量
BINARY_NAME = auth-service
GO = go
DOCKER = docker
DOCKER_COMPOSE = docker-compose

help: ## 显示帮助信息
	@echo "Auth Service - Makefile Commands"
	@echo "================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## 编译构建
	@echo "Building $(BINARY_NAME)..."
	$(GO) build -o $(BINARY_NAME) ./cmd/server
	@echo "Build complete!"

run: ## 运行服务
	@echo "Starting auth service..."
	$(GO) run ./cmd/server

test: ## 运行所有测试
	@echo "Running tests..."
	$(GO) test -v ./...

test-coverage: ## 运行测试并生成覆盖率报告
	@echo "Running tests with coverage..."
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-race: ## 运行竞态检测
	@echo "Running race detector..."
	$(GO) test -race -v ./...

clean: ## 清理构建文件
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html
	rm -rf dist/
	@echo "Clean complete!"

lint: ## 代码检查 (需要安装 golangci-lint)
	@echo "Running linter..."
	golangci-lint run

lint-fix: ## 自动修复代码问题
	@echo "Running linter with fixes..."
	golangci-lint run --fix

docker-build: ## 构建 Docker 镜像
	@echo "Building Docker image..."
	$(DOCKER) build -t auth-service:latest .

docker-up: ## 启动 Docker 服务 (使用独立 MySQL)
	@echo "Starting Docker services (standalone mode)..."
	$(DOCKER_COMPOSE) -f docker-compose.standalone.yml up -d

docker-up-dev: ## 启动 Docker 服务 (包含 MySQL，开发模式)
	@echo "Starting Docker services (with MySQL)..."
	$(DOCKER_COMPOSE) up -d

docker-down: ## 停止 Docker 服务 (使用独立 MySQL)
	@echo "Stopping Docker services (standalone mode)..."
	$(DOCKER_COMPOSE) -f docker-compose.standalone.yml down

docker-down-dev: ## 停止 Docker 服务 (包含 MySQL，开发模式)
	@echo "Stopping Docker services (with MySQL)..."
	$(DOCKER_COMPOSE) down

docker-logs: ## 查看 Docker 日志
	$(DOCKER_COMPOSE) -f docker-compose.standalone.yml logs -f auth-service

docker-logs-dev: ## 查看 Docker 日志 (开发模式)
	$(DOCKER_COMPOSE) logs -f auth-service

init-db: ## 初始化数据库 (如果使用 docker-compose.yml 中的 MySQL)
	@echo "Initializing database..."
	$(DOCKER_COMPOSE) up -d mysql
	@echo "Waiting for MySQL to be ready..."
	@sleep 5
	@echo "Database initialized!"

generate-key: ## 生成 MASTER_KEY（同 generate-master-key）
	@echo "Generating MASTER_KEY..."
	@openssl rand -base64 32
	@echo "Add this to your .env file as MASTER_KEY"

generate-keys: ## 生成 JWT RSA 密钥对（私钥+公钥）
	@echo "Generating JWT RSA key pair..."
	@mkdir -p cmd/server/keys
	@openssl genrsa -out cmd/server/keys/jwt_private_tmp.pem 2048 2>/dev/null
	@openssl pkcs8 -topk8 -nocrypt -in cmd/server/keys/jwt_private_tmp.pem \
	         -out cmd/server/keys/jwt_private.pem 2>/dev/null
	@openssl rsa -in cmd/server/keys/jwt_private_tmp.pem -pubout \
	         -out cmd/server/keys/jwt_public.pem 2>/dev/null
	@rm -f cmd/server/keys/jwt_private_tmp.pem
	@chmod 600 cmd/server/keys/jwt_private.pem
	@echo "JWT keys generated: cmd/server/keys/jwt_private.pem, cmd/server/keys/jwt_public.pem"

generate-master-key: ## 生成 MASTER_KEY（AES-256，Base64 编码）
	@printf "MASTER_KEY=%s\n" "$$(openssl rand -base64 32)"

health-check: ## 检查服务健康状态
	@curl -sf "http://localhost:$${SERVER_PORT:-8080}/health" | python3 -m json.tool 2>/dev/null \
	  || curl -sf "http://localhost:$${SERVER_PORT:-8080}/health"

mod-tidy: ## 整理依赖
	@echo "Running go mod tidy..."
	$(GO) mod tidy

mod-download: ## 下载依赖
	@echo "Downloading dependencies..."
	$(GO) mod download

vendor: ## 创建 vendor 目录
	@echo "Creating vendor directory..."
	$(GO) mod vendor

# 开发相关
dev: ## 本地开发启动（含环境检查，热加载优先使用 air）
	@bash scripts/dev.sh

# 生产构建
prod-build: ## 生产环境编译
	@echo "Building for production..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -a -installsuffix cgo -o $(BINARY_NAME)-linux-amd64 .
	@echo "Production build complete!"

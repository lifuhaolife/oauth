FROM golang:1.21-alpine AS builder

WORKDIR /build

# 安装依赖
RUN apk add --no-cache git

# 复制 go.mod 和 go.sum
COPY go.mod go.sum* ./
RUN go mod download || true

# 复制源代码
COPY . .

# 编译
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# 最终镜像
FROM alpine:latest

WORKDIR /app

# 安装 CA 证书
RUN apk --no-cache add ca-certificates

# 从构建器复制二进制文件
COPY --from=builder /build/main .
COPY --from=builder /build/.env.example .env.example

# 创建日志目录
RUN mkdir -p /app/logs

# 暴露端口
EXPOSE 8080

# 启动服务
CMD ["./main"]

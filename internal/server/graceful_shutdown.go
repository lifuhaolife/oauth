package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// GracefulShutdown 优雅停机
func GracefulShutdown(server *http.Server, shutdownTimeout time.Duration) {
	// 创建信号通道
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	
	// 等待信号
	<-quit
	log.Println("接收到关闭信号，开始优雅停机...")
	
	// 创建超时context
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	
	// 关闭服务器
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("服务器强制关闭: %v", err)
	}
	
	log.Println("服务器已优雅关闭")
}
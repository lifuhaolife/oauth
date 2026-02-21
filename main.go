package main

import (
	"auth-service/internal/config"
	"auth-service/internal/handler"
	"auth-service/internal/middleware"
	"auth-service/internal/model"
	"auth-service/internal/service"
	"auth-service/internal/keystore"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	// 加载配置
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("加载配置失败：%v", err)
	}

	// 初始化数据库
	if err := model.InitDB(cfg); err != nil {
		log.Fatalf("初始化数据库失败：%v", err)
	}

	// 初始化密钥管理
	if err := keystore.InitKeyStore(cfg); err != nil {
		log.Fatalf("初始化密钥管理失败：%v", err)
	}

	// 初始化服务
	service.InitServices()

	// 设置 Gin 模式
	gin.SetMode(cfg.ServerMode)

	// 创建路由
	r := gin.Default()

	// 全局中间件
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.RateLimitMiddleware())
	r.Use(middleware.LogMiddleware())

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// 认证路由组
	authGroup := r.Group("/api/v1/auth")
	{
		// 获取 RSA 公钥
		authGroup.GET("/pubkey", handler.GetRSAPublicKey)

		// 微信登录配置 URL
		authGroup.GET("/wechat/url", handler.GetWechatAuthURL)

		// 微信登录回调
		authGroup.GET("/wechat/callback", handler.WechatCallback)

		// 登录接口
		authGroup.POST("/login", handler.Login)

		// 刷新 Token
		authGroup.POST("/refresh", handler.RefreshToken)

		// 登出
		authGroup.POST("/logout", middleware.AuthMiddleware(), handler.Logout)
	}

	// 用户路由组 (需要认证)
	userGroup := r.Group("/api/v1/user")
	userGroup.Use(middleware.AuthMiddleware())
	{
		userGroup.GET("/me", handler.GetCurrentUser)
		userGroup.PUT("/password", handler.ChangePassword)
	}

	// 管理路由组 (需要管理员权限)
	adminGroup := r.Group("/api/v1/admin")
	adminGroup.Use(middleware.AuthMiddleware(), middleware.AdminMiddleware())
	{
		adminGroup.GET("/users", handler.ListUsers)
		adminGroup.PUT("/users/:id/status", handler.UpdateUserStatus)
		adminGroup.GET("/login-logs", handler.GetLoginLogs)
		adminGroup.GET("/keys/stats", handler.GetKeyStats)
	}

	// JWK 端点 (用于 JWT 公钥发现)
	r.GET("/.well-known/jwks.json", handler.GetJWKS)

	// 启动服务
	addr := ":" + cfg.ServerPort
	log.Printf("启动认证服务，监听端口：%s", cfg.ServerPort)
	if err := r.Run(addr); err != nil {
		log.Fatalf("启动服务失败：%v", err)
	}
}

package main

import (
	"auth-service/internal/config"
	"auth-service/internal/handler"
	"auth-service/internal/keystore"
	"auth-service/internal/middleware"
	"auth-service/internal/migrate"
	"auth-service/internal/model"
	"auth-service/internal/server"
	"auth-service/internal/service"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// 加载配置
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("加载配置失败：%v", err)
	}

	// 初始化日志配置（根据 LOG_LEVEL 环境变量设置级别）
	config.SetLogLevel(cfg.LogLevel)
	config.SetupLogger()
	log.Printf("日志系统初始化完成，级别: %s", cfg.LogLevel)

	// 初始化数据库
	if err := model.InitDB(cfg); err != nil {
		log.Fatalf("初始化数据库失败：%v", err)
	}

	// 执行版本化 SQL 迁移（在 AutoMigrate 之前）
	if err := migrate.RunMigrations(model.GetDB()); err != nil {
		log.Fatalf("数据库迁移失败：%v", err)
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
	r := gin.New()

	// 全局中间件 - 按照重要性排序
	r.Use(middleware.RecoveryMiddleware())     // 恐慌恢复（最先）
	r.Use(middleware.TimeoutMiddleware(30 * time.Second)) // 30秒超时控制
	r.Use(middleware.LogMiddleware())          // 日志记录
	r.Use(middleware.MonitorMiddleware())      // API监控
	r.Use(middleware.CORSMiddleware())         // CORS处理
	r.Use(middleware.RateLimitMiddleware())    // 限流

	// 健康检查和就绪检查
	r.GET("/health", handler.HealthCheck)
	r.GET("/ready", handler.ReadyCheck)
	r.GET("/metrics", middleware.MetricsHandler)

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
		adminGroup.POST("/users/create", handler.CreateUser)
		adminGroup.PUT("/users/:id/status", handler.UpdateUserStatus)
		adminGroup.GET("/login-logs", handler.GetLoginLogs)
		adminGroup.GET("/keys/stats", handler.GetKeyStats)
	}

	// JWK 端点 (用于 JWT 公钥发现)
	r.GET("/.well-known/jwks.json", handler.GetJWKS)

	// 创建HTTP服务器
	addr := ":" + cfg.ServerPort
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	// 在goroutine中启动服务器
	go func() {
		log.Printf("启动认证服务，监听端口：%s", cfg.ServerPort)
		log.Printf("服务版本: 1.0.0")
		log.Printf("运行模式: %s", cfg.ServerMode)
		
		// 启动监控日志记录器
		middleware.StartMetricsLogger()
		log.Printf("监控日志记录器已启动")
		
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("启动服务失败：%v", err)
		}
	}()

	// 等待中断信号进行优雅停机
	server.GracefulShutdown(srv, 30*time.Second)
}
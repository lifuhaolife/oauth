package middleware

import (
	"auth-service/internal/service"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// CORSMiddleware CORS 跨域中间件
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Request-ID")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RateLimitMiddleware 速率限制中间件 (防暴力破解)
func RateLimitMiddleware() gin.HandlerFunc {
	// 按 IP 限制
	visitors := make(map[string]*rate.Limiter)

	return func(c *gin.Context) {
		ip := c.ClientIP()

		limiter, exists := visitors[ip]
		if !exists {
			// 每分钟 60 次请求，突发 10 次
			limiter = rate.NewLimiter(rate.Every(time.Minute/60), 10)
			visitors[ip] = limiter
		}

		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "请求过于频繁，请稍后再试",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// LogMiddleware 日志中间件
func LogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		// 处理请求
		c.Next()

		// 记录日志
		latency := time.Since(start)
		statusCode := c.Writer.Status()

		// 跳过健康检查日志
		if path != "/health" {
			println("[HTTP] ", c.Request.Method, path, statusCode, latency.String())
		}
	}
}

// AuthMiddleware JWT 认证中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取 Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "缺少认证信息",
			})
			c.Abort()
			return
		}

		// 解析 Bearer Token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "无效的认证格式",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// 验证 Token
		authService := service.GetAuthService()
		claims, err := authService.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "无效的 Token",
			})
			c.Abort()
			return
		}

		// 将用户信息注入上下文
		c.Set("user_id", int64(claims["sub"].(float64)))
		c.Set("username", claims["username"])

		c.Next()
	}
}

// AdminMiddleware 管理员权限中间件
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _ := c.Get("user_id")

		// 查询用户角色
		// 简单实现：检查是否是管理员
		// 实际应该从数据库或缓存中获取

		// 临时实现：假设 user_id=1 是管理员
		if userID.(int64) != 1 {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "需要管理员权限",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

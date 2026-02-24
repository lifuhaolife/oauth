package middleware

import (
	"auth-service/internal/model"
	"auth-service/internal/service"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// CORSMiddleware CORS 跨域中间件
// 通过 CORS_ALLOWED_ORIGINS 环境变量配置允许的域名（逗号分隔）。
// 未配置或值为 * 时，使用通配符（不携带 Credentials）。
func CORSMiddleware() gin.HandlerFunc {
	allowedOriginsEnv := os.Getenv("CORS_ALLOWED_ORIGINS")
	var allowedOrigins []string
	useWildcard := allowedOriginsEnv == "" || allowedOriginsEnv == "*"
	if !useWildcard {
		for _, o := range strings.Split(allowedOriginsEnv, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				allowedOrigins = append(allowedOrigins, o)
			}
		}
		if len(allowedOrigins) == 0 {
			useWildcard = true
		}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		if useWildcard {
			// 通配符模式：不设置 Credentials（W3C 规范要求）
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			// 精确匹配模式
			matched := false
			for _, o := range allowedOrigins {
				if o == origin {
					matched = true
					break
				}
			}
			if matched {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
				c.Writer.Header().Set("Vary", "Origin")
			}
		}

		c.Writer.Header().Set("Access-Control-Allow-Headers",
			"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Request-ID")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// visitorEntry 限流条目，包含 Limiter 和最后访问时间
type visitorEntry struct {
	limiter    *rate.Limiter
	lastSeen   time.Time
}

// RateLimitMiddleware 限流中间件（按 IP，含过期清理防 OOM）
func RateLimitMiddleware() gin.HandlerFunc {
	var mu sync.Mutex
	visitors := make(map[string]*visitorEntry)

	// 后台清理：每 5 分钟清除超过 10 分钟未访问的 IP
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			threshold := time.Now().Add(-10 * time.Minute)
			for ip, v := range visitors {
				if v.lastSeen.Before(threshold) {
					delete(visitors, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()

		mu.Lock()
		v, exists := visitors[ip]
		if !exists {
			// 每分钟 60 次请求，突发上限 10
			v = &visitorEntry{
				limiter: rate.NewLimiter(rate.Every(time.Minute/60), 10),
			}
			visitors[ip] = v
		}
		v.lastSeen = time.Now()
		limiter := v.limiter
		mu.Unlock()

		if !limiter.Allow() {
			log.Printf("[RATE_LIMIT] IP=%s path=%s - 请求被限流", ip, c.Request.URL.Path)
			model.Fail(c, model.ErrRateLimit)
			c.Abort()
			return
		}

		c.Next()
	}
}

// LogMiddleware 日志中间件 - 只记录元数据，不打印请求体
func LogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()
		requestID := c.GetHeader("X-Request-ID")

		if requestID == "" {
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
		}

		c.Header("X-Request-ID", requestID)

		if path != "/health" {
			log.Printf("[REQUEST_START] request_id=%s method=%s path=%s client_ip=%s user_agent=%s",
				requestID, c.Request.Method, path, clientIP, userAgent)
		}

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()

		var errorMsg string
		if len(c.Errors) > 0 {
			errorMsg = c.Errors.String()
		}

		query := path
		if raw != "" {
			query = path + "?" + raw
		}

		if path != "/health" || statusCode != 200 {
			log.Printf("[REQUEST_END] request_id=%s method=%s path=%s status=%d latency=%v client_ip=%s user_agent=%s error=%s",
				requestID, c.Request.Method, query, statusCode, latency, clientIP, userAgent, errorMsg)
		}

		if latency > time.Second {
			log.Printf("[SLOW_REQUEST_WARNING] request_id=%s method=%s path=%s latency=%v",
				requestID, c.Request.Method, path, latency)
		}
	}
}

// RecoveryMiddleware 恐慌恢复中间件
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				stack := make([]byte, 4096)
				stack = stack[:runtime.Stack(stack, false)]

				requestID := c.GetHeader("X-Request-ID")
				if requestID == "" {
					requestID = "unknown"
				}

				log.Printf("[PANIC_RECOVERED] request_id=%s error=%v stack=%s", requestID, err, string(stack))

				model.Fail(c, model.ErrServerError)
				c.Abort()
			}
		}()
		c.Next()
	}
}

// AuthMiddleware JWT 认证中间件
// 验证顺序：提取 Bearer token → RS256 签名验证 → type==access 验证 → 黑名单检查
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		method := c.Request.Method
		requestID := c.GetHeader("X-Request-ID")

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Printf("[AUTH_FAILED] request_id=%s method=%s path=%s reason=missing_authorization_header",
				requestID, method, path)
			model.Fail(c, model.ErrNoAuth)
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Printf("[AUTH_FAILED] request_id=%s method=%s path=%s reason=invalid_format",
				requestID, method, path)
			model.FailMsg(c, model.ErrNoAuth, "无效的认证格式，需要 Bearer <token>")
			c.Abort()
			return
		}

		tokenString := parts[1]

		authService := service.GetAuthService()
		claims, err := authService.ValidateToken(tokenString)
		if err != nil {
			log.Printf("[AUTH_FAILED] request_id=%s method=%s path=%s reason=%v",
				requestID, method, path, err)
			model.Fail(c, model.ErrTokenInvalid)
			c.Abort()
			return
		}

		// 验证 token 类型：只接受 access token，拒绝 refresh token
		if claims["type"] != "access" {
			log.Printf("[AUTH_FAILED] request_id=%s method=%s path=%s reason=invalid_token_type type=%v",
				requestID, method, path, claims["type"])
			model.FailMsg(c, model.ErrTokenInvalid, "不接受 refresh token")
			c.Abort()
			return
		}

		userID := claims["sub"].(int64)
		username := claims["username"].(string)

		log.Printf("[AUTH_SUCCESS] request_id=%s method=%s path=%s user_id=%d username=%s",
			requestID, method, path, userID, username)

		c.Set("user_id", userID)
		c.Set("username", username)
		c.Set("request_id", requestID)

		c.Next()
	}
}

// AdminMiddleware 管理员权限中间件（基于 users.role 字段，非硬编码 ID）
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		requestID, _ := c.Get("request_id")
		path := c.Request.URL.Path

		db := model.GetDB()
		if db == nil {
			model.Fail(c, model.ErrForbidden)
			c.Abort()
			return
		}

		var user model.User
		if err := db.Select("role, status").First(&user, userID).Error; err != nil {
			log.Printf("[ADMIN_DENIED] request_id=%v path=%s user_id=%v - 查询用户失败: %v",
				requestID, path, userID, err)
			model.Fail(c, model.ErrForbidden)
			c.Abort()
			return
		}

		if user.Status != 1 || user.Role != "admin" {
			log.Printf("[ADMIN_DENIED] request_id=%v path=%s user_id=%v role=%s status=%d - 权限不足",
				requestID, path, userID, user.Role, user.Status)
			model.Fail(c, model.ErrForbidden)
			c.Abort()
			return
		}

		log.Printf("[ADMIN_GRANTED] request_id=%v path=%s user_id=%v", requestID, path, userID)
		c.Next()
	}
}

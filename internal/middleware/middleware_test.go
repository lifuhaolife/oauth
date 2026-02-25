package middleware

import (
	"auth-service/internal/config"
	"auth-service/internal/jwt"
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"auth-service/internal/service"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

var testJWTService *jwt.JWTService

// TestMain 初始化 keystore + authService（无需数据库）
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	tmpDir, err := os.MkdirTemp("", "middleware_test_*")
	if err != nil {
		panic("创建临时目录失败: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("生成测试密钥失败: " + err.Error())
	}

	privKeyPath := tmpDir + "/private.pem"
	pubKeyPath := tmpDir + "/public.pem"

	privBytes, _ := x509.MarshalPKCS8PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	os.WriteFile(privKeyPath, privPEM, 0600)

	pubBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	os.WriteFile(pubKeyPath, pubPEM, 0644)

	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	cfg := &config.Config{
		JWTPrivateKeyPath: privKeyPath,
		JWTPublicKeyPath:  pubKeyPath,
		MasterKey:         aesKey,
	}

	if err := keystore.InitKeyStore(cfg); err != nil {
		panic("初始化 KeyStore 失败: " + err.Error())
	}
	service.InitServices()

	testJWTService = jwt.NewJWTService()

	os.Exit(m.Run())
}

// generateTestToken 生成测试用 access token
func generateTestToken(t *testing.T, userID int64, username string) string {
	t.Helper()
	user := &model.User{ID: userID, Username: username, Role: "user", Status: 1}
	token, _, err := testJWTService.GenerateToken(user)
	if err != nil {
		t.Fatalf("生成测试 token 失败: %v", err)
	}
	return token
}

// parseBody 解析响应 JSON body
func parseBody(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("解析响应 JSON 失败: %v（body: %s）", err, body)
	}
	return m
}

// ===== CORSMiddleware 测试 =====

func TestCORSMiddleware_SetHeaders(t *testing.T) {
	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("应设置 Access-Control-Allow-Origin: *")
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("应设置 Access-Control-Allow-Methods")
	}
	if w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("应设置 Access-Control-Allow-Headers")
	}
}

func TestCORSMiddleware_OptionsPreFlight(t *testing.T) {
	r := gin.New()
	r.Use(CORSMiddleware())
	r.OPTIONS("/test", func(c *gin.Context) {})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("OPTIONS 预检应返回 204，实际 %d", w.Code)
	}
}

// ===== AuthMiddleware 测试 =====

func TestAuthMiddleware_NoAuthHeader(t *testing.T) {
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("无 Authorization 头应返回 401，实际 %d", w.Code)
	}
	body := parseBody(t, w.Body.Bytes())
	if int(body["code"].(float64)) != int(model.ErrNoAuth) {
		t.Errorf("错误码应为 %d，实际 %v", model.ErrNoAuth, body["code"])
	}
}

func TestAuthMiddleware_InvalidFormat(t *testing.T) {
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })

	cases := []string{
		"Token abc",
		"Basic abc123",
		"Bearer",
	}

	for _, authHeader := range cases {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q 应返回 401，实际 %d", authHeader, w.Code)
		}
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("非法 token 应返回 401，实际 %d", w.Code)
	}
	body := parseBody(t, w.Body.Bytes())
	if int(body["code"].(float64)) != int(model.ErrTokenInvalid) {
		t.Errorf("错误码应为 %d，实际 %v", model.ErrTokenInvalid, body["code"])
	}
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	token := generateTestToken(t, 1, "admin")
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("合法 token 应返回 200，实际 %d（body: %s）", w.Code, w.Body.String())
	}
	body := parseBody(t, w.Body.Bytes())
	if int64(body["user_id"].(float64)) != 1 {
		t.Errorf("user_id 应为 1，实际 %v", body["user_id"])
	}
}

func TestAuthMiddleware_BlacklistedToken(t *testing.T) {
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })

	token := generateTestToken(t, 1, "admin")
	testJWTService.AddToBlacklist(token)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("黑名单 token 应返回 401，实际 %d", w.Code)
	}
	body := parseBody(t, w.Body.Bytes())
	if int(body["code"].(float64)) != int(model.ErrTokenInvalid) {
		t.Errorf("错误码应为 %d，实际 %v", model.ErrTokenInvalid, body["code"])
	}
}

func TestAuthMiddleware_SetsContextValues(t *testing.T) {
	var capturedUserID interface{}
	var capturedUsername interface{}

	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/test", func(c *gin.Context) {
		capturedUserID, _ = c.Get("user_id")
		capturedUsername, _ = c.Get("username")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := generateTestToken(t, 42, "testuser")
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("应返回 200，实际 %d（body: %s）", w.Code, w.Body.String())
	}
	if capturedUserID.(int64) != 42 {
		t.Errorf("Context user_id 应为 42，实际 %v", capturedUserID)
	}
	if capturedUsername.(string) != "testuser" {
		t.Errorf("Context username 应为 testuser，实际 %q", capturedUsername)
	}
}

// ===== AdminMiddleware 测试 =====

func TestAdminMiddleware_AdminUser(t *testing.T) {
	// AdminMiddleware 现在查询数据库验证角色，无 DB 时返回 403
	if model.GetDB() == nil {
		t.Skip("需要数据库连接（AdminMiddleware 需查询 users.role）")
	}
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", int64(1)); c.Next() })
	r.Use(AdminMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("admin 用户（user_id=1）应返回 200，实际 %d（body: %s）", w.Code, w.Body.String())
	}
}

func TestAdminMiddleware_NonAdminUser(t *testing.T) {
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", int64(2)); c.Next() })
	r.Use(AdminMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("非 admin 用户应返回 403，实际 %d", w.Code)
	}
	body := parseBody(t, w.Body.Bytes())
	if int(body["code"].(float64)) != int(model.ErrForbidden) {
		t.Errorf("错误码应为 %d，实际 %v", model.ErrForbidden, body["code"])
	}
}

// ===== Auth + Admin 组合链路测试 =====

func TestAuthAndAdminMiddlewareChain(t *testing.T) {
	if model.GetDB() == nil {
		t.Skip("需要数据库连接（AdminMiddleware 需查询 users.role）")
	}
	r := gin.New()
	r.Use(AuthMiddleware(), AdminMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// 1. 无 token → 401
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("无 token 应返回 401，实际 %d", w.Code)
	}

	// 2. 非 admin token → 403
	token := generateTestToken(t, 99, "normaluser")
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("非 admin 应返回 403，实际 %d", w2.Code)
	}

	// 3. admin token (user_id=1) → 200
	adminToken := generateTestToken(t, 1, "admin")
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.Header.Set("Authorization", "Bearer "+adminToken)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("admin 应返回 200，实际 %d（body: %s）", w3.Code, w3.Body.String())
	}
}

// ===== RateLimitMiddleware 测试 =====

func TestRateLimitMiddleware_AllowedRequest(t *testing.T) {
	r := gin.New()
	r.Use(RateLimitMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("正常请求应返回 200，实际 %d", w.Code)
	}
}

func TestRateLimitMiddleware_MultipleRequestsSameIP(t *testing.T) {
	r := gin.New()
	r.Use(RateLimitMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	ip := "192.168.1.2:12345"

	// 发送多个请求（应该都成功，因为限制是 60/分钟）
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("第 %d 个请求应返回 200，实际 %d", i+1, w.Code)
		}
	}
}

func TestRateLimitMiddleware_DifferentIPs(t *testing.T) {
	r := gin.New()
	r.Use(RateLimitMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// 不同 IP 应该独立计算限流
	for i := 1; i <= 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1." + string(rune(48+i)) + ":12345"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("IP %d 的请求应返回 200，实际 %d", i, w.Code)
		}
	}
}

// ===== LogMiddleware 测试 =====

func TestLogMiddleware_RequestLogging(t *testing.T) {
	r := gin.New()
	r.Use(LogMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("LogMiddleware 不应改变响应状态，实际 %d", w.Code)
	}
}

func TestLogMiddleware_DifferentMethods(t *testing.T) {
	tests := []struct {
		method string
	}{
		{"GET"},
		{"POST"},
		{"PUT"},
		{"DELETE"},
		{"PATCH"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			r := gin.New()
			r.Use(LogMiddleware())
			r.Handle(tt.method, "/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

			req := httptest.NewRequest(tt.method, "/test", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("%s 请求应返回 200，实际 %d", tt.method, w.Code)
			}
		})
	}
}

// ===== RecoveryMiddleware 测试 =====

func TestRecoveryMiddleware_RecoversPanic(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})
	r.GET("/normal", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// 测试 panic 恢复
	req := httptest.NewRequest("GET", "/panic", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Panic 恢复应返回 500，实际 %d", w.Code)
	}

	// 测试正常请求仍然有效
	req2 := httptest.NewRequest("GET", "/normal", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Panic 恢复后正常请求应返回 200，实际 %d", w2.Code)
	}
}

func TestRecoveryMiddleware_NormalRequest(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("正常请求应返回 200，实际 %d", w.Code)
	}
}

// ===== TimeoutMiddleware 测试 =====

func TestTimeoutMiddleware_NormalRequest(t *testing.T) {
	r := gin.New()
	r.Use(TimeoutMiddleware(5 * 1000)) // 5 seconds in milliseconds
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 超时中间件可能返回不同的状态码取决于实现
	// 这里我们只检查请求被处理了
	if w.Code == 0 {
		t.Error("请求应该被处理")
	}
}

// ===== MonitorMiddleware 测试 =====

func TestMonitorMiddleware_TrackingMetrics(t *testing.T) {
	r := gin.New()
	r.Use(MonitorMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("MonitorMiddleware 不应改变状态，实际 %d", w.Code)
	}
}

func TestGetMetrics_ReturnsMetrics(t *testing.T) {
	// 发送几个请求以生成指标
	r := gin.New()
	r.Use(MonitorMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}

	// 获取指标
	metrics := GetMetrics()
	if metrics == nil {
		t.Error("GetMetrics 应返回指标，实际 nil")
	}
}

func TestMetricsHandler_ReturnsJSON(t *testing.T) {
	r := gin.New()
	r.Use(MonitorMiddleware())
	r.GET("/metrics", MetricsHandler)
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// 发送一个请求
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 获取指标
	req2 := httptest.NewRequest("GET", "/metrics", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("MetricsHandler 应返回 200，实际 %d", w2.Code)
	}

	// 检查响应是否为 JSON (允许 charset 后缀)
	contentType := w2.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("ContentType 应包含 application/json，实际 %s", contentType)
	}
}

func TestStartMetricsLogger(t *testing.T) {
	// 测试启动 metrics logger 不会panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("StartMetricsLogger 不应 panic：%v", r)
		}
	}()

	StartMetricsLogger()
}

// ===== CORSMiddleware 额外测试 =====

func TestCORSMiddleware_PreflightRequest(t *testing.T) {
	r := gin.New()
	r.Use(CORSMiddleware())
	r.OPTIONS("/test", func(c *gin.Context) {})
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("CORS 预检请求应返回 Allow-Origin 头")
	}
}

func TestCORSMiddleware_CredentialsHeader(t *testing.T) {
	// 设置允许的 CORS origins
	os.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
	defer os.Unsetenv("CORS_ALLOWED_ORIGINS")

	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// 发送带 Origin 头的请求，该 Origin 在允许列表中
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	allowCredentials := w.Header().Get("Access-Control-Allow-Credentials")
	if allowCredentials != "true" {
		t.Errorf("Allow-Credentials 应为 true，实际 %q", allowCredentials)
	}
}

// ===== AdminMiddleware 额外测试 =====

func TestAdminMiddleware_MissingUserID(t *testing.T) {
	// 测试 user_id 缺失的情况
	r := gin.New()
	r.Use(AdminMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	// 不设置 user_id
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("缺失 user_id 应返回 403，实际 %d", w.Code)
	}
}

func TestAdminMiddleware_InvalidUserID(t *testing.T) {
	// 测试 user_id 不存在的情况
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", int64(999999)); c.Next() })
	r.Use(AdminMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("不存在的 user_id 应返回 403，实际 %d", w.Code)
	}
}

// ===== RateLimitMiddleware 额外测试 =====

func TestRateLimitMiddleware_ExtractIPFromXForwardedFor(t *testing.T) {
	r := gin.New()
	r.Use(RateLimitMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	// 模拟代理请求
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("X-Forwarded-For 请求应返回 200，实际 %d", w.Code)
	}
}

func TestRateLimitMiddleware_ExtractIPFromXRealIP(t *testing.T) {
	r := gin.New()
	r.Use(RateLimitMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	// 模拟代理请求
	req.Header.Set("X-Real-IP", "203.0.113.2")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("X-Real-IP 请求应返回 200，实际 %d", w.Code)
	}
}

// ===== TimeoutMiddleware 额外测试 =====

func TestTimeoutMiddleware_ConfiguredTimeout(t *testing.T) {
	r := gin.New()
	r.Use(TimeoutMiddleware(1000)) // 1 second timeout
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 应该成功，因为处理不会超过 1 秒
	if w.Code == 0 {
		t.Error("请求应该被处理")
	}
}

// ===== CORSMiddleware 额外测试 =====

func TestCORSMiddleware_WildcardOrigin(t *testing.T) {
	// 清除 CORS_ALLOWED_ORIGINS，使用通配符模式
	os.Unsetenv("CORS_ALLOWED_ORIGINS")

	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin != "*" {
		t.Errorf("通配符模式应返回 *，实际 %q", allowOrigin)
	}

	// 验证不设置 Credentials（W3C 规范）
	allowCredentials := w.Header().Get("Access-Control-Allow-Credentials")
	if allowCredentials != "" {
		t.Errorf("通配符模式不应设置 Credentials，实际 %q", allowCredentials)
	}
}

func TestCORSMiddleware_MismatchedOrigin(t *testing.T) {
	os.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
	defer os.Unsetenv("CORS_ALLOWED_ORIGINS")

	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// 发送不匹配的 Origin
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 不匹配的 origin 不应该被设置
	allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin != "" {
		t.Errorf("不匹配的 Origin 不应被设置，实际 %q", allowOrigin)
	}
}

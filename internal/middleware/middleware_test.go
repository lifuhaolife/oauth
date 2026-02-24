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

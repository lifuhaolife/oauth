package handler

import (
	"auth-service/internal/config"
	"auth-service/internal/jwt"
	"auth-service/internal/keystore"
	"auth-service/internal/middleware"
	"auth-service/internal/model"
	"auth-service/internal/service"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

var testJWTSvc *jwt.JWTService

// TestMain 初始化 keystore + service（无需数据库）
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	tmpDir, err := os.MkdirTemp("", "handler_test_*")
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
	testJWTSvc = jwt.NewJWTService()

	os.Exit(m.Run())
}

// setupRouter 构建与 main.go 一致的测试路由
func setupRouter() *gin.Engine {
	r := gin.New()
	r.Use(middleware.CORSMiddleware())

	r.GET("/health", func(c *gin.Context) {
		model.OK(c, gin.H{"status": "ok"})
	})

	authGroup := r.Group("/api/v1/auth")
	{
		authGroup.GET("/pubkey", GetRSAPublicKey)
		authGroup.POST("/login", Login)
		authGroup.POST("/refresh", RefreshToken)
		authGroup.POST("/logout", middleware.AuthMiddleware(), Logout)
	}

	userGroup := r.Group("/api/v1/user")
	userGroup.Use(middleware.AuthMiddleware())
	{
		userGroup.GET("/me", GetCurrentUser)
		userGroup.PUT("/password", ChangePassword)
	}

	adminGroup := r.Group("/api/v1/admin")
	adminGroup.Use(middleware.AuthMiddleware(), middleware.AdminMiddleware())
	{
		adminGroup.GET("/users", ListUsers)
		adminGroup.POST("/users/create", CreateUser)
		adminGroup.PUT("/users/:id/status", UpdateUserStatus)
		adminGroup.GET("/login-logs", GetLoginLogs)
		adminGroup.GET("/keys/stats", GetKeyStats)
	}

	r.GET("/.well-known/jwks.json", GetJWKS)

	return r
}

// do 发送测试请求的辅助函数
func do(r *gin.Engine, method, path, body, token string) *httptest.ResponseRecorder {
	var reqBody *bytes.Reader
	if body != "" {
		reqBody = bytes.NewReader([]byte(body))
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// parseResp 解析 JSON 响应
func parseResp(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("解析响应失败: %v（body: %s）", err, w.Body.String())
	}
	return m
}

// tokenFor 生成指定用户的 access token
func tokenFor(t *testing.T, userID int64, username string) string {
	t.Helper()
	user := &model.User{ID: userID, Username: username, Role: "user", Status: 1}
	token, _, err := testJWTSvc.GenerateToken(user)
	if err != nil {
		t.Fatalf("生成 token 失败: %v", err)
	}
	return token
}

// ===== 健康检查 =====

func TestHealthCheck(t *testing.T) {
	r := setupRouter()
	w := do(r, "GET", "/health", "", "")

	if w.Code != http.StatusOK {
		t.Errorf("健康检查应返回 200，实际 %d", w.Code)
	}
	resp := parseResp(t, w)
	if int(resp["code"].(float64)) != 0 {
		t.Errorf("code 应为 0，实际 %v", resp["code"])
	}
}

// ===== GetRSAPublicKey 测试 =====

func TestGetRSAPublicKey(t *testing.T) {
	r := setupRouter()
	w := do(r, "GET", "/api/v1/auth/pubkey", "", "")

	if w.Code != http.StatusOK {
		t.Errorf("pubkey 应返回 200，实际 %d（body: %s）", w.Code, w.Body.String())
	}
	resp := parseResp(t, w)
	if int(resp["code"].(float64)) != 0 {
		t.Errorf("code 应为 0，实际 %v", resp["code"])
	}

	data := resp["data"].(map[string]interface{})
	if data["key_id"] == nil || data["key_id"].(string) == "" {
		t.Error("key_id 不应为空")
	}
	if data["public_key"] == nil || data["public_key"].(string) == "" {
		t.Error("public_key 不应为空")
	}

	// 公钥应为有效 Base64，解码后为 PEM
	pubKeyB64 := data["public_key"].(string)
	pubKeyPEM, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		t.Fatalf("public_key 不是有效 Base64: %v", err)
	}
	if !strings.Contains(string(pubKeyPEM), "PUBLIC KEY") {
		t.Error("解码后应为 PEM 格式公钥")
	}
}

func TestGetRSAPublicKeyNoAuth(t *testing.T) {
	// pubkey 接口无需鉴权
	r := setupRouter()
	w := do(r, "GET", "/api/v1/auth/pubkey", "", "")

	if w.Code != http.StatusOK {
		t.Errorf("pubkey 无需鉴权应返回 200，实际 %d", w.Code)
	}
}

// ===== GetJWKS 测试 =====

func TestGetJWKS(t *testing.T) {
	r := setupRouter()
	w := do(r, "GET", "/.well-known/jwks.json", "", "")

	if w.Code != http.StatusOK {
		t.Errorf("JWKS 应返回 200，实际 %d", w.Code)
	}

	var jwks model.JWKSResponse
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("JWKS 响应格式错误: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS 应包含至少一个密钥")
	}

	key := jwks.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("kty 应为 RSA，实际 %q", key.Kty)
	}
	if key.Alg != "RS256" {
		t.Errorf("alg 应为 RS256，实际 %q", key.Alg)
	}
	if key.N == "" || key.E == "" {
		t.Error("n 和 e 不应为空")
	}
}

// ===== Login 接口测试（不含 DB 查询的参数验证） =====

func TestLogin_MissingParams(t *testing.T) {
	r := setupRouter()

	// 缺少必填字段
	cases := []string{
		`{}`,
		`{"key_id":"test"}`,
		`{"key_id":"test","encrypted_data":"x"}`,
		`{"key_id":"test","encrypted_data":"x","timestamp":1234567890}`,
	}

	for _, body := range cases {
		w := do(r, "POST", "/api/v1/auth/login", body, "")
		if w.Code == http.StatusOK {
			t.Errorf("缺少必填字段 %q 应返回错误，实际 200", body)
		}
	}
}

func TestLogin_ExpiredTimestamp(t *testing.T) {
	r := setupRouter()

	// 获取一个真实公钥 key_id
	wPub := do(r, "GET", "/api/v1/auth/pubkey", "", "")
	pubResp := parseResp(t, wPub)
	keyID := pubResp["data"].(map[string]interface{})["key_id"].(string)

	// 时间戳超过 5 分钟前
	body := json.RawMessage(`{"key_id":"` + keyID + `","encrypted_data":"dGVzdA==","timestamp":` +
		strings.TrimSpace(jsonInt(time.Now().Unix()-400)) + `,"nonce":"test"}`)

	w := do(r, "POST", "/api/v1/auth/login", string(body), "")
	resp := parseResp(t, w)
	if int(resp["code"].(float64)) != int(model.ErrRequestExpired) {
		t.Errorf("过期时间戳应返回 code=%d，实际 %v", model.ErrRequestExpired, resp["code"])
	}
}

func TestLogin_InvalidKeyID(t *testing.T) {
	r := setupRouter()

	body := `{"key_id":"nonexistent-key-id-00000000","encrypted_data":"dGVzdA==","timestamp":` +
		jsonInt(time.Now().Unix()) + `,"nonce":"abc"}`

	w := do(r, "POST", "/api/v1/auth/login", body, "")
	resp := parseResp(t, w)
	if int(resp["code"].(float64)) != int(model.ErrKeyInvalid) {
		t.Errorf("无效 key_id 应返回 code=%d，实际 %v", model.ErrKeyInvalid, resp["code"])
	}
}

func TestLogin_InvalidBase64(t *testing.T) {
	r := setupRouter()

	// 获取有效 key_id
	wPub := do(r, "GET", "/api/v1/auth/pubkey", "", "")
	pubResp := parseResp(t, wPub)
	keyID := pubResp["data"].(map[string]interface{})["key_id"].(string)

	body := `{"key_id":"` + keyID + `","encrypted_data":"not-valid-base64!!!","timestamp":` +
		jsonInt(time.Now().Unix()) + `,"nonce":"abc"}`

	w := do(r, "POST", "/api/v1/auth/login", body, "")
	resp := parseResp(t, w)
	// 应返回解密相关错误（20002 或 10002）
	code := int(resp["code"].(float64))
	if code == 0 {
		t.Errorf("非法 Base64 应返回错误，实际 code=%d", code)
	}
}

// ===== RefreshToken 测试（不含 DB） =====

func TestRefreshToken_InvalidToken(t *testing.T) {
	r := setupRouter()
	w := do(r, "POST", "/api/v1/auth/refresh", `{"refresh_token":"invalid.token.here"}`, "")

	resp := parseResp(t, w)
	if int(resp["code"].(float64)) != int(model.ErrTokenInvalid) {
		t.Errorf("非法 refresh_token 应返回 code=%d，实际 %v", model.ErrTokenInvalid, resp["code"])
	}
}

func TestRefreshToken_MissingField(t *testing.T) {
	r := setupRouter()
	w := do(r, "POST", "/api/v1/auth/refresh", `{}`, "")

	if w.Code == http.StatusOK {
		t.Error("缺少 refresh_token 字段应返回错误")
	}
}

func TestRefreshToken_NoAuthRequired(t *testing.T) {
	// /auth/refresh 无需 Authorization 头
	r := setupRouter()
	w := do(r, "POST", "/api/v1/auth/refresh", `{"refresh_token":"invalid.token"}`, "")
	// 不应因为缺少 Authorization 头而返回 401，而是因为 token 非法返回 30004
	resp := parseResp(t, w)
	code := int(resp["code"].(float64))
	if code == int(model.ErrNoAuth) {
		t.Error("/auth/refresh 不需要鉴权，不应返回 30001")
	}
}

// ===== 鉴权拦截测试 =====

func TestProtectedEndpoints_NoToken(t *testing.T) {
	r := setupRouter()

	protected := []struct{ method, path string }{
		{"GET", "/api/v1/user/me"},
		{"PUT", "/api/v1/user/password"},
		{"POST", "/api/v1/auth/logout"},
		{"GET", "/api/v1/admin/users"},
		{"POST", "/api/v1/admin/users/create"},
		{"GET", "/api/v1/admin/login-logs"},
		{"GET", "/api/v1/admin/keys/stats"},
	}

	for _, ep := range protected {
		w := do(r, ep.method, ep.path, "", "")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 无 token 应返回 401，实际 %d", ep.method, ep.path, w.Code)
		}
		resp := parseResp(t, w)
		if int(resp["code"].(float64)) != int(model.ErrNoAuth) {
			t.Errorf("%s %s 错误码应为 %d，实际 %v", ep.method, ep.path, model.ErrNoAuth, resp["code"])
		}
	}
}

func TestAdminEndpoints_NonAdminToken(t *testing.T) {
	r := setupRouter()
	token := tokenFor(t, 99, "normaluser")

	adminEndpoints := []struct{ method, path string }{
		{"GET", "/api/v1/admin/users"},
		{"GET", "/api/v1/admin/login-logs"},
		{"GET", "/api/v1/admin/keys/stats"},
	}

	for _, ep := range adminEndpoints {
		w := do(r, ep.method, ep.path, "", token)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s 非 admin 应返回 403，实际 %d", ep.method, ep.path, w.Code)
		}
		resp := parseResp(t, w)
		if int(resp["code"].(float64)) != int(model.ErrForbidden) {
			t.Errorf("%s %s 错误码应为 %d，实际 %v", ep.method, ep.path, model.ErrForbidden, resp["code"])
		}
	}
}

// ===== GetKeyStats 测试 =====

func TestGetKeyStats_AdminOnly(t *testing.T) {
	// AdminMiddleware 现在查询数据库验证角色，无 DB 时返回 403
	if model.GetDB() == nil {
		t.Skip("需要数据库连接（AdminMiddleware 需查询 users.role）")
	}
	r := setupRouter()

	adminToken := tokenFor(t, 1, "admin")
	w := do(r, "GET", "/api/v1/admin/keys/stats", "", adminToken)

	if w.Code != http.StatusOK {
		t.Errorf("admin 访问 /admin/keys/stats 应返回 200，实际 %d（body: %s）", w.Code, w.Body.String())
	}
	resp := parseResp(t, w)
	if int(resp["code"].(float64)) != 0 {
		t.Errorf("code 应为 0，实际 %v", resp["code"])
	}

	data := resp["data"].(map[string]interface{})
	if _, ok := data["rsa_pool_active"]; !ok {
		t.Error("响应应包含 rsa_pool_active")
	}
	if _, ok := data["jwt_key_loaded"]; !ok {
		t.Error("响应应包含 jwt_key_loaded")
	}
}

// ===== 公开接口无需鉴权验证 =====

func TestPublicEndpoints_NoToken(t *testing.T) {
	r := setupRouter()

	public := []struct{ method, path string }{
		{"GET", "/health"},
		{"GET", "/api/v1/auth/pubkey"},
		{"GET", "/.well-known/jwks.json"},
	}

	for _, ep := range public {
		w := do(r, ep.method, ep.path, "", "")
		if w.Code == http.StatusUnauthorized {
			t.Errorf("%s %s 公开接口不应要求鉴权，实际返回 401", ep.method, ep.path)
		}
	}
}

// ===== DB 相关 Handler 测试（需要数据库时运行） =====

func TestLogin_WithDB(t *testing.T) {
	t.Skip("需要数据库连接，请在集成测试中运行")
}

func TestGetCurrentUser_WithDB(t *testing.T) {
	t.Skip("需要数据库连接，请在集成测试中运行")
}

func TestChangePassword_WithDB(t *testing.T) {
	t.Skip("需要数据库连接，请在集成测试中运行")
}

func TestListUsers_WithDB(t *testing.T) {
	t.Skip("需要数据库连接，请在集成测试中运行")
}

func TestCreateUser_WithDB(t *testing.T) {
	t.Skip("需要数据库连接，请在集成测试中运行")
}

// jsonInt 将 int64 转为 JSON 数字字符串
func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

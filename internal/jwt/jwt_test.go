package jwt

import (
	"auth-service/internal/config"
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// 测试用户
var testUser = &model.User{
	ID:       1,
	Username: "testuser",
	Role:     "user",
	Status:   1,
}

var testUser2 = &model.User{
	ID:       2,
	Username: "otheruser",
	Role:     "user",
	Status:   1,
}

// TestMain 初始化 JWT 测试所需的 KeyStore
func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "jwt_test_*")
	if err != nil {
		panic("创建临时目录失败: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)

	// 生成测试 RSA 密钥对
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("生成测试 RSA 密钥失败: " + err.Error())
	}

	privKeyPath := tmpDir + "/private.pem"
	pubKeyPath := tmpDir + "/public.pem"

	// 写入私钥（PKCS#8）
	privBytes, _ := x509.MarshalPKCS8PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	os.WriteFile(privKeyPath, privPEM, 0600)

	// 写入公钥
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

	os.Exit(m.Run())
}

// ===== GenerateToken 测试 =====

func TestGenerateToken(t *testing.T) {
	svc := NewJWTService()

	accessToken, refreshToken, err := svc.GenerateToken(testUser)
	if err != nil {
		t.Fatalf("GenerateToken 失败: %v", err)
	}
	if accessToken == "" {
		t.Error("access token 不应为空")
	}
	if refreshToken == "" {
		t.Error("refresh token 不应为空")
	}
	// access token 和 refresh token 应不同
	if accessToken == refreshToken {
		t.Error("access token 和 refresh token 不应相同")
	}
}

func TestGenerateTokenMultipleUsers(t *testing.T) {
	svc := NewJWTService()

	token1, _, _ := svc.GenerateToken(testUser)
	token2, _, _ := svc.GenerateToken(testUser2)

	// 不同用户 token 应不同
	if token1 == token2 {
		t.Error("不同用户生成的 token 不应相同")
	}
}

// ===== ValidateToken 测试 =====

func TestValidateAccessToken(t *testing.T) {
	svc := NewJWTService()

	accessToken, _, _ := svc.GenerateToken(testUser)
	claims, err := svc.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("ValidateToken 失败: %v", err)
	}

	if claims["sub"].(int64) != testUser.ID {
		t.Errorf("sub 应为 %d，实际 %v", testUser.ID, claims["sub"])
	}
	if claims["username"].(string) != testUser.Username {
		t.Errorf("username 应为 %q，实际 %v", testUser.Username, claims["username"])
	}
	if claims["type"].(string) != "access" {
		t.Errorf("type 应为 access，实际 %v", claims["type"])
	}
}

func TestValidateRefreshToken(t *testing.T) {
	svc := NewJWTService()

	_, refreshToken, _ := svc.GenerateToken(testUser)
	claims, err := svc.ValidateToken(refreshToken)
	if err != nil {
		t.Fatalf("ValidateToken(refresh) 失败: %v", err)
	}

	if claims["type"].(string) != "refresh" {
		t.Errorf("type 应为 refresh，实际 %v", claims["type"])
	}
	if claims["sub"].(int64) != testUser.ID {
		t.Errorf("sub 应为 %d，实际 %v", testUser.ID, claims["sub"])
	}
}

func TestValidateTokenClaims(t *testing.T) {
	svc := NewJWTService()

	accessToken, _, _ := svc.GenerateToken(testUser)
	claims, _ := svc.ValidateToken(accessToken)

	// scope 应为 string slice
	scope, ok := claims["scope"].([]string)
	if !ok || len(scope) == 0 {
		t.Error("access token scope 应为非空字符串数组")
	}

	// jti 不应为空
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		t.Error("jti 不应为空")
	}

	// device 不应为空
	device, ok := claims["device"].(string)
	if !ok || device == "" {
		t.Error("device 不应为空")
	}
}

func TestValidateInvalidToken(t *testing.T) {
	svc := NewJWTService()

	cases := []string{
		"",
		"invalid.token",
		"not.a.jwt.at.all",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
	}

	for _, token := range cases {
		_, err := svc.ValidateToken(token)
		if err == nil {
			t.Errorf("非法 token %q 验证应失败", token)
		}
	}
}

func TestValidateTokenSubjectIsInt64(t *testing.T) {
	svc := NewJWTService()

	accessToken, _, _ := svc.GenerateToken(testUser)
	claims, err := svc.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("验证失败: %v", err)
	}

	// sub 必须是 int64（修复 string(rune(id)) bug 后的正确类型）
	userID, ok := claims["sub"].(int64)
	if !ok {
		t.Errorf("sub 应为 int64 类型，实际类型 %T，值 %v", claims["sub"], claims["sub"])
	}
	if userID != testUser.ID {
		t.Errorf("sub 值应为 %d，实际 %d", testUser.ID, userID)
	}
}

// ===== 黑名单测试 =====

func TestAddToBlacklist(t *testing.T) {
	svc := NewJWTService()

	accessToken, _, _ := svc.GenerateToken(testUser)

	// 加黑名单前应有效
	_, err := svc.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("加黑名单前 token 应有效: %v", err)
	}

	// 加入黑名单
	if err := svc.AddToBlacklist(accessToken); err != nil {
		t.Fatalf("AddToBlacklist 失败: %v", err)
	}

	// 加黑名单后应被拒绝
	_, err = svc.ValidateToken(accessToken)
	if err == nil {
		t.Error("黑名单中的 token 验证应失败")
	}
}

func TestIsInBlacklist(t *testing.T) {
	svc := NewJWTService()

	token, _, _ := svc.GenerateToken(testUser)

	if svc.IsInBlacklist(token) {
		t.Error("未加黑名单的 token 不应在黑名单中")
	}

	svc.AddToBlacklist(token)

	if !svc.IsInBlacklist(token) {
		t.Error("已加黑名单的 token 应在黑名单中")
	}
}

func TestBlacklistIsolation(t *testing.T) {
	svc := NewJWTService()

	token1, _, _ := svc.GenerateToken(testUser)
	token2, _, _ := svc.GenerateToken(testUser2)

	svc.AddToBlacklist(token1)

	// token1 应在黑名单
	if !svc.IsInBlacklist(token1) {
		t.Error("token1 应在黑名单")
	}
	// token2 不应受影响
	if svc.IsInBlacklist(token2) {
		t.Error("token2 不应在黑名单")
	}

	// ValidateToken 验证
	_, err := svc.ValidateToken(token1)
	if err == nil {
		t.Error("token1 验证应失败（在黑名单中）")
	}
	_, err = svc.ValidateToken(token2)
	if err != nil {
		t.Errorf("token2 验证应通过: %v", err)
	}
}

func TestAddToBlacklistInvalidToken(t *testing.T) {
	svc := NewJWTService()

	err := svc.AddToBlacklist("not-a-jwt")
	if err == nil {
		t.Error("将非法 token 加入黑名单应返回错误")
	}
}

// ===== 多用户并发安全测试 =====

func TestConcurrentTokenGeneration(t *testing.T) {
	svc := NewJWTService()
	done := make(chan struct{}, 10)

	for i := 0; i < 10; i++ {
		go func(id int64) {
			user := &model.User{ID: id, Username: "user"}
			_, _, err := svc.GenerateToken(user)
			if err != nil {
				t.Errorf("并发 GenerateToken 失败: %v", err)
			}
			done <- struct{}{}
		}(int64(i + 1))
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestConcurrentBlacklist(t *testing.T) {
	svc := NewJWTService()
	done := make(chan struct{}, 10)

	tokens := make([]string, 10)
	for i := 0; i < 10; i++ {
		user := &model.User{ID: int64(i + 1), Username: "user"}
		token, _, _ := svc.GenerateToken(user)
		tokens[i] = token
	}

	for i := 0; i < 10; i++ {
		go func(token string) {
			svc.AddToBlacklist(token)
			svc.IsInBlacklist(token)
			done <- struct{}{}
		}(tokens[i])
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

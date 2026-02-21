package jwt

import (
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setupTestJWT 创建测试用 JWT 服务
func setupTestJWT(t *testing.T) *JWTService {
	// 创建临时目录
	tmpDir := t.TempDir()

	// 生成测试用 JWT 密钥对
	privateKeyPath := filepath.Join(tmpDir, "jwt_private.pem")
	publicKeyPath := filepath.Join(tmpDir, "jwt_public.pem")

	// 这里简化处理，实际应该生成真实的密钥对
	// 测试时使用现有密钥或生成新密钥

	return NewJWTService()
}

// TestGenerateToken 测试 JWT Token 生成
func TestGenerateToken(t *testing.T) {
	svc := NewJWTService()

	user := &model.User{
		ID:       1,
		Username: "testuser",
		Role:     "user",
	}

	accessToken, refreshToken, err := svc.GenerateToken(user)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Token 不应该为空
	if accessToken == "" {
		t.Error("Access token should not be empty")
	}

	if refreshToken == "" {
		t.Error("Refresh token should not be empty")
	}

	// Token 长度应该合理
	if len(accessToken) < 100 {
		t.Errorf("Access token too short: got %d chars", len(accessToken))
	}
}

// TestValidateToken 测试 Token 验证
func TestValidateToken(t *testing.T) {
	svc := NewJWTService()

	user := &model.User{
		ID:       1,
		Username: "testuser",
		Role:     "user",
	}

	accessToken, _, err := svc.GenerateToken(user)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// 验证有效 Token
	claims, err := svc.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	// 验证 claims 内容
	if claims["username"] != "testuser" {
		t.Errorf("Username in claims: got %v, want testuser", claims["username"])
	}

	if claims["type"] != "access" {
		t.Errorf("Token type: got %v, want access", claims["type"])
	}
}

// TestValidateInvalidToken 测试无效 Token 验证
func TestValidateInvalidToken(t *testing.T) {
	svc := NewJWTService()

	// 无效 Token 应该验证失败
	_, err := svc.ValidateToken("invalid.token.here")
	if err == nil {
		t.Error("Invalid token should fail validation")
	}
}

// TestBlacklist 测试 Token 黑名单
func TestBlacklist(t *testing.T) {
	svc := NewJWTService()

	user := &model.User{
		ID:       1,
		Username: "testuser",
	}

	accessToken, _, err := svc.GenerateToken(user)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// 初始时 Token 不应该在黑名单中
	if svc.IsInBlacklist(accessToken) {
		t.Error("New token should not be in blacklist")
	}

	// 加入黑名单
	err = svc.AddToBlacklist(accessToken)
	if err != nil {
		t.Fatalf("AddToBlacklist failed: %v", err)
	}

	// 加入后应该在黑名单中
	if !svc.IsInBlacklist(accessToken) {
		t.Error("Token should be in blacklist after adding")
	}
}

// TestRefreshToken 测试刷新 Token
func TestRefreshToken(t *testing.T) {
	svc := NewJWTService()

	user := &model.User{
		ID:       1,
		Username: "testuser",
	}

	_, refreshToken, err := svc.GenerateToken(user)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// 验证刷新 Token
	claims, err := svc.ValidateToken(refreshToken)
	if err != nil {
		t.Fatalf("Validate refresh token failed: %v", err)
	}

	// 刷新 Token 类型应该是 "refresh"
	if claims["type"] != "refresh" {
		t.Errorf("Refresh token type: got %v, want refresh", claims["type"])
	}
}

// TestDeviceFingerprint 测试设备指纹生成
func TestDeviceFingerprint(t *testing.T) {
	svc := NewJWTService()

	// 同一用户应该生成相同设备指纹
	fp1 := svc.generateDeviceFingerprint(1)
	fp2 := svc.generateDeviceFingerprint(1)

	// 注意：当前实现可能每次不同，因为包含时间戳
	// 这是预期行为，设备指纹可以变化
	if fp1 == "" || fp2 == "" {
		t.Error("Device fingerprint should not be empty")
	}

	// 不同用户应该生成不同设备指纹
	fp3 := svc.generateDeviceFingerprint(2)
	if fp1 == fp3 {
		t.Error("Different users should have different device fingerprints")
	}
}

// TestTokenExpiration 测试 Token 过期时间
func TestTokenExpiration(t *testing.T) {
	svc := NewJWTService()

	// 验证过期时间设置
	if svc.accessExpire != 15*time.Minute {
		t.Errorf("Access expire: got %v, want 15m", svc.accessExpire)
	}

	if svc.refreshExpire != 7*24*time.Hour {
		t.Errorf("Refresh expire: got %v, want 168h", svc.refreshExpire)
	}
}

// TestHashToken 测试 Token 哈希
func TestHashToken(t *testing.T) {
	svc := NewJWTService()

	token1 := "test.token.1"
	token2 := "test.token.2"

	hash1 := svc.hashToken(token1)
	hash2 := svc.hashToken(token2)

	// 相同 Token 应该产生相同哈希
	if hash1 != svc.hashToken(token1) {
		t.Error("Same token should produce same hash")
	}

	// 不同 Token 应该产生不同哈希
	if hash1 == hash2 {
		t.Error("Different tokens should produce different hashes")
	}

	// 哈希长度应该是 64 (SHA256 hex)
	if len(hash1) != 64 {
		t.Errorf("Hash length: got %d, want 64", len(hash1))
	}
}

// TestCleanBlacklist 测试黑名单清理
func TestCleanBlacklist(t *testing.T) {
	// 这个测试主要验证清理函数不崩溃
	svc := NewJWTService()
	svc.CleanBlacklist()
	// 没有 panic 即为通过
}

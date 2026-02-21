package model

import (
	"testing"
	"time"
)

// TestUserEncryptPhone 测试手机号加密
func TestUserEncryptPhone(t *testing.T) {
	user := &User{
		ID:       1,
		Username: "testuser",
	}

	key := []byte("01234567890123456789012345678901") // 32 字节
	phone := "13800138000"

	err := user.EncryptPhone(phone, key)
	if err != nil {
		t.Fatalf("EncryptPhone failed: %v", err)
	}

	// 加密后的数据不应该为空
	if len(user.PhoneEncrypted) == 0 {
		t.Error("Encrypted phone should not be empty")
	}

	// 加密后的数据不应该等于原手机号
	if string(user.PhoneEncrypted) == phone {
		t.Error("Encrypted phone should be different from original")
	}
}

// TestUserDecryptPhone 测试手机号解密
func TestUserDecryptPhone(t *testing.T) {
	user := &User{
		ID:       1,
		Username: "testuser",
	}

	key := []byte("01234567890123456789012345678901")
	phone := "13800138000"

	// 先加密
	user.EncryptPhone(phone, key)

	// 再解密
	err := user.DecryptPhone(key)
	if err != nil {
		t.Fatalf("DecryptPhone failed: %v", err)
	}

	// 解密后的手机号应该与原手机号相同
	if user.Phone != phone {
		t.Errorf("Decrypted phone: got %s, want %s", user.Phone, phone)
	}
}

// TestUserDecryptPhoneWrongKey 测试错误密钥解密
func TestUserDecryptPhoneWrongKey(t *testing.T) {
	user := &User{
		ID:       1,
		Username: "testuser",
	}

	key1 := []byte("01234567890123456789012345678901")
	key2 := []byte("different_key_123456789012345")
	phone := "13800138000"

	// 用 key1 加密
	user.EncryptPhone(phone, key1)

	// 用 key2 解密应该失败
	err := user.DecryptPhone(key2)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

// TestUserGetMaskedPhone 测试手机号脱敏
func TestUserGetMaskedPhone(t *testing.T) {
	user := &User{
		ID:       1,
		Username: "testuser",
	}

	key := []byte("01234567890123456789012345678901")
	phone := "13800138000"

	user.EncryptPhone(phone, key)

	masked := user.GetMaskedPhone(key)

	// 脱敏后的手机号应该是 11 位
	if len(masked) != 11 {
		t.Errorf("Masked phone length: got %d, want 11", len(masked))
	}

	// 格式应该是 138****8000
	expected := "138****8000"
	if masked != expected {
		t.Errorf("Masked phone: got %s, want %s", masked, expected)
	}
}

// TestUserGetMaskedPhoneInvalid 测试无效数据脱敏
func TestUserGetMaskedPhoneInvalid(t *testing.T) {
	user := &User{
		ID:             1,
		Username:       "testuser",
		PhoneEncrypted: []byte("short"), // 太短的数据
	}

	key := []byte("01234567890123456789012345678901")
	masked := user.GetMaskedPhone(key)

	// 无效数据应该返回 "***"
	if masked != "***" {
		t.Errorf("Invalid phone masked: got %s, want ***", masked)
	}
}

// TestUserTableName 测试表名
func TestUserTableName(t *testing.T) {
	user := &User{}
	name := user.TableName()
	if name != "users" {
		t.Errorf("Table name: got %s, want users", name)
	}
}

// TestTokenBlacklistTableName 测试 Token 黑名单表名
func TestTokenBlacklistTableName(t *testing.T) {
	tb := &TokenBlacklist{}
	name := tb.TableName()
	if name != "token_blacklist" {
		t.Errorf("Table name: got %s, want token_blacklist", name)
	}
}

// TestLoginLogTableName 测试登录日志表名
func TestLoginLogTableName(t *testing.T) {
	ll := &LoginLog{}
	name := ll.TableName()
	if name != "login_logs" {
		t.Errorf("Table name: got %s, want login_logs", name)
	}
}

// TestKeyStoreRecordTableName 测试密钥记录表名
func TestKeyStoreRecordTableName(t *testing.T) {
	ksr := &KeyStoreRecord{}
	name := ksr.TableName()
	if name != "key_store_record" {
		t.Errorf("Table name: got %s, want key_store_record", name)
	}
}

// TestLoginRequestValidation 测试登录请求验证
func TestLoginRequestValidation(t *testing.T) {
	req := &LoginRequest{
		KeyID:     "test-key-id",
		Encrypted: "dGVzdC1lbmNyeXB0ZWQtZGF0YQ==",
		Signature: "test-signature",
		Timestamp: time.Now().Unix(),
		Nonce:     "test-nonce",
	}

	// 验证字段不为空
	if req.KeyID == "" {
		t.Error("KeyID should not be empty")
	}

	if req.Encrypted == "" {
		t.Error("Encrypted should not be empty")
	}

	if req.Signature == "" {
		t.Error("Signature should not be empty")
	}

	if req.Timestamp == 0 {
		t.Error("Timestamp should not be zero")
	}

	if req.Nonce == "" {
		t.Error("Nonce should not be empty")
	}
}

// TestLoginResponse 测试登录响应
func TestLoginResponse(t *testing.T) {
	resp := &LoginResponse{
		AccessToken:  "eyJ.access.token",
		RefreshToken: "eyJ.refresh.token",
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}

	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}

	if resp.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}

	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType: got %s, want Bearer", resp.TokenType)
	}

	if resp.ExpiresIn != 900 {
		t.Errorf("ExpiresIn: got %d, want 900", resp.ExpiresIn)
	}
}

// TestUserInfo 测试用户信息
func TestUserInfo(t *testing.T) {
	now := time.Now()
	info := &UserInfo{
		ID:        1,
		Username:  "testuser",
		Nickname:  "Test User",
		Avatar:    "https://example.com/avatar.jpg",
		Phone:     "138****8000",
		Role:      "user",
		CreatedAt: now,
	}

	if info.ID != 1 {
		t.Errorf("ID: got %d, want 1", info.ID)
	}

	if info.Username != "testuser" {
		t.Errorf("Username: got %s, want testuser", info.Username)
	}

	if info.Role != "user" {
		t.Errorf("Role: got %s, want user", info.Role)
	}
}

// TestRefreshTokenRequest 测试刷新 Token 请求
func TestRefreshTokenRequest(t *testing.T) {
	req := &RefreshTokenRequest{
		RefreshToken: "eyJ.refresh.token",
	}

	if req.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}
}

// TestLogoutRequest 测试登出请求
func TestLogoutRequest(t *testing.T) {
	req := &LogoutRequest{
		AccessToken: "eyJ.access.token",
	}

	if req.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
}

// TestRSAPublicKeyResponse 测试 RSA 公钥响应
func TestRSAPublicKeyResponse(t *testing.T) {
	resp := &RSAPublicKeyResponse{
		KeyID:     "test-key-id",
		PublicKey: "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0=",
	}

	if resp.KeyID == "" {
		t.Error("KeyID should not be empty")
	}

	if resp.PublicKey == "" {
		t.Error("PublicKey should not be empty")
	}
}

// TestWechatAuthURLResponse 测试微信授权 URL 响应
func TestWechatAuthURLResponse(t *testing.T) {
	resp := &WechatAuthURLResponse{
		AuthURL:   "https://open.weixin.qq.com/connect/qrconnect?appid=xxx",
		State:     "random-state-string",
		ExpiresIn: 600,
	}

	if resp.AuthURL == "" {
		t.Error("AuthURL should not be empty")
	}

	if resp.State == "" {
		t.Error("State should not be empty")
	}

	if resp.ExpiresIn <= 0 {
		t.Error("ExpiresIn should be positive")
	}
}

package service

import (
	"auth-service/internal/crypto"
	"auth-service/internal/model"
	"testing"
)

// TestHashPassword 测试密码哈希
func TestHashPassword(t *testing.T) {
	password := "TestPassword123!"

	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if len(hash) < 60 {
		t.Errorf("Hash length too short: got %d, want >= 60", len(hash))
	}
}

// TestCheckPassword 测试密码验证
func TestCheckPassword(t *testing.T) {
	password := "TestPassword123!"
	hash, _ := crypto.HashPassword(password)

	if !checkPassword(password, hash) {
		t.Error("Valid password should pass verification")
	}

	if checkPassword("WrongPassword", hash) {
		t.Error("Wrong password should fail verification")
	}
}

// TestAuthServiceStructure 测试 AuthService 结构
func TestAuthServiceStructure(t *testing.T) {
	// 验证结构定义
	service := &AuthService{}
	if service == nil {
		t.Error("AuthService should be creatable")
	}
}

// TestLoginRequest 测试登录请求结构
func TestLoginRequest(t *testing.T) {
	req := &model.LoginRequest{
		KeyID:     "test-key",
		Encrypted: "encrypted-data",
		Signature: "signature",
		Timestamp: 1234567890,
		Nonce:     "nonce",
	}

	if req.KeyID == "" {
		t.Error("KeyID should not be empty")
	}

	if req.Encrypted == "" {
		t.Error("Encrypted should not be empty")
	}
}

// TestWechatLoginRequest 测试微信登录请求
func TestWechatLoginRequest(t *testing.T) {
	req := &model.WechatLoginRequest{
		Code: "test-auth-code",
	}

	if req.Code == "" {
		t.Error("Code should not be empty")
	}
}

package model

import (
	"crypto/rand"
	"testing"
)

// ===== User.EncryptPhone / DecryptPhone 测试 =====

func TestUserModel(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	phones := []string{
		"13800138000",
		"+8613912345678",
		"010-12345678",
	}

	for _, phone := range phones {
		user := &User{}
		if err := user.EncryptPhone(phone, key); err != nil {
			t.Fatalf("EncryptPhone(%q) 失败: %v", phone, err)
		}
		if len(user.PhoneEncrypted) == 0 {
			t.Fatal("加密后数据不应为空")
		}

		if err := user.DecryptPhone(key); err != nil {
			t.Fatalf("DecryptPhone(%q) 失败: %v", phone, err)
		}
		if user.Phone != phone {
			t.Errorf("解密结果不匹配: got %q, want %q", user.Phone, phone)
		}
	}
}

func TestDecryptPhoneWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	user := &User{}
	user.EncryptPhone("13800138000", key1)

	if err := user.DecryptPhone(key2); err == nil {
		t.Error("用错误密钥解密应返回错误")
	}
}

func TestDecryptPhoneEmptyData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	user := &User{PhoneEncrypted: nil}
	if err := user.DecryptPhone(key); err == nil {
		t.Error("空加密数据解密应返回错误")
	}
}

func TestDecryptPhoneTooShort(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	user := &User{PhoneEncrypted: []byte{0x01, 0x02}}
	if err := user.DecryptPhone(key); err == nil {
		t.Error("过短的加密数据（< 12 字节）应返回错误")
	}
}

// ===== GetMaskedPhone 测试 =====

func TestTokenBlacklistModel(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	user := &User{}
	user.EncryptPhone("13800138000", key)

	masked := user.GetMaskedPhone(key)
	if masked == "***" {
		t.Error("有效手机号脱敏结果不应为 ***")
	}
	if masked != "138****8000" {
		t.Errorf("脱敏格式不正确: got %q, want 138****8000", masked)
	}
}

func TestGetMaskedPhoneNoData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	user := &User{PhoneEncrypted: nil}
	masked := user.GetMaskedPhone(key)
	if masked != "***" {
		t.Errorf("无手机号时脱敏结果应为 ***，实际 %q", masked)
	}
}

func TestGetMaskedPhoneShortNumber(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	user := &User{}
	user.EncryptPhone("123", key) // 少于 7 位

	masked := user.GetMaskedPhone(key)
	if masked != "***" {
		t.Errorf("短号码脱敏结果应为 ***，实际 %q", masked)
	}
}

func TestGetMaskedPhoneWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	user := &User{}
	user.EncryptPhone("13800138000", key1)

	masked := user.GetMaskedPhone(key2)
	if masked != "***" {
		t.Errorf("错误密钥脱敏应返回 ***，实际 %q", masked)
	}
}

// ===== LoginLogModel 测试（结构字段验证） =====

func TestLoginLogModel(t *testing.T) {
	log := &LoginLog{
		UserID:    1,
		LoginType: "PASSWORD",
		IPAddress: "127.0.0.1",
		Status:    1,
	}
	if log.LoginType != "PASSWORD" {
		t.Errorf("LoginType 不匹配: %q", log.LoginType)
	}
	if log.Status != 1 {
		t.Errorf("Status 不匹配: %d", log.Status)
	}
	if LoginLog.TableName(*log) != "login_logs" {
		t.Errorf("表名不正确: %q", LoginLog.TableName(*log))
	}
}

// ===== User 可空手机号测试 =====

func TestUserPhoneNullable(t *testing.T) {
	user := &User{
		Username:     "testuser",
		PasswordHash: "hash",
		Status:       1,
		Role:         "user",
	}
	// PhoneEncrypted 为 nil 不应引发 panic
	if user.PhoneEncrypted != nil {
		t.Error("未设置手机号时 PhoneEncrypted 应为 nil")
	}
}

// ===== TableName 测试 =====

func TestTableNames(t *testing.T) {
	tests := []struct {
		name  string
		table string
	}{
		{"users", User{}.TableName()},
		{"token_blacklist", TokenBlacklist{}.TableName()},
		{"login_logs", LoginLog{}.TableName()},
		{"key_store_record", KeyStoreRecord{}.TableName()},
	}
	for _, tt := range tests {
		if tt.table != tt.name {
			t.Errorf("表名不正确: got %q, want %q", tt.table, tt.name)
		}
	}
}

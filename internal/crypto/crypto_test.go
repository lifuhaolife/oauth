package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// ===== RSA 测试 =====

func TestRSAEncryptDecrypt(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}

	cases := [][]byte{
		[]byte(`{"username":"admin","password":"Admin@123"}`),
		[]byte("hello world"),
		[]byte("中文内容"),
	}

	for _, plaintext := range cases {
		ciphertext, err := RSAEncrypt(&privKey.PublicKey, plaintext)
		if err != nil {
			t.Fatalf("RSA 加密失败: %v", err)
		}
		if bytes.Equal(ciphertext, plaintext) {
			t.Error("密文不应与明文相同")
		}

		decrypted, err := RSADecrypt(privKey, ciphertext)
		if err != nil {
			t.Fatalf("RSA 解密失败: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("解密结果不匹配: got %q, want %q", decrypted, plaintext)
		}
	}
}

func TestRSADecryptWrongKey(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	ciphertext, _ := RSAEncrypt(&key1.PublicKey, []byte("secret"))
	_, err := RSADecrypt(key2, ciphertext)
	if err == nil {
		t.Error("用错误私钥解密应该返回错误")
	}
}

func TestPublicKeyToPEMAndParse(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	pemBytes, err := PublicKeyToPEM(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("公钥转 PEM 失败: %v", err)
	}
	if len(pemBytes) == 0 {
		t.Fatal("PEM 数据不应为空")
	}

	parsedKey, err := ParseRSAPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("解析公钥 PEM 失败: %v", err)
	}
	if parsedKey.N.Cmp(privKey.PublicKey.N) != 0 || parsedKey.E != privKey.PublicKey.E {
		t.Error("解析后公钥与原公钥不匹配")
	}
}

func TestParseRSAPublicKeyInvalidPEM(t *testing.T) {
	_, err := ParseRSAPublicKey([]byte("not a pem"))
	if err == nil {
		t.Error("非法 PEM 数据应返回错误")
	}
}

func TestRSAEncryptDecryptRoundTrip(t *testing.T) {
	// 验证 PublicKeyToPEM → ParseRSAPublicKey → RSAEncrypt → RSADecrypt 完整链路
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	payload := []byte(`{"username":"test","password":"Test@1234"}`)

	pemBytes, _ := PublicKeyToPEM(&privKey.PublicKey)
	parsedPub, _ := ParseRSAPublicKey(pemBytes)

	ciphertext, err := RSAEncrypt(parsedPub, payload)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	decrypted, err := RSADecrypt(privKey, ciphertext)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("完整链路解密结果不匹配")
	}
}

// ===== AES-GCM 测试 =====

func TestAESEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	cases := [][]byte{
		[]byte("13800138000"),
		[]byte("手机号：+8613912345678"),
		[]byte(""),
	}

	for _, plaintext := range cases {
		ciphertext, iv, err := AESEncrypt(key, plaintext)
		if err != nil {
			t.Fatalf("AES 加密失败: %v", err)
		}
		if len(iv) != 12 {
			t.Errorf("IV 长度应为 12，实际 %d", len(iv))
		}

		decrypted, err := AESDecrypt(key, ciphertext, iv)
		if err != nil {
			t.Fatalf("AES 解密失败: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("AES 解密结果不匹配: got %q, want %q", decrypted, plaintext)
		}
	}
}

func TestAESEncryptProducesRandomIV(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("same plaintext")

	_, iv1, _ := AESEncrypt(key, plaintext)
	_, iv2, _ := AESEncrypt(key, plaintext)

	// 随机 IV，两次加密 IV 不应相同
	if bytes.Equal(iv1, iv2) {
		t.Error("两次加密的 IV 不应相同（随机性验证）")
	}
}

func TestAESDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	ciphertext, iv, _ := AESEncrypt(key1, []byte("secret"))
	_, err := AESDecrypt(key2, ciphertext, iv)
	if err == nil {
		t.Error("用错误密钥解密应该失败")
	}
}

func TestAESDecryptTamperedData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	ciphertext, iv, _ := AESEncrypt(key, []byte("original"))
	ciphertext[0] ^= 0xff // 篡改密文

	_, err := AESDecrypt(key, ciphertext, iv)
	if err == nil {
		t.Error("篡改密文后解密应该失败（GCM 认证）")
	}
}

func TestAESInvalidKeyLength(t *testing.T) {
	badKey := make([]byte, 10) // AES 要求 16/24/32 字节
	_, _, err := AESEncrypt(badKey, []byte("data"))
	if err == nil {
		t.Error("非法密钥长度应返回错误")
	}
}

// ===== BCrypt 测试 =====

func TestHashPassword(t *testing.T) {
	password := "Admin@123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("哈希密码失败: %v", err)
	}
	if hash == "" {
		t.Fatal("哈希结果不应为空")
	}
	if hash == password {
		t.Error("哈希结果不应与原密码相同")
	}
}

func TestHashPasswordUnique(t *testing.T) {
	password := "SamePassword1"

	hash1, _ := HashPassword(password)
	hash2, _ := HashPassword(password)

	// BCrypt 每次加盐不同，哈希结果不同
	if hash1 == hash2 {
		t.Error("相同密码两次哈希结果不应相同（盐值随机性）")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "Admin@123"
	hash, _ := HashPassword(password)

	if !CheckPasswordHash(password, hash) {
		t.Error("正确密码验证应通过")
	}

	if CheckPasswordHash("wrongpassword", hash) {
		t.Error("错误密码验证应失败")
	}

	if CheckPasswordHash("", hash) {
		t.Error("空密码验证应失败")
	}
}

func TestVerifyPasswordWithMultipleHashes(t *testing.T) {
	passwords := []string{"Test@123", "P@ssw0rd", "Abcdef1G"}
	for _, pwd := range passwords {
		hash, err := HashPassword(pwd)
		if err != nil {
			t.Fatalf("哈希 %q 失败: %v", pwd, err)
		}
		if !CheckPasswordHash(pwd, hash) {
			t.Errorf("密码 %q 验证失败", pwd)
		}
	}
}

// ===== Base64 测试 =====

func TestBase64EncodeDecode(t *testing.T) {
	cases := [][]byte{
		[]byte("hello world"),
		[]byte("中文内容"),
		{0x00, 0x01, 0xff, 0xfe}, // 二进制数据
		{},
	}

	for _, data := range cases {
		encoded := Base64Encode(data)
		decoded, err := Base64Decode(encoded)
		if err != nil {
			t.Fatalf("Base64 解码失败: %v", err)
		}
		if !bytes.Equal(decoded, data) {
			t.Errorf("Base64 往返结果不匹配")
		}
	}
}

func TestBase64DecodeInvalid(t *testing.T) {
	_, err := Base64Decode("not!valid!base64!!!")
	if err == nil {
		t.Error("非法 Base64 字符串应返回错误")
	}
}

// ===== HMAC 测试 =====

func TestHMACSignVerify(t *testing.T) {
	key := []byte("test-secret-key-32bytes-long!!!!")
	data := []byte(`{"key_id":"abc","timestamp":1234567890}`)

	sig := HMACSign(key, data)
	if len(sig) == 0 {
		t.Fatal("签名不应为空")
	}

	if !HMACVerify(key, data, sig) {
		t.Error("HMAC 验证应通过")
	}
}

func TestHMACTamperedData(t *testing.T) {
	key := []byte("test-key")
	data := []byte("original data")
	sig := HMACSign(key, data)

	if HMACVerify(key, []byte("tampered data"), sig) {
		t.Error("篡改数据 HMAC 验证应失败")
	}
}

func TestHMACWrongKey(t *testing.T) {
	key1 := []byte("key1")
	key2 := []byte("key2")
	data := []byte("payload")

	sig := HMACSign(key1, data)

	if HMACVerify(key2, data, sig) {
		t.Error("错误密钥 HMAC 验证应失败")
	}
}

func TestHMACDeterministic(t *testing.T) {
	key := []byte("fixed-key")
	data := []byte("fixed-data")

	sig1 := HMACSign(key, data)
	sig2 := HMACSign(key, data)

	if !bytes.Equal(sig1, sig2) {
		t.Error("相同输入 HMAC 应确定性输出")
	}
}

package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// TestHashPassword 测试 BCrypt 密码哈希
func TestHashPassword(t *testing.T) {
	password := "TestPassword123!"

	// 测试哈希生成
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// 哈希长度应该大于 60 (BCrypt 格式)
	if len(hash) < 60 {
		t.Errorf("Hash length too short: got %d, want >= 60", len(hash))
	}

	// 两次哈希应该不同 (因为 salt 不同)
	hash2, _ := HashPassword(password)
	if hash == hash2 {
		t.Error("Same password should produce different hashes")
	}
}

// TestCheckPasswordHash 测试密码验证
func TestCheckPasswordHash(t *testing.T) {
	password := "TestPassword123!"
	wrongPassword := "WrongPassword456!"

	hash, _ := HashPassword(password)

	// 正确密码应该验证通过
	if !CheckPasswordHash(password, hash) {
		t.Error("Valid password failed verification")
	}

	// 错误密码应该验证失败
	if CheckPasswordHash(wrongPassword, hash) {
		t.Error("Invalid password passed verification")
	}

	// 空密码测试
	if CheckPasswordHash("", hash) {
		t.Error("Empty password should not pass verification")
	}
}

// TestRSAEncryption 测试 RSA 加密/解密
func TestRSAEncryption(t *testing.T) {
	// 生成测试密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// 测试明文
	plaintext := []byte("Hello, World! 测试中文")

	// 加密
	ciphertext, err := RSAEncrypt(publicKey, plaintext)
	if err != nil {
		t.Fatalf("RSAEncrypt failed: %v", err)
	}

	// 密文应该与明文不同
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// 解密
	decrypted, err := RSADecrypt(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("RSADecrypt failed: %v", err)
	}

	// 解密结果应该与原文相同
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text doesn't match: got %s, want %s", decrypted, plaintext)
	}
}

// TestAESGCMEncryption 测试 AES-GCM 加密/解密
func TestAESGCMEncryption(t *testing.T) {
	// 32 字节 AES 密钥
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("Hello, World! 测试中文")

	// 加密
	ciphertext, iv, err := AESEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("AESEncrypt failed: %v", err)
	}

	// 密文应该与明文不同
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// 解密
	decrypted, err := AESDecrypt(key, ciphertext, iv)
	if err != nil {
		t.Fatalf("AESDecrypt failed: %v", err)
	}

	// 解密结果应该与原文相同
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text doesn't match: got %s, want %s", decrypted, plaintext)
	}
}

// TestAESGCMWrongKey 测试错误密钥解密
func TestAESGCMWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	plaintext := []byte("Secret data")
	ciphertext, iv, _ := AESEncrypt(key1, plaintext)

	// 用错误密钥解密应该失败
	_, err := AESDecrypt(key2, ciphertext, iv)
	if err == nil {
		t.Error("Decryption with wrong key should fail")
	}
}

// TestHMACSign 测试 HMAC 签名
func TestHMACSign(t *testing.T) {
	key := []byte("secret-key")
	data := []byte("message to sign")

	signature := HMACSign(key, data)

	// 签名长度应该是 32 (SHA256)
	if len(signature) != 32 {
		t.Errorf("HMAC signature length: got %d, want 32", len(signature))
	}

	// 相同数据应该产生相同签名
	signature2 := HMACSign(key, data)
	if !bytes.Equal(signature, signature2) {
		t.Error("Same data should produce same HMAC signature")
	}

	// 不同数据应该产生不同签名
	signature3 := HMACSign(key, []byte("different message"))
	if bytes.Equal(signature, signature3) {
		t.Error("Different data should produce different HMAC signature")
	}
}

// TestHMACVerify 测试 HMAC 验证
func TestHMACVerify(t *testing.T) {
	key := []byte("secret-key")
	data := []byte("message to sign")
	signature := HMACSign(key, data)

	// 正确签名应该验证通过
	if !HMACVerify(key, data, signature) {
		t.Error("Valid HMAC signature failed verification")
	}

	// 错误签名应该验证失败
	wrongSignature := make([]byte, len(signature))
	copy(wrongSignature, signature)
	wrongSignature[0] ^= 0xFF

	if HMACVerify(key, data, wrongSignature) {
		t.Error("Invalid HMAC signature passed verification")
	}

	// 错误数据应该验证失败
	if HMACVerify(key, []byte("tampered message"), signature) {
		t.Error("Tampered data should fail HMAC verification")
	}
}

// TestBase64Encoding 测试 Base64 编解码
func TestBase64Encoding(t *testing.T) {
	original := []byte("Hello, World! 测试中文")

	encoded := Base64Encode(original)
	decoded, err := Base64Decode(encoded)
	if err != nil {
		t.Fatalf("Base64Decode failed: %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("Decoded data doesn't match: got %s, want %s", decoded, original)
	}
}

// TestPublicKeyToPEM 测试公钥 PEM 格式化
func TestPublicKeyToPEM(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	pemBytes, err := PublicKeyToPEM(publicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM failed: %v", err)
	}

	// PEM 应该以 BEGIN PUBLIC KEY 开头
	if len(pemBytes) < 50 || !bytes.Contains(pemBytes, []byte("BEGIN PUBLIC KEY")) {
		t.Error("Invalid PEM format")
	}
}

// TestParseRSAPublicKey 测试解析 RSA 公钥
func TestParseRSAPublicKey(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	pemBytes, _ := PublicKeyToPEM(publicKey)

	parsedKey, err := ParseRSAPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("ParseRSAPublicKey failed: %v", err)
	}

	// 解析的公钥应该与原公钥相同
	if parsedKey.N.Cmp(publicKey.N) != 0 {
		t.Error("Parsed public key doesn't match original")
	}
}

// TestParseRSAPrivateKey 测试解析 RSA 私钥
func TestParseRSAPrivateKey(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	pemBytes, _ := PublicKeyToPEM(&privateKey.PublicKey)

	// 尝试用公钥 PEM 解析私钥应该失败
	_, err := ParseRSAPrivateKey(pemBytes)
	if err == nil {
		t.Error("Parsing public key as private key should fail")
	}
}

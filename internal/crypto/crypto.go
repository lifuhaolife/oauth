package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// ============ RSA 加密/解密 ============

// RSAPublicKeyToPEM 将 RSA 公钥转换为 PEM 格式
func PublicKeyToPEM(pubKey *rsa.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return pemBytes, nil
}

// ParseRSAPublicKey 从 PEM 解析 RSA 公钥
func ParseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("无效的 PEM 数据")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("不是 RSA 公钥")
	}

	return rsaPubKey, nil
}

// ParseRSAPrivateKey 从 PEM 解析 RSA 私钥
func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("无效的 PEM 数据")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("不是 RSA 私钥")
	}

	return rsaPrivKey, nil
}

// RSAEncrypt RSA 加密 (PKCS#1 v1.5 for web compatibility)
func RSAEncrypt(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("RSA 加密失败：%v", err)
	}
	return ciphertext, nil
}

// RSADecrypt RSA 解密
func RSADecrypt(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("RSA 解密失败：%v", err)
	}
	return plaintext, nil
}

// ============ AES 加密/解密 (GCM 模式) ============

// AESEncrypt AES-GCM 加密
func AESEncrypt(key, plaintext []byte) (ciphertext []byte, iv []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// 生成随机 nonce (12 字节)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	encrypted := gcm.Seal(nil, nonce, plaintext, nil)
	return encrypted, nonce, nil
}

// AESDecrypt AES-GCM 解密
func AESDecrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES 解密失败：%v", err)
	}

	return plaintext, nil
}

// ============ BCrypt 密码哈希 ============

// HashPassword BCrypt 哈希密码
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash 验证密码
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ============ Base64 工具 ============

// Base64Encode Base64 编码
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode Base64 解码
func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// ============  HMAC 签名 ============

// HMACSign HMAC-SHA256 签名
// 用于请求签名防篡改
func HMACSign(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMACVerify 验证 HMAC 签名
func HMACVerify(key, data, signature []byte) bool {
	expected := HMACSign(key, data)
	return hmac.Equal(expected, signature)
}

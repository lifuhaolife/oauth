package keystore

import (
	"auth-service/internal/config"
	"auth-service/internal/crypto"
	"auth-service/internal/model"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

// RSAPubKeyEntry RSA 公钥条目 (存储在缓存中)
type RSAPubKeyEntry struct {
	KeyID       string    // 密钥唯一标识
	PrivateKey  *rsa.PrivateKey // 私钥 (内存中)
	PublicKey   *rsa.PublicKey  // 公钥
	CreatedAt   time.Time // 创建时间
	IsUsed      bool      // 是否已使用
	ExpiredAt   time.Time // 过期时间
}

// KeyStore 密钥管理
type KeyStore struct {
	mu            sync.RWMutex
	rsaKeyPool    map[string]*RSAPubKeyEntry // RSA 密钥池 (key_id -> entry)
	aesDataKey    []byte                     // AES 数据加密密钥 (内存中)
	jwtPrivateKey *rsa.PrivateKey            // JWT 私钥
	jwtPublicKey  *rsa.PublicKey             // JWT 公钥
	cfg           *config.Config
}

var (
	globalKeyStore *KeyStore
	once           sync.Once
)

// InitKeyStore 初始化密钥管理
func InitKeyStore(cfg *config.Config) error {
	var initErr error
	once.Do(func() {
		ks := &KeyStore{
			rsaKeyPool:  make(map[string]*RSAPubKeyEntry),
			aesDataKey:  cfg.MasterKey, // 使用 MASTER_KEY 作为 AES 密钥
			cfg:         cfg,
		}

		// 加载 JWT 密钥对
		if err := ks.loadJWTKeyPair(); err != nil {
			initErr = fmt.Errorf("加载 JWT 密钥对失败：%v", err)
			return
		}

		// 初始化 RSA 密钥池 (预生成 10 对)
		if err := ks.initRSAPool(10); err != nil {
			initErr = fmt.Errorf("初始化 RSA 密钥池失败：%v", err)
			return
		}

		// 启动密钥池维护协程
		go ks.maintainKeyPool()

		globalKeyStore = ks
	})
	return initErr
}

// GetKeyStore 获取全局密钥管理实例
func GetKeyStore() *KeyStore {
	return globalKeyStore
}

// loadJWTKeyPair 加载 JWT 密钥对
func (ks *KeyStore) loadJWTKeyPair() error {
	// 读取私钥
	privateKeyPEM, err := os.ReadFile(ks.cfg.JWTPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("读取私钥文件失败：%v", err)
	}

	privateKey, err := crypto.ParseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("解析私钥失败：%v", err)
	}
	ks.jwtPrivateKey = privateKey

	// 读取公钥
	publicKeyPEM, err := os.ReadFile(ks.cfg.JWTPublicKeyPath)
	if err != nil {
		return fmt.Errorf("读取公钥文件失败：%v", err)
	}

	publicKey, err := crypto.ParseRSAPublicKey(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("解析公钥失败：%v", err)
	}
	ks.jwtPublicKey = publicKey

	return nil
}

// initRSAPool 初始化 RSA 密钥池
func (ks *KeyStore) initRSAPool(size int) error {
	for i := 0; i < size; i++ {
		if err := ks.generateRSAKey(); err != nil {
			return err
		}
	}
	return nil
}

// generateRSAKey 生成单个 RSA 密钥对
func (ks *KeyStore) generateRSAKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成 RSA 密钥失败：%v", err)
	}

	// 生成 key_id (公钥指纹)
	pubKeyBytes, err := crypto.PublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(pubKeyBytes)
	keyID := hex.EncodeToString(fingerprint[:])[:32]

	entry := &RSAPubKeyEntry{
		KeyID:      keyID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
		IsUsed:     false,
		ExpiredAt:  time.Now().Add(10 * time.Minute), // 10 分钟过期
	}

	ks.mu.Lock()
	ks.rsaKeyPool[keyID] = entry
	ks.mu.Unlock()

	return nil
}

// GetRSAPublicKey 获取 RSA 公钥 (返回未使用的密钥)
func (ks *KeyStore) GetRSAPublicKey() (string, string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// 查找未使用且未过期的密钥
	for keyID, entry := range ks.rsaKeyPool {
		if !entry.IsUsed && time.Now().Before(entry.ExpiredAt) {
			// 返回公钥 PEM
			pubKeyPEM, err := crypto.PublicKeyToPEM(entry.PublicKey)
			if err != nil {
				return "", "", err
			}
			return keyID, base64.StdEncoding.EncodeToString(pubKeyPEM), nil
		}
	}

	// 没有可用密钥，生成新的
	if err := ks.generateRSAKey(); err != nil {
		return "", "", err
	}

	// 返回新生成的密钥
	for keyID, entry := range ks.rsaKeyPool {
		if !entry.IsUsed && time.Now().Before(entry.ExpiredAt) {
			pubKeyPEM, err := crypto.PublicKeyToPEM(entry.PublicKey)
			if err != nil {
				return "", "", err
			}
			return keyID, base64.StdEncoding.EncodeToString(pubKeyPEM), nil
		}
	}

	return "", "", errors.New("无法获取 RSA 公钥")
}

// GetRSAPrivateKey 根据 key_id 获取 RSA 私钥
func (ks *KeyStore) GetRSAPrivateKey(keyID string) (*rsa.PrivateKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	entry, exists := ks.rsaKeyPool[keyID]
	if !exists {
		return nil, errors.New("密钥不存在")
	}

	if entry.IsUsed {
		return nil, errors.New("密钥已使用，请重新获取公钥")
	}

	if time.Now().After(entry.ExpiredAt) {
		return nil, errors.New("密钥已过期，请重新获取公钥")
	}

	// 标记为已使用
	entry.IsUsed = true

	return entry.PrivateKey, nil
}

// InvalidateKey 使密钥失效 (使用后销毁)
func (ks *KeyStore) InvalidateKey(keyID string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	delete(ks.rsaKeyPool, keyID)
}

// maintainKeyPool 维护密钥池 (清理过期密钥，补充新密钥)
func (ks *KeyStore) maintainKeyPool() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ks.mu.Lock()

		now := time.Now()
		activeCount := 0

		// 清理过期和已使用的密钥
		for keyID, entry := range ks.rsaKeyPool {
			if entry.IsUsed || now.After(entry.ExpiredAt) {
				delete(ks.rsaKeyPool, keyID)
			} else {
				activeCount++
			}
		}

		// 补充密钥池 (保持至少 10 个可用密钥)
		for activeCount < 10 {
			if err := ks.generateRSAKey(); err != nil {
				fmt.Printf("补充 RSA 密钥失败：%v\n", err)
			} else {
				activeCount++
			}
		}

		ks.mu.Unlock()
	}
}

// GetAESKey 获取 AES 加密密钥
func (ks *KeyStore) GetAESKey() []byte {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.aesDataKey
}

// GetJWTPrivateKey 获取 JWT 私钥
func (ks *KeyStore) GetJWTPrivateKey() *rsa.PrivateKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.jwtPrivateKey
}

// GetJWTPublicKey 获取 JWT 公钥
func (ks *KeyStore) GetJWTPublicKey() *rsa.PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.jwtPublicKey
}

// GetKeyStats 获取密钥统计信息
func (ks *KeyStore) GetKeyStats() map[string]interface{} {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	activeCount := 0
	usedCount := 0
	for _, entry := range ks.rsaKeyPool {
		if entry.IsUsed {
			usedCount++
		} else {
			activeCount++
		}
	}

	return map[string]interface{}{
		"rsa_pool_active":  activeCount,
		"rsa_pool_used":    usedCount,
		"rsa_pool_total":   activeCount + usedCount,
		"aes_key_loaded":   len(ks.aesDataKey) > 0,
		"jwt_key_loaded":   ks.jwtPrivateKey != nil,
	}
}

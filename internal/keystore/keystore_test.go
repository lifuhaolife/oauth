package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

// TestRSAPubKeyEntry 测试 RSA 密钥条目结构
func TestRSAPubKeyEntry(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skipf("Skipping test: %v", err)
	}

	entry := &RSAPubKeyEntry{
		KeyID:      "test-key-123",
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
		IsUsed:     false,
		ExpiredAt:  time.Now().Add(10 * time.Minute),
	}

	if entry.KeyID != "test-key-123" {
		t.Errorf("KeyID: got %s, want test-key-123", entry.KeyID)
	}

	if entry.IsUsed != false {
		t.Error("New entry should not be marked as used")
	}
}

// TestKeyStoreInit 测试 KeyStore 初始化
func TestKeyStoreInit(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
	}

	if ks.rsaKeyPool == nil {
		t.Error("rsaKeyPool should be initialized")
	}

	if ks.GetRSAKeyPoolSize() != 0 {
		t.Error("Initial pool size should be 0")
	}
}

// TestKeyStoreGenerateRSAKey 测试生成 RSA 密钥
func TestKeyStoreGenerateRSAKey(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
	}

	err := ks.generateRSAKey()
	if err != nil {
		t.Fatalf("generateRSAKey failed: %v", err)
	}

	if len(ks.rsaKeyPool) != 1 {
		t.Errorf("Pool size: got %d, want 1", len(ks.rsaKeyPool))
	}

	// 验证生成的密钥条目
	for keyID, entry := range ks.rsaKeyPool {
		if keyID != entry.KeyID {
			t.Error("KeyID mismatch in pool")
		}

		if entry.PrivateKey == nil {
			t.Error("PrivateKey should not be nil")
		}

		if entry.PublicKey == nil {
			t.Error("PublicKey should not be nil")
		}

		if entry.IsUsed != false {
			t.Error("New key should not be marked as used")
		}

		// 验证过期时间是 10 分钟
		expectedExpire := entry.CreatedAt.Add(10 * time.Minute)
		if entry.ExpiredAt.After(expectedExpire) || entry.ExpiredAt.Before(entry.CreatedAt.Add(9*time.Minute)) {
			t.Errorf("ExpiredAt: got %v, want around %v", entry.ExpiredAt, expectedExpire)
		}
	}
}

// TestKeyStoreInitRSAPool 测试初始化密钥池
func TestKeyStoreInitRSAPool(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
	}

	poolSize := 5
	err := ks.initRSAPool(poolSize)
	if err != nil {
		t.Fatalf("initRSAPool failed: %v", err)
	}

	if len(ks.rsaKeyPool) != poolSize {
		t.Errorf("Pool size: got %d, want %d", len(ks.rsaKeyPool), poolSize)
	}
}

// TestKeyStoreGetRSAPublicKey 测试获取 RSA 公钥
func TestKeyStoreGetRSAPublicKey(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
	}

	// 先初始化一个密钥
	err := ks.generateRSAKey()
	if err != nil {
		t.Fatalf("generateRSAKey failed: %v", err)
	}

	// 获取公钥
	keyID, publicKey, err := ks.GetRSAPublicKey()
	if err != nil {
		t.Fatalf("GetRSAPublicKey failed: %v", err)
	}

	if keyID == "" {
		t.Error("KeyID should not be empty")
	}

	if publicKey == "" {
		t.Error("PublicKey should not be empty")
	}

	// 验证密钥被标记为已使用
	entry, exists := ks.rsaKeyPool[keyID]
	if !exists {
		t.Fatal("Key should exist in pool")
	}

	if !entry.IsUsed {
		t.Error("Key should be marked as used after getting")
	}
}

// TestKeyStoreGetRSAPrivateKey 测试获取 RSA 私钥
func TestKeyStoreGetRSAPrivateKey(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
	}

	// 生成密钥
	err := ks.generateRSAKey()
	if err != nil {
		t.Fatalf("generateRSAKey failed: %v", err)
	}

	// 获取一个未使用的密钥 ID
	var keyID string
	for kid, entry := range ks.rsaKeyPool {
		if !entry.IsUsed {
			keyID = kid
			break
		}
	}

	if keyID == "" {
		t.Fatal("Should have an unused key")
	}

	// 获取私钥
	privateKey, err := ks.GetRSAPrivateKey(keyID)
	if err != nil {
		t.Fatalf("GetRSAPrivateKey failed: %v", err)
	}

	if privateKey == nil {
		t.Error("PrivateKey should not be nil")
	}
}

// TestKeyStoreGetRSAPrivateKeyAlreadyUsed 测试获取已使用的密钥
func TestKeyStoreGetRSAPrivateKeyAlreadyUsed(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
	}

	err := ks.generateRSAKey()
	if err != nil {
		t.Fatalf("generateRSAKey failed: %v", err)
	}

	// 获取密钥 ID 并标记为已使用
	var keyID string
	for kid, entry := range ks.rsaKeyPool {
		keyID = kid
		entry.IsUsed = true
		break
	}

	// 尝试获取已使用的密钥应该失败
	_, err = ks.GetRSAPrivateKey(keyID)
	if err == nil {
		t.Error("GetRSAPrivateKey should fail for used key")
	}
}

// TestKeyStoreGetRSAPrivateKeyExpired 测试获取过期密钥
func TestKeyStoreGetRSAPrivateKeyExpired(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
	}

	err := ks.generateRSAKey()
	if err != nil {
		t.Fatalf("generateRSAKey failed: %v", err)
	}

	// 获取密钥 ID 并设置为已过期
	var keyID string
	for kid, entry := range ks.rsaKeyPool {
		keyID = kid
		entry.ExpiredAt = time.Now().Add(-1 * time.Minute) // 1 分钟前过期
		break
	}

	// 尝试获取过期密钥应该失败
	_, err = ks.GetRSAPrivateKey(keyID)
	if err == nil {
		t.Error("GetRSAPrivateKey should fail for expired key")
	}
}

// TestKeyStoreInvalidateKey 测试使密钥失效
func TestKeyStoreInvalidateKey(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
	}

	err := ks.generateRSAKey()
	if err != nil {
		t.Fatalf("generateRSAKey failed: %v", err)
	}

	// 获取密钥 ID
	var keyID string
	for kid := range ks.rsaKeyPool {
		keyID = kid
		break
	}

	// 使密钥失效
	ks.InvalidateKey(keyID)

	// 验证密钥被删除
	if _, exists := ks.rsaKeyPool[keyID]; exists {
		t.Error("Key should be removed after invalidation")
	}
}

// TestKeyStoreGetKeyStats 测试获取密钥统计
func TestKeyStoreGetKeyStats(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
		aesDataKey: []byte("test-key-123456789012345678901234"),
	}

	// 添加活跃密钥
	ks.generateRSAKey()
	ks.generateRSAKey()

	// 添加已使用密钥
	ks.generateRSAKey()
	for _, entry := range ks.rsaKeyPool {
		entry.IsUsed = true
		break
	}

	stats := ks.GetKeyStats()

	if stats["rsa_pool_active"].(int) != 2 {
		t.Errorf("Active pool: got %v, want 2", stats["rsa_pool_active"])
	}

	if stats["rsa_pool_used"].(int) != 1 {
		t.Errorf("Used pool: got %v, want 1", stats["rsa_pool_used"])
	}

	if stats["aes_key_loaded"].(bool) != true {
		t.Error("AES key should be loaded")
	}
}

// TestKeyStoreMaintainKeyPool 测试密钥池维护
func TestKeyStoreMaintainKeyPool(t *testing.T) {
	ks := &KeyStore{
		rsaKeyPool: make(map[string]*RSAPubKeyEntry),
	}

	// 添加一个已过期的密钥
	err := ks.generateRSAKey()
	if err != nil {
		t.Fatalf("generateRSAKey failed: %v", err)
	}

	for _, entry := range ks.rsaKeyPool {
		entry.ExpiredAt = time.Now().Add(-1 * time.Minute)
		entry.IsUsed = true
	}

	// 运行维护
	ks.maintainKeyPool()

	// 过期的密钥应该被清理，并且补充新密钥
	if len(ks.rsaKeyPool) < 1 {
		t.Errorf("Pool should have at least 1 key after maintenance, got %d", len(ks.rsaKeyPool))
	}
}

// GetRSAKeyPoolSize 获取密钥池大小 (测试辅助方法)
func (ks *KeyStore) GetRSAKeyPoolSize() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return len(ks.rsaKeyPool)
}

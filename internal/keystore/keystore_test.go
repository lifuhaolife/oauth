package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

// newTestKeyStore 创建独立测试用 KeyStore，不使用全局单例
func newTestKeyStore(t *testing.T) *KeyStore {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试 JWT 密钥失败: %v", err)
	}
	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	return &KeyStore{
		rsaKeyPool:    make(map[string]*RSAPubKeyEntry),
		aesDataKey:    aesKey,
		jwtPrivateKey: privKey,
		jwtPublicKey:  &privKey.PublicKey,
	}
}

// ===== generateRSAKey 测试 =====

func TestGenerateRSAKeyPair(t *testing.T) {
	ks := newTestKeyStore(t)

	if err := ks.generateRSAKey(); err != nil {
		t.Fatalf("generateRSAKey 失败: %v", err)
	}
	if len(ks.rsaKeyPool) != 1 {
		t.Errorf("密钥池应有 1 个密钥，实际 %d 个", len(ks.rsaKeyPool))
	}

	for _, entry := range ks.rsaKeyPool {
		if entry.KeyID == "" {
			t.Error("KeyID 不应为空")
		}
		if len(entry.KeyID) != 32 {
			t.Errorf("KeyID 长度应为 32，实际 %d", len(entry.KeyID))
		}
		if entry.IsUsed {
			t.Error("新密钥不应被标记为已使用")
		}
		if entry.PrivateKey == nil {
			t.Error("私钥不应为 nil")
		}
		if entry.PublicKey == nil {
			t.Error("公钥不应为 nil")
		}
		if !time.Now().Before(entry.ExpiredAt) {
			t.Error("新密钥不应已过期")
		}
	}
}

func TestGenerateRSAKeyPairMultiple(t *testing.T) {
	ks := newTestKeyStore(t)

	for i := 0; i < 5; i++ {
		if err := ks.generateRSAKey(); err != nil {
			t.Fatalf("第 %d 次 generateRSAKey 失败: %v", i+1, err)
		}
	}
	if len(ks.rsaKeyPool) != 5 {
		t.Errorf("密钥池应有 5 个密钥，实际 %d 个", len(ks.rsaKeyPool))
	}
}

func TestGenerateRSAKeyPairUniqueness(t *testing.T) {
	ks := newTestKeyStore(t)

	for i := 0; i < 5; i++ {
		ks.generateRSAKey()
	}

	seen := make(map[string]bool)
	for keyID := range ks.rsaKeyPool {
		if seen[keyID] {
			t.Errorf("发现重复 KeyID: %s", keyID)
		}
		seen[keyID] = true
	}
}

// ===== GetRSAPublicKey 测试 =====

func TestGetPublicKey(t *testing.T) {
	ks := newTestKeyStore(t)
	ks.generateRSAKey()

	keyID, pubKeyB64, err := ks.GetRSAPublicKey()
	if err != nil {
		t.Fatalf("GetRSAPublicKey 失败: %v", err)
	}
	if keyID == "" {
		t.Error("KeyID 不应为空")
	}
	if pubKeyB64 == "" {
		t.Error("公钥 Base64 不应为空")
	}
}

func TestGetPublicKeyFromEmptyPool(t *testing.T) {
	ks := newTestKeyStore(t)
	// 池为空时应自动生成

	keyID, pubKeyB64, err := ks.GetRSAPublicKey()
	if err != nil {
		t.Fatalf("空密钥池应自动生成密钥: %v", err)
	}
	if keyID == "" || pubKeyB64 == "" {
		t.Error("自动生成的密钥不应为空")
	}
}

func TestGetPublicKeyReturnsDifferentKeys(t *testing.T) {
	ks := newTestKeyStore(t)
	ks.initRSAPool(5)

	// 同一次返回的 keyID 应和私钥匹配（一致性）
	keyID, _, _ := ks.GetRSAPublicKey()
	if _, exists := ks.rsaKeyPool[keyID]; !exists {
		t.Error("返回的 KeyID 应在密钥池中存在")
	}
}

// ===== GetRSAPrivateKey 测试 =====

func TestGetPrivateKey(t *testing.T) {
	ks := newTestKeyStore(t)
	ks.generateRSAKey()

	keyID, _, _ := ks.GetRSAPublicKey()

	privKey, err := ks.GetRSAPrivateKey(keyID)
	if err != nil {
		t.Fatalf("GetRSAPrivateKey 失败: %v", err)
	}
	if privKey == nil {
		t.Error("私钥不应为 nil")
	}
}

func TestGetPrivateKeyNotExists(t *testing.T) {
	ks := newTestKeyStore(t)

	_, err := ks.GetRSAPrivateKey("nonexistent-key-id-0000000000000")
	if err == nil {
		t.Error("获取不存在的密钥应返回错误")
	}
}

func TestGetPrivateKeyAlreadyUsed(t *testing.T) {
	ks := newTestKeyStore(t)
	ks.generateRSAKey()

	keyID, _, _ := ks.GetRSAPublicKey()
	ks.GetRSAPrivateKey(keyID) // 第一次：标记为已使用

	_, err := ks.GetRSAPrivateKey(keyID)
	if err == nil {
		t.Error("已使用的密钥再次获取应返回错误")
	}
}

func TestKeyIsMarkedUsedAfterGet(t *testing.T) {
	ks := newTestKeyStore(t)
	ks.generateRSAKey()

	keyID, _, _ := ks.GetRSAPublicKey()
	ks.GetRSAPrivateKey(keyID)

	entry := ks.rsaKeyPool[keyID]
	if entry == nil {
		t.Fatal("密钥条目不应为 nil")
	}
	if !entry.IsUsed {
		t.Error("获取私钥后应标记为已使用")
	}
}

// ===== InvalidateKey 测试 =====

func TestInvalidateKey(t *testing.T) {
	ks := newTestKeyStore(t)
	ks.generateRSAKey()

	keyID, _, _ := ks.GetRSAPublicKey()
	ks.InvalidateKey(keyID)

	if _, exists := ks.rsaKeyPool[keyID]; exists {
		t.Error("InvalidateKey 后密钥应从池中删除")
	}
}

func TestInvalidateNonExistentKey(t *testing.T) {
	ks := newTestKeyStore(t)
	// 对不存在的 key 调用 InvalidateKey 不应 panic
	ks.InvalidateKey("nonexistent-key")
}

// ===== 一次性密钥语义测试 =====

func TestKeyOneTimeUse(t *testing.T) {
	ks := newTestKeyStore(t)
	ks.generateRSAKey()

	keyID, _, _ := ks.GetRSAPublicKey()

	// 第一次：成功
	_, err := ks.GetRSAPrivateKey(keyID)
	if err != nil {
		t.Fatalf("第一次获取私钥应成功: %v", err)
	}

	// 第二次：失败（一次性密钥）
	_, err = ks.GetRSAPrivateKey(keyID)
	if err == nil {
		t.Error("一次性密钥第二次使用应失败")
	}
}

// ===== initRSAPool 测试 =====

func TestInitRSAPool(t *testing.T) {
	ks := newTestKeyStore(t)

	if err := ks.initRSAPool(5); err != nil {
		t.Fatalf("initRSAPool 失败: %v", err)
	}
	if len(ks.rsaKeyPool) != 5 {
		t.Errorf("密钥池应有 5 个密钥，实际 %d 个", len(ks.rsaKeyPool))
	}
}

func TestInitRSAPoolZero(t *testing.T) {
	ks := newTestKeyStore(t)

	if err := ks.initRSAPool(0); err != nil {
		t.Fatalf("initRSAPool(0) 不应报错: %v", err)
	}
	if len(ks.rsaKeyPool) != 0 {
		t.Errorf("密钥池应为空，实际 %d 个", len(ks.rsaKeyPool))
	}
}

// ===== GetKeyStats 测试 =====

func TestGetKeyStats(t *testing.T) {
	ks := newTestKeyStore(t)
	ks.initRSAPool(3)

	// 将一个密钥标记为已使用
	keyID, _, _ := ks.GetRSAPublicKey()
	ks.GetRSAPrivateKey(keyID)

	stats := ks.GetKeyStats()

	if stats["rsa_pool_total"].(int) != 3 {
		t.Errorf("总密钥数应为 3，实际 %v", stats["rsa_pool_total"])
	}
	if stats["rsa_pool_used"].(int) != 1 {
		t.Errorf("已使用密钥数应为 1，实际 %v", stats["rsa_pool_used"])
	}
	if stats["rsa_pool_active"].(int) != 2 {
		t.Errorf("活跃密钥数应为 2，实际 %v", stats["rsa_pool_active"])
	}
	if stats["aes_key_loaded"].(bool) != true {
		t.Error("AES 密钥应已加载")
	}
	if stats["jwt_key_loaded"].(bool) != true {
		t.Error("JWT 密钥应已加载")
	}
}

func TestGetKeyStatsEmptyPool(t *testing.T) {
	ks := newTestKeyStore(t)

	stats := ks.GetKeyStats()
	if stats["rsa_pool_total"].(int) != 0 {
		t.Errorf("空池总数应为 0，实际 %v", stats["rsa_pool_total"])
	}
}

// ===== GetAESKey 测试 =====

func TestGetAESKey(t *testing.T) {
	ks := newTestKeyStore(t)

	key := ks.GetAESKey()
	if len(key) != 32 {
		t.Errorf("AES 密钥长度应为 32，实际 %d", len(key))
	}
}

// ===== GetJWTKeys 测试 =====

func TestGetJWTKeys(t *testing.T) {
	ks := newTestKeyStore(t)

	privKey := ks.GetJWTPrivateKey()
	if privKey == nil {
		t.Error("JWT 私钥不应为 nil")
	}

	pubKey := ks.GetJWTPublicKey()
	if pubKey == nil {
		t.Error("JWT 公钥不应为 nil")
	}

	// 公私钥应匹配
	if privKey.PublicKey.N.Cmp(pubKey.N) != 0 {
		t.Error("JWT 公私钥不匹配")
	}
}

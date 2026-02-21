package tests

import (
	"os"
	"testing"

	"auth-service/internal/config"
)

func TestConfigLoading(t *testing.T) {
	// 保存原始环境变量
	originalMasterKey := os.Getenv("MASTER_KEY")

	// 设置测试环境变量
	os.Setenv("MASTER_KEY", "dGVzdF9tYXN0ZXJfa2V5X2Zvcl90ZXN0aW5nXzEyMw==") // Base64 encoded test key
	defer func() {
		// 恢复原始环境变量
		if originalMasterKey != "" {
			os.Setenv("MASTER_KEY", originalMasterKey)
		} else {
			os.Unsetenv("MASTER_KEY")
		}
	}()

	// 测试配置加载
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.DBHost == "" {
		t.Error("Expected DBHost to be set")
	}

	t.Logf("Successfully loaded config with DBHost: %s", cfg.DBHost)
}
package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

type Config struct {
	// 数据库配置
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	// JWT 配置
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string

	// 微信配置
	WechatAppID     string
	WechatAppSecret string
	WechatGrantType string

	// 服务配置
	ServerPort string
	ServerMode string

	// 日志配置
	LogLevel string
	LogFile  string

	// 主密钥 (用于加密存储敏感数据)
	MasterKey []byte
}

// LoadConfig 加载配置
func LoadConfig() (*Config, error) {
	// 加载 .env 文件
	envFile := filepath.Join(".", ".env")
	if _, err := os.Stat(envFile); err == nil {
		if err := godotenv.Load(envFile); err != nil {
			return nil, fmt.Errorf("加载.env 文件失败：%v", err)
		}
	}

	cfg := &Config{
		// 数据库配置
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "3306"),
		DBUser:     getEnv("DB_USER", "root"),
		DBPassword: getEnv("DB_PASSWORD", ""),
		DBName:     getEnv("DB_NAME", "auth_service"),

		// JWT 配置
		JWTPrivateKeyPath: getEnv("JWT_PRIVATE_KEY_PATH", "./keys/jwt_private.pem"),
		JWTPublicKeyPath:  getEnv("JWT_PUBLIC_KEY_PATH", "./keys/jwt_public.pem"),

		// 微信配置
		WechatAppID:     getEnv("WECHAT_APP_ID", ""),
		WechatAppSecret: getEnv("WECHAT_APP_SECRET", ""),
		WechatGrantType: getEnv("WECHAT_GRANT_TYPE", "authorization_code"),

		// 服务配置
		ServerPort: getEnv("SERVER_PORT", "8080"),
		ServerMode: getEnv("SERVER_MODE", "release"),

		// 日志配置
		LogLevel: getEnv("LOG_LEVEL", "info"),
		LogFile:  getEnv("LOG_FILE", "./logs/auth.log"),
	}

	// 加载或生成主密钥
	if err := cfg.loadOrGenerateMasterKey(); err != nil {
		return nil, fmt.Errorf("加载主密钥失败：%v", err)
	}

	// 确保 JWT 密钥对存在
	if err := ensureJWTKeyPair(cfg); err != nil {
		return nil, fmt.Errorf("确保 JWT 密钥对失败：%v", err)
	}

	return cfg, nil
}

// loadOrGenerateMasterKey 加载或生成主密钥
func (c *Config) loadOrGenerateMasterKey() error {
	masterKeyStr := os.Getenv("MASTER_KEY")

	if masterKeyStr == "" {
		// 生成新的主密钥 (32 字节)
		masterKey := make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			return fmt.Errorf("生成主密钥失败：%v", err)
		}

		// Base64 编码
		masterKeyStr = base64.StdEncoding.EncodeToString(masterKey)

		// 提示用户保存
		fmt.Println("========================================")
		fmt.Println("⚠️  已自动生成新的 MASTER_KEY")
		fmt.Println("⚠️  请务必备份此密钥，丢失后无法恢复！")
		fmt.Println("========================================")
		fmt.Printf("MASTER_KEY=%s\n", masterKeyStr)
		fmt.Println("========================================")
		fmt.Println("请将此密钥添加到 .env 文件中")
		fmt.Println("========================================")

		c.MasterKey = masterKey
	} else {
		// 解码 Base64
		key, err := base64.StdEncoding.DecodeString(masterKeyStr)
		if err != nil {
			return fmt.Errorf("解码主密钥失败：%v", err)
		}
		if len(key) != 32 {
			return fmt.Errorf("主密钥长度应为 32 字节，当前：%d 字节", len(key))
		}
		c.MasterKey = key
	}

	return nil
}

// ensureJWTKeyPair 确保 JWT 密钥对存在
func ensureJWTKeyPair(cfg *Config) error {
	// 检查私钥是否存在
	if _, err := os.Stat(cfg.JWTPrivateKeyPath); err == nil {
		return nil // 已存在
	}

	// 生成 RSA 密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成 JWT 密钥对失败：%v", err)
	}

	// 创建目录
	if err := os.MkdirAll(filepath.Dir(cfg.JWTPrivateKeyPath), 0755); err != nil {
		return err
	}

	// 保存私钥
	privateKeyBytes := x509.MarshalPKCS8PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	if err := os.WriteFile(cfg.JWTPrivateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("保存私钥失败：%v", err)
	}

	// 保存公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("编码公钥失败：%v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	if err := os.WriteFile(cfg.JWTPublicKeyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("保存公钥失败：%v", err)
	}

	fmt.Println("已生成新的 JWT 密钥对")
	return nil
}

// getEnv 获取环境变量，如果不存在则返回默认值
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

package model

import (
	"auth-service/internal/config"
	"auth-service/internal/crypto"
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB

// InitDB 初始化数据库
func InitDB(cfg *config.Config) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBName,
	)

	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("连接数据库失败：%v", err)
	}

	// 自动迁移表结构
	if err := AutoMigrate(); err != nil {
		return fmt.Errorf("数据库迁移失败：%v", err)
	}

	return nil
}

// GetDB 获取数据库实例
func GetDB() *gorm.DB {
	return db
}

// AutoMigrate 自动迁移表结构
func AutoMigrate() error {
	return db.AutoMigrate(
		&User{},
		&TokenBlacklist{},
		&LoginLog{},
		&KeyStoreRecord{},
	)
}

// ==================== User Role Constants ====================

// User role constants
const (
	RoleUser  = "user"  // 普通用户
	RoleAdmin = "admin" // 管理员
)

// ==================== User Model ====================

// User 用户表
type User struct {
	ID             int64     `gorm:"primaryKey" json:"id"`
	Username       string    `gorm:"size:50;uniqueIndex;not null" json:"username"`
	PasswordHash   string    `gorm:"size:255;not null" json:"-"`
	PhoneEncrypted []byte    `gorm:"size:255" json:"-"` // AES 加密存储，无手机号时为 NULL
	Phone          string    `gorm:"-" json:"phone,omitempty"`   // 解密后的手机号 (仅返回时用)
	WechatOpenID   string    `gorm:"size:64;uniqueIndex" json:"-"`
	WechatUnionID  string    `gorm:"size:64" json:"-"`
	Avatar         string    `gorm:"size:255" json:"avatar,omitempty"`
	Nickname       string    `gorm:"size:100" json:"nickname,omitempty"`
	Status         int       `gorm:"default:1" json:"status"` // 1:正常 0:禁用
	Role           string    `gorm:"size:20;default:'user'" json:"role"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP    string    `gorm:"size:45" json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// EncryptPhone 加密手机号
func (u *User) EncryptPhone(phone string, key []byte) error {
	encrypted, iv, err := crypto.AESEncrypt(key, []byte(phone))
	if err != nil {
		return err
	}
	// 将密文和 IV 一起存储
	data := append(encrypted, iv...)
	u.PhoneEncrypted = data
	return nil
}

// DecryptPhone 解密手机号
func (u *User) DecryptPhone(key []byte) error {
	if len(u.PhoneEncrypted) < 12 { // IV 长度为 12
		return fmt.Errorf("无效的加密数据")
	}
	// 分离密文和 IV
	ivLen := 12
	ciphertext := u.PhoneEncrypted[:len(u.PhoneEncrypted)-ivLen]
	iv := u.PhoneEncrypted[len(u.PhoneEncrypted)-ivLen:]

	plaintext, err := crypto.AESDecrypt(key, ciphertext, iv)
	if err != nil {
		return err
	}
	u.Phone = string(plaintext)
	return nil
}

// GetMaskedPhone 获取脱敏手机号
func (u *User) GetMaskedPhone(key []byte) string {
	if err := u.DecryptPhone(key); err != nil {
		return "***"
	}
	if len(u.Phone) >= 7 {
		return u.Phone[:3] + "****" + u.Phone[len(u.Phone)-4:]
	}
	return "***"
}

// TableName 指定表名
func (User) TableName() string {
	return "users"
}

// TokenBlacklist Token 黑名单表
type TokenBlacklist struct {
	ID        int64     `gorm:"primaryKey" json:"id"`
	Jti       string    `gorm:"size:64;uniqueIndex;not null" json:"jti"`
	ExpiredAt time.Time `json:"expired_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (TokenBlacklist) TableName() string {
	return "token_blacklist"
}

// LoginLog 登录日志表
type LoginLog struct {
	ID         int64     `gorm:"primaryKey" json:"id"`
	UserID     int64     `gorm:"index" json:"user_id"`
	LoginType  string    `gorm:"size:20" json:"login_type"` // PASSWORD/WECHAT
	IPAddress  string    `gorm:"size:45" json:"ip_address"`
	UserAgent  string    `gorm:"type:text" json:"user_agent"`
	Status     int       `json:"status"` // 1:成功 0:失败
	FailReason string    `gorm:"size:255" json:"fail_reason,omitempty"`
	CreatedAt  time.Time `gorm:"index" json:"created_at"`
}

func (LoginLog) TableName() string {
	return "login_logs"
}

// KeyStoreRecord 密钥存储记录表 (用于审计)
type KeyStoreRecord struct {
	ID              int64     `gorm:"primaryKey" json:"id"`
	KeyName         string    `gorm:"size:50;uniqueIndex" json:"key_name"`
	KeyFingerprint  string    `gorm:"size:64" json:"key_fingerprint"` // 密钥指纹
	IsUsed          int       `gorm:"default:0" json:"is_used"`       // 0:未使用 1:已使用
	UsedAt          *time.Time `json:"used_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiredAt       time.Time `gorm:"index" json:"expired_at"`
}

func (KeyStoreRecord) TableName() string {
	return "key_store_record"
}

// ============ 数据传输结构 ============

// LoginRequest 登录请求
type LoginRequest struct {
	KeyID     string `json:"key_id" binding:"required"`
	Encrypted string `json:"encrypted_data" binding:"required"`
	Signature string `json:"signature"`  // 签名验证暂未实现，可选
	Timestamp int64  `json:"timestamp" binding:"required"`
	Nonce     string `json:"nonce" binding:"required"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	User         UserInfo  `json:"user"`
}

// UserInfo 用户信息
type UserInfo struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Nickname  string    `json:"nickname,omitempty"`
	Avatar    string    `json:"avatar,omitempty"`
	Phone     string    `json:"phone,omitempty"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// RefreshTokenRequest 刷新 Token 请求
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutRequest 登出请求
type LogoutRequest struct {
	AccessToken string `json:"access_token" binding:"required"`
}

// WechatLoginRequest 微信登录请求
type WechatLoginRequest struct {
	Code string `json:"code" binding:"required"`
}

// WechatAuthURLResponse 微信授权 URL 响应
type WechatAuthURLResponse struct {
	AuthURL   string `json:"auth_url"`
	State     string `json:"state"`
	ExpiresIn int    `json:"expires_in"`
}

// RSAPublicKeyResponse RSA 公钥响应
type RSAPublicKeyResponse struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // Base64 编码的 PEM
}

// JWKSResponse JWK Set 响应
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// CreateUserPayload RSA 解密后的创建用户 payload（仅内部使用）
type CreateUserPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Phone    string `json:"phone"`
	Nickname string `json:"nickname"`
	Role     string `json:"role"` // 可选：用户角色，默认为 "user"，可指定 "admin"
}

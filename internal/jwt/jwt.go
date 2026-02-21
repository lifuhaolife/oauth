package jwt

import (
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTService JWT 服务
type JWTService struct {
	accessExpire  time.Duration
	refreshExpire time.Duration
}

// Claims JWT Claims
type Claims struct {
	jwt.RegisteredClaims
	Type    string   `json:"type"`     // access 或 refresh
	Device  string   `json:"device"`   // 设备指纹
	Scope   []string `json:"scope"`    // 权限范围
	Username string  `json:"username"` // 用户名
}

var (
	blacklist     = make(map[string]time.Time)
	blacklistLock sync.RWMutex
)

// NewJWTService 创建 JWT 服务
func NewJWTService() *JWTService {
	return &JWTService{
		accessExpire:  15 * time.Minute,
		refreshExpire: 7 * 24 * time.Hour,
	}
}

// GenerateToken 生成 JWT Token
func (s *JWTService) GenerateToken(user *model.User) (accessToken, refreshToken string, err error) {
	keyStore := keystore.GetKeyStore()
	privateKey := keyStore.GetJWTPrivateKey()

	// 生成 JTI
	jti := uuid.New().String()

	// 设备指纹 (可以用 IP+UserAgent 的哈希)
	device := s.generateDeviceFingerprint(user.ID)

	now := time.Now()

	// Access Token
	accessClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   string(rune(user.ID)),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessExpire)),
			Issuer:    "auth-service",
			ID:        jti,
		},
		Type:     "access",
		Device:   device,
		Scope:    []string{"read", "write"},
		Username: user.Username,
	}

	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken, err = accessTokenObj.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}

	// Refresh Token
	refreshClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   string(rune(user.ID)),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshExpire)),
			Issuer:    "auth-service",
			ID:        jti + "_refresh",
		},
		Type:     "refresh",
		Device:   device,
		Scope:    []string{"refresh"},
		Username: user.Username,
	}

	refreshTokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshToken, err = refreshTokenObj.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// ValidateToken 验证 Token
func (s *JWTService) ValidateToken(tokenString string) (map[string]interface{}, error) {
	keyStore := keystore.GetKeyStore()
	publicKey := keyStore.GetJWTPublicKey()

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("不支持的签名算法")
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// 检查是否在黑名单中
		if s.IsInBlacklist(tokenString) {
			return nil, errors.New("Token 已失效")
		}

		return map[string]interface{}{
			"sub":      claims.Subject,
			"jti":      claims.ID,
			"type":     claims.Type,
			"device":   claims.Device,
			"scope":    claims.Scope,
			"username": claims.Username,
		}, nil
	}

	return nil, errors.New("无效的 Token")
}

// AddToBlacklist 将 Token 加入黑名单
func (s *JWTService) AddToBlacklist(tokenString string) error {
	// 解析 token 获取过期时间
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return errors.New("无效的 Token")
	}

	// 获取过期时间
	var exp time.Time
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	} else {
		exp = time.Now().Add(1 * time.Hour)
	}

	// 计算 token 的 hash 作为 key
	tokenHash := s.hashToken(tokenString)

	blacklistLock.Lock()
	defer blacklistLock.Unlock()
	blacklist[tokenHash] = exp

	// 同时存入数据库 (持久化)
	s.saveToDatabase(claims.ID, exp)

	return nil
}

// IsInBlacklist 检查 Token 是否在黑名单中
func (s *JWTService) IsInBlacklist(tokenString string) bool {
	tokenHash := s.hashToken(tokenString)

	blacklistLock.RLock()
	defer blacklistLock.RUnlock()

	exp, exists := blacklist[tokenHash]
	if !exists {
		return false
	}

	// 如果已过期，从内存中移除
	if time.Now().After(exp) {
		delete(blacklist, tokenHash)
		return false
	}

	return true
}

// generateDeviceFingerprint 生成设备指纹
func (s *JWTService) generateDeviceFingerprint(userID int64) string {
	// 简单实现，实际可以用 IP+UserAgent+ 其他特征
	data := []byte(fmt.Sprintf("%d_%s", userID, time.Now().String()))
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])[:32]
}

// hashToken 计算 Token 哈希
func (s *JWTService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// saveToDatabase 保存到数据库
func (s *JWTService) saveToDatabase(jti string, expiredAt time.Time) {
	// 异步保存
	go func() {
		record := model.TokenBlacklist{
			Jti:       jti,
			ExpiredAt: expiredAt,
			CreatedAt: time.Now(),
		}
		model.GetDB().Create(&record)
	}()
}

// CleanBlacklist 清理过期的黑名单记录
func (s *JWTService) CleanBlacklist() {
	blacklistLock.Lock()
	defer blacklistLock.Unlock()

	now := time.Now()
	for hash, exp := range blacklist {
		if now.After(exp) {
			delete(blacklist, hash)
		}
	}
}

// 启动定期清理
func init() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			// 清理内存黑名单
			blacklistLock.Lock()
			now := time.Now()
			for hash, exp := range blacklist {
				if now.After(exp) {
					delete(blacklist, hash)
				}
			}
			blacklistLock.Unlock()

			// 清理数据库黑名单
			model.GetDB().Where("expired_at < ?", now).Delete(&model.TokenBlacklist{})
		}
	}()
}

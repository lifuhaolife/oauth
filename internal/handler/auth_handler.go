package handler

import (
	"auth-service/internal/crypto"
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"auth-service/internal/service"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// nonceCache Nonce 去重缓存（防重放攻击），key = "nonce:timestamp"，value = 过期时间
var nonceCache sync.Map

// init 启动 nonce 缓存清理协程
func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			nonceCache.Range(func(key, value interface{}) bool {
				if exp, ok := value.(time.Time); ok && now.After(exp) {
					nonceCache.Delete(key)
				}
				return true
			})
		}
	}()
}

// GetRSAPublicKey 获取 RSA 公钥
func GetRSAPublicKey(c *gin.Context) {
	keyStore := keystore.GetKeyStore()

	keyID, publicKeyBase64, err := keyStore.GetRSAPublicKey()
	if err != nil {
		model.Fail(c, model.ErrPubKeyFail)
		return
	}

	go recordPubKeyUsage(keyID)

	model.OK(c, gin.H{
		"key_id":     keyID,
		"public_key": publicKeyBase64,
	})
}

// recordPubKeyUsage 记录公钥使用（DB 未初始化时静默跳过）
func recordPubKeyUsage(keyID string) {
	db := model.GetDB()
	if db == nil {
		return
	}
	record := model.KeyStoreRecord{
		KeyName:        "rsa_" + keyID,
		KeyFingerprint: keyID,
		IsUsed:         0,
		CreatedAt:      time.Now(),
		ExpiredAt:      time.Now().Add(10 * time.Minute),
	}
	db.Create(&record)
}

// Login 用户登录
func Login(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[LOGIN] 参数解析失败: %v", err)
		model.Fail(c, model.ErrParamInvalid)
		return
	}

	log.Printf("[LOGIN] KeyID=%s Timestamp=%d Nonce=%s", req.KeyID, req.Timestamp, req.Nonce)

	// 验证时间戳（防重放，5 分钟窗口）
	now := time.Now().Unix()
	if now-req.Timestamp > 300 {
		model.Fail(c, model.ErrRequestExpired)
		return
	}

	// Nonce 去重（防重放）
	if err := checkNonce(req.Nonce, req.Timestamp); err != nil {
		log.Printf("[LOGIN] Nonce 重复 nonce=%s", req.Nonce)
		model.FailMsg(c, model.ErrRequestExpired, "重复的请求")
		return
	}

	// 验证签名（如果客户端提供了签名）
	if err := verifySignature(req); err != nil {
		log.Printf("[LOGIN] 签名验证失败: %v", err)
		model.Fail(c, model.ErrSigInvalid)
		return
	}

	// 获取 RSA 私钥解密
	keyStore := keystore.GetKeyStore()
	privateKey, err := keyStore.GetRSAPrivateKey(req.KeyID)
	if err != nil {
		model.Fail(c, model.ErrKeyInvalid)
		return
	}

	// Base64 解码加密数据
	encryptedData, err := base64.StdEncoding.DecodeString(req.Encrypted)
	if err != nil {
		model.Fail(c, model.ErrDataFormat)
		return
	}

	// RSA 解密
	decryptedData, err := crypto.RSADecrypt(privateKey, encryptedData)
	if err != nil {
		model.Fail(c, model.ErrDecryptFail)
		return
	}

	// 使用后销毁密钥
	go keyStore.InvalidateKey(req.KeyID)

	// 解析解密后的凭证
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(decryptedData, &credentials); err != nil {
		model.Fail(c, model.ErrDataFormat)
		return
	}

	// 调用认证服务
	authService := service.GetAuthService()
	user, resp, err := authService.Login(credentials.Username, credentials.Password)
	if err != nil {
		go logLoginAttempt(0, "PASSWORD", c.ClientIP(), c.Request.UserAgent(), 0, err.Error())
		model.FailMsg(c, model.ErrAuthFail, err.Error())
		return
	}

	go logLoginAttempt(user.ID, "PASSWORD", c.ClientIP(), c.Request.UserAgent(), 1, "")

	user.DecryptPhone(keyStore.GetAESKey())

	model.OK(c, gin.H{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
		"token_type":    resp.TokenType,
		"expires_in":    resp.ExpiresIn,
		"user": gin.H{
			"id":         user.ID,
			"username":   user.Username,
			"nickname":   user.Nickname,
			"avatar":     user.Avatar,
			"phone":      user.Phone,
			"role":       user.Role,
			"created_at": user.CreatedAt,
		},
	})
}

// RefreshToken 刷新 Token
func RefreshToken(c *gin.Context) {
	var req model.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		model.Fail(c, model.ErrParamInvalid)
		return
	}

	authService := service.GetAuthService()
	resp, err := authService.RefreshToken(req.RefreshToken)
	if err != nil {
		model.FailMsg(c, model.ErrTokenInvalid, err.Error())
		return
	}

	model.OK(c, gin.H{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
		"token_type":    resp.TokenType,
		"expires_in":    resp.ExpiresIn,
	})
}

// Logout 用户登出
func Logout(c *gin.Context) {
	var req model.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		model.Fail(c, model.ErrParamInvalid)
		return
	}

	authService := service.GetAuthService()
	if err := authService.Logout(req.AccessToken); err != nil {
		model.Fail(c, model.ErrServerError)
		return
	}

	model.OKEmpty(c)
}

// GetCurrentUser 获取当前用户信息
func GetCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")

	keyStore := keystore.GetKeyStore()
	authService := service.GetAuthService()

	user, err := authService.GetUserByID(userID.(int64))
	if err != nil {
		model.Fail(c, model.ErrNotFound)
		return
	}

	model.OK(c, gin.H{
		"id":         user.ID,
		"username":   user.Username,
		"nickname":   user.Nickname,
		"avatar":     user.Avatar,
		"phone":      user.GetMaskedPhone(keyStore.GetAESKey()),
		"role":       user.Role,
		"created_at": user.CreatedAt,
		"last_login": user.LastLoginAt,
	})
}

// ChangePassword 修改密码（含密码强度校验）
func ChangePassword(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		model.Fail(c, model.ErrParamInvalid)
		return
	}

	authService := service.GetAuthService()
	if err := authService.ChangePassword(userID.(int64), req.OldPassword, req.NewPassword); err != nil {
		model.FailMsg(c, model.ErrAuthFail, err.Error())
		return
	}

	model.OKEmpty(c)
}

// GetWechatAuthURL 获取微信授权 URL
func GetWechatAuthURL(c *gin.Context) {
	model.OK(c, model.WechatAuthURLResponse{
		AuthURL:   "",
		State:     "",
		ExpiresIn: 0,
	})
}

// WechatCallback 微信登录回调
func WechatCallback(c *gin.Context) {
	code := c.Query("code")

	if code == "" {
		model.Fail(c, model.ErrParamInvalid)
		return
	}

	authService := service.GetAuthService()
	_, _, err := authService.WechatLogin(code)
	if err != nil {
		model.FailMsg(c, model.ErrServerError, err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/login/success?token=xxx")
}

// GetJWKS 获取 JWK Set（遵循 RFC 7517 标准格式，此接口格式例外）
func GetJWKS(c *gin.Context) {
	keyStore := keystore.GetKeyStore()
	publicKey := keyStore.GetJWTPublicKey()

	eBytes := big.NewInt(int64(publicKey.E)).Bytes()
	jwk := model.JWK{
		Kty: "RSA",
		Kid: "jwt-key-1",
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	c.JSON(http.StatusOK, model.JWKSResponse{
		Keys: []model.JWK{jwk},
	})
}

// verifySignature 验证请求签名（HMAC-SHA256）
// 若客户端未提供签名（空字符串），则跳过验证（向后兼容）。
// 提供签名时，使用 MASTER_KEY 计算 HMAC-SHA256 并做常量时间比较。
func verifySignature(req model.LoginRequest) error {
	if req.Signature == "" {
		return nil
	}

	ks := keystore.GetKeyStore()
	masterKey := ks.GetAESKey()

	msg := fmt.Sprintf("timestamp=%d&nonce=%s&key_id=%s", req.Timestamp, req.Nonce, req.KeyID)
	expected := crypto.HMACSign(masterKey, []byte(msg))
	expectedHex := hex.EncodeToString(expected)

	if !crypto.HMACVerify(masterKey, []byte(msg), []byte(req.Signature)) {
		// 也尝试 hex 编码比较
		if req.Signature != expectedHex {
			return fmt.Errorf("签名验证失败")
		}
	}
	return nil
}

// checkNonce 检查 nonce 唯一性（防重放）
// 同一 nonce+timestamp 组合在 5 分钟内只能使用一次。
func checkNonce(nonce string, timestamp int64) error {
	key := fmt.Sprintf("%s:%d", nonce, timestamp)
	expireAt := time.Now().Add(5 * time.Minute)
	if _, loaded := nonceCache.LoadOrStore(key, expireAt); loaded {
		return fmt.Errorf("重复的请求")
	}
	return nil
}

// logLoginAttempt 记录登录日志（DB 未初始化时静默跳过）
func logLoginAttempt(userID int64, loginType, ip, ua string, status int, failReason string) {
	db := model.GetDB()
	if db == nil {
		return
	}
	record := model.LoginLog{
		UserID:     userID,
		LoginType:  loginType,
		IPAddress:  ip,
		UserAgent:  ua,
		Status:     status,
		FailReason: failReason,
		CreatedAt:  time.Now(),
	}
	db.Create(&record)
}

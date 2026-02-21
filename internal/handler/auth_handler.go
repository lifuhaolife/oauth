package handler

import (
	"auth-service/internal/crypto"
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"auth-service/internal/service"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// GetRSAPublicKey 获取 RSA 公钥
// @Summary 获取 RSA 公钥
// @Tags 认证
// @Success 200 {object} model.Response
// @Router /api/v1/auth/pubkey [get]
func GetRSAPublicKey(c *gin.Context) {
	keyStore := keystore.GetKeyStore()

	keyID, publicKeyBase64, err := keyStore.GetRSAPublicKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Code:    500,
			Message: "获取公钥失败",
			Error:   err.Error(),
		})
		return
	}

	// 记录公钥使用 (异步)
	go recordPubKeyUsage(keyID)

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "获取公钥成功",
		Data: gin.H{
			"key_id":     keyID,
			"public_key": publicKeyBase64,
		},
	})
}

// recordPubKeyUsage 记录公钥使用
func recordPubKeyUsage(keyID string) {
	// 记录到数据库用于审计
	record := model.KeyStoreRecord{
		KeyName:        "rsa_" + keyID,
		KeyFingerprint: keyID,
		IsUsed:         0,
		CreatedAt:      time.Now(),
		ExpiredAt:      time.Now().Add(10 * time.Minute),
	}
	model.GetDB().Create(&record)
}

// Login 用户登录
// @Summary 用户登录
// @Tags 认证
// @Accept json
// @Param request body model.LoginRequest true "登录请求"
// @Success 200 {object} model.LoginResponse
// @Router /api/v1/auth/login [post]
func Login(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// 打印详细错误信息用于调试
		fmt.Printf("登录请求参数错误: %v\n", err)
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "请求参数错误",
			Error:   err.Error(),
		})
		return
	}

	fmt.Printf("登录请求: KeyID=%s, Timestamp=%d, Nonce=%s\n", req.KeyID, req.Timestamp, req.Nonce)

	// 验证时间戳 (防重放攻击)
	now := time.Now().Unix()
	if now-req.Timestamp > 300 { // 5 分钟
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "请求已过期",
		})
		return
	}

	// 验证签名
	if err := verifySignature(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "签名验证失败",
		})
		return
	}

	// 获取 RSA 私钥解密
	keyStore := keystore.GetKeyStore()
	privateKey, err := keyStore.GetRSAPrivateKey(req.KeyID)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "密钥无效或已使用",
		})
		return
	}

	// Base64 解码加密数据
	encryptedData, err := base64.StdEncoding.DecodeString(req.Encrypted)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "无效的加密数据",
		})
		return
	}

	// RSA 解密
	decryptedData, err := crypto.RSADecrypt(privateKey, encryptedData)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "解密失败",
		})
		return
	}

	// 使用后销毁密钥
	go keyStore.InvalidateKey(req.KeyID)

	// 解析解密后的数据
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(decryptedData, &credentials); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "无效的数据格式",
		})
		return
	}

	// 调用认证服务
	authService := service.GetAuthService()
	user, resp, err := authService.Login(credentials.Username, credentials.Password)
	if err != nil {
		// 记录登录失败日志
		go logLoginAttempt(0, "PASSWORD", "", "", 0, err.Error())

		c.JSON(http.StatusUnauthorized, model.ErrorResponse{
			Code:    401,
			Message: err.Error(),
		})
		return
	}

	// 记录登录成功日志
	go logLoginAttempt(user.ID, "PASSWORD", c.ClientIP(), c.Request.UserAgent(), 1, "")

	// 解密手机号返回
	user.DecryptPhone(keyStore.GetAESKey())

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "登录成功",
		Data: gin.H{
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
		},
	})
}

// RefreshToken 刷新 Token
func RefreshToken(c *gin.Context) {
	var req model.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "请求参数错误",
			Error:   err.Error(),
		})
		return
	}

	authService := service.GetAuthService()
	resp, err := authService.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{
			Code:    401,
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "刷新成功",
		Data: gin.H{
			"access_token":  resp.AccessToken,
			"refresh_token": resp.RefreshToken,
			"token_type":    resp.TokenType,
			"expires_in":    resp.ExpiresIn,
		},
	})
}

// Logout 用户登出
func Logout(c *gin.Context) {
	var req model.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "请求参数错误",
			Error:   err.Error(),
		})
		return
	}

	authService := service.GetAuthService()
	if err := authService.Logout(req.AccessToken); err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Code:    500,
			Message: "登出失败",
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "登出成功",
	})
}

// GetCurrentUser 获取当前用户信息
func GetCurrentUser(c *gin.Context) {
	// 从上下文获取用户信息 (由 AuthMiddleware 注入)
	userID, _ := c.Get("user_id")

	keyStore := keystore.GetKeyStore()
	authService := service.GetAuthService()

	user, err := authService.GetUserByID(userID.(int64))
	if err != nil {
		c.JSON(http.StatusNotFound, model.ErrorResponse{
			Code:    404,
			Message: "用户不存在",
			Error:   err.Error(),
		})
		return
	}

	// 解密手机号
	user.DecryptPhone(keyStore.GetAESKey())

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "获取成功",
		Data: gin.H{
			"id":         user.ID,
			"username":   user.Username,
			"nickname":   user.Nickname,
			"avatar":     user.Avatar,
			"phone":      user.GetMaskedPhone(keyStore.GetAESKey()),
			"role":       user.Role,
			"created_at": user.CreatedAt,
			"last_login": user.LastLoginAt,
		},
	})
}

// ChangePassword 修改密码
func ChangePassword(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "请求参数错误",
			Error:   err.Error(),
		})
		return
	}

	authService := service.GetAuthService()
	if err := authService.ChangePassword(userID.(int64), req.OldPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "密码修改成功",
	})
}

// GetWechatAuthURL 获取微信授权 URL
func GetWechatAuthURL(c *gin.Context) {
	// TODO: 配置微信参数后实现
	c.JSON(http.StatusOK, model.WechatAuthURLResponse{
		AuthURL:   "",
		State:     "",
		ExpiresIn: 0,
	})
}

// WechatCallback 微信登录回调
func WechatCallback(c *gin.Context) {
	code := c.Query("code")

	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "缺少 code 参数",
		})
		return
	}

	authService := service.GetAuthService()
	_, _, err := authService.WechatLogin(code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 重定向到前端页面，带上 token
	c.Redirect(http.StatusFound, "/login/success?token=xxx")
}

// GetJWKS 获取 JWK Set (用于 JWT 公钥发现)
func GetJWKS(c *gin.Context) {
	keyStore := keystore.GetKeyStore()
	publicKey := keyStore.GetJWTPublicKey()

	// 生成 JWK
	jwk := model.JWK{
		Kty: "RSA",
		Kid: "jwt-key-1",
		Use: "sig",
		Alg: "RS256",
		N:   crypto.Base64Encode(publicKey.N.Bytes()),
		E:   crypto.Base64Encode([]byte{0, 1, 0, 1}), // 65537
	}

	c.JSON(http.StatusOK, model.JWKSResponse{
		Keys: []model.JWK{jwk},
	})
}

// verifySignature 验证请求签名
func verifySignature(req model.LoginRequest) error {
	// TODO: 实现 HMAC 签名验证
	// 这里简化处理，实际应该验证 signature 字段
	return nil
}

// logLoginAttempt 记录登录日志
func logLoginAttempt(userID int64, loginType, ip, ua string, status int, failReason string) {
	log := model.LoginLog{
		UserID:     userID,
		LoginType:  loginType,
		IPAddress:  ip,
		UserAgent:  ua,
		Status:     status,
		FailReason: failReason,
		CreatedAt:  time.Now(),
	}
	model.GetDB().Create(&log)
}

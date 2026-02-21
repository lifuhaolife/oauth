package service

import (
	"auth-service/internal/crypto"
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"auth-service/pkg/jwt"
	"errors"
	"time"
)

// AuthService 认证服务
type AuthService struct {
	keyStore *keystore.KeyStore
	jwtSvc   *jwt.JWTService
}

var authService *AuthService

// InitServices 初始化所有服务
func InitServices() {
	authService = &AuthService{
		keyStore: keystore.GetKeyStore(),
		jwtSvc:   jwt.NewJWTService(),
	}
}

// GetAuthService 获取认证服务实例
func GetAuthService() *AuthService {
	return authService
}

// Login 用户登录 (密码)
func (s *AuthService) Login(username, password string) (*model.User, *model.LoginResponse, error) {
	// 查询用户
	var user model.User
	if err := model.GetDB().Where("username = ?", username).First(&user).Error; err != nil {
		return nil, nil, errors.New("用户名或密码错误")
	}

	// 检查用户状态
	if user.Status != 1 {
		return nil, nil, errors.New("账号已被禁用")
	}

	// 验证密码
	if !checkPassword(password, user.PasswordHash) {
		return nil, nil, errors.New("用户名或密码错误")
	}

	// 生成 JWT
	accessToken, refreshToken, err := s.jwtSvc.GenerateToken(&user)
	if err != nil {
		return nil, nil, errors.New("生成 Token 失败")
	}

	// 更新最后登录时间
	now := time.Now()
	user.LastLoginAt = &now
	model.GetDB().Save(&user)

	// 准备响应
	resp := &model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 分钟
	}

	return &user, resp, nil
}

// WechatLogin 微信登录
func (s *AuthService) WechatLogin(code string) (*model.User, *model.LoginResponse, error) {
	// TODO: 调用微信 API 换取用户信息
	// 这里预留接口，实际使用时需要配置 WECHAT_APP_ID 和 WECHAT_APP_SECRET

	// 1. 用 code 换取 access_token 和 openid
	// 2. 用 openid 查询用户
	// 3. 不存在则创建新用户
	// 4. 生成 JWT

	return nil, nil, errors.New("微信登录暂未启用，请先配置微信参数")
}

// RefreshToken 刷新 Token
func (s *AuthService) RefreshToken(refreshToken string) (*model.LoginResponse, error) {
	// 验证 refresh token
	claims, err := s.jwtSvc.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.New("无效的刷新 Token")
	}

	// 检查是否是 refresh token
	if claims["type"] != "refresh" {
		return nil, errors.New("无效的 Token 类型")
	}

	// 检查是否在黑名单中
	if s.jwtSvc.IsInBlacklist(refreshToken) {
		return nil, errors.New("Token 已失效")
	}

	// 获取用户 ID
	userID := int64(claims["sub"].(float64))

	// 查询用户
	var user model.User
	if err := model.GetDB().First(&user, userID).Error; err != nil {
		return nil, errors.New("用户不存在")
	}

	// 检查用户状态
	if user.Status != 1 {
		return nil, errors.New("账号已被禁用")
	}

	// 生成新的 token 对
	accessToken, newRefreshToken, err := s.jwtSvc.GenerateToken(&user)
	if err != nil {
		return nil, errors.New("生成 Token 失败")
	}

	return &model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}

// Logout 登出
func (s *AuthService) Logout(accessToken string) error {
	// 将 token 加入黑名单
	return s.jwtSvc.AddToBlacklist(accessToken)
}

// ValidateToken 验证 Token
func (s *AuthService) ValidateToken(tokenString string) (map[string]interface{}, error) {
	return s.jwtSvc.ValidateToken(tokenString)
}

// GetUserByID 根据 ID 获取用户
func (s *AuthService) GetUserByID(userID int64) (*model.User, error) {
	var user model.User
	if err := model.GetDB().First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// ChangePassword 修改密码
func (s *AuthService) ChangePassword(userID int64, oldPassword, newPassword string) error {
	// 查询用户
	var user model.User
	if err := model.GetDB().First(&user, userID).Error; err != nil {
		return errors.New("用户不存在")
	}

	// 验证旧密码
	if !checkPassword(oldPassword, user.PasswordHash) {
		return errors.New("原密码错误")
	}

	// 更新密码
	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		return errors.New("加密失败")
	}

	user.PasswordHash = hashedPassword
	if err := model.GetDB().Save(&user).Error; err != nil {
		return errors.New("更新失败")
	}

	// 可选：使所有 token 失效
	// s.jwtSvc.BlacklistAllUserTokens(userID)

	return nil
}

// hashPassword 哈希密码
func hashPassword(password string) (string, error) {
	return crypto.HashPassword(password)
}

// checkPassword 验证密码
func checkPassword(password, hash string) bool {
	return crypto.CheckPasswordHash(password, hash)
}

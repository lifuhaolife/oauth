package service

import (
	"auth-service/internal/crypto"
	"auth-service/internal/jwt"
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode"
)

// AuthService 认证服务
type AuthService struct {
	keyStore *keystore.KeyStore
	jwtSvc   *jwt.JWTService
}

var authService *AuthService

// InitServices 初始化所有服务
func InitServices() {
	jwtSvc := jwt.NewJWTService()
	authService = &AuthService{
		keyStore: keystore.GetKeyStore(),
		jwtSvc:   jwtSvc,
	}

	// 从数据库加载未过期的黑名单，确保重启后已登出 token 继续无效
	if err := jwtSvc.LoadBlacklistFromDB(); err != nil {
		// 非致命错误，仅记录警告
		fmt.Printf("[WARN] 加载 token 黑名单失败: %v\n", err)
	} else {
		fmt.Println("[INFO] Token 黑名单已从数据库加载")
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
	userID := claims["sub"].(int64)

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

	// 新密码强度校验
	if err := validatePasswordStrength(newPassword); err != nil {
		return err
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

// ErrUsernameAlreadyExists 用户名已存在哨兵错误
var ErrUsernameAlreadyExists = errors.New("用户名已存在")

// validateUsername 校验用户名格式（4-20 位，仅字母/数字/下划线）
func validateUsername(username string) error {
	if len(username) < 4 || len(username) > 20 {
		return fmt.Errorf("用户名长度必须在 4-20 位之间")
	}
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_]+$`, username)
	if !matched {
		return fmt.Errorf("用户名只能包含字母、数字和下划线")
	}
	return nil
}

// validatePasswordStrength 校验密码强度（8+ 位，含大小写字母和数字）
func validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("密码至少需要 8 位")
	}
	var hasUpper, hasLower, hasDigit bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("密码必须包含大写字母、小写字母和数字")
	}
	return nil
}

// CreateUser 创建新用户（管理员操作）
func (s *AuthService) CreateUser(username, password, phone, nickname, role string) (*model.User, error) {
	// 1. 用户名格式校验
	if err := validateUsername(username); err != nil {
		return nil, err
	}

	// 2. 检查用户名唯一性
	var count int64
	model.GetDB().Model(&model.User{}).Where("username = ?", username).Count(&count)
	if count > 0 {
		return nil, ErrUsernameAlreadyExists
	}

	// 3. 密码强度校验
	if err := validatePasswordStrength(password); err != nil {
		return nil, err
	}

	// 4. 角色合法性校验（仅允许 "user" 或 "admin"，不传默认为 "user"）
	if role == "" {
		role = model.RoleUser
	}
	if role != model.RoleUser && role != model.RoleAdmin {
		return nil, fmt.Errorf("角色值无效，仅允许 '%s' 或 '%s'", model.RoleUser, model.RoleAdmin)
	}

	// 5. BCrypt 哈希密码
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("密码加密失败")
	}

	// 6. 构建用户记录（使用传入的 role，而非硬编码）
	user := model.User{
		Username:     username,
		PasswordHash: hashedPassword,
		Nickname:     nickname,
		Status:       1,
		Role:         role,
	}

	// 7. 若有手机号，AES 加密存储
	if phone != "" {
		if err := user.EncryptPhone(phone, s.keyStore.GetAESKey()); err != nil {
			return nil, fmt.Errorf("手机号加密失败")
		}
	}

	// 8. 创建用户记录
	if err := model.GetDB().Create(&user).Error; err != nil {
		return nil, fmt.Errorf("创建用户失败")
	}

	return &user, nil
}

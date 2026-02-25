package handler

import (
	"auth-service/internal/crypto"
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"auth-service/internal/service"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// ListUsers 获取用户列表 (管理员)
func ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	var users []model.User
	var total int64

	model.GetDB().Model(&model.User{}).Count(&total)
	model.GetDB().Offset(offset).Limit(pageSize).Find(&users)

	keyStore := keystore.GetKeyStore()

	// 脱敏处理
	for i := range users {
		users[i].Phone = users[i].GetMaskedPhone(keyStore.GetAESKey())
	}

	model.OK(c, gin.H{
		"users":     users,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// UpdateUserStatus 更新用户状态 (管理员)
func UpdateUserStatus(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Status int `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		model.Fail(c, model.ErrParamInvalid)
		return
	}

	if req.Status != 0 && req.Status != 1 {
		model.FailMsg(c, model.ErrParamInvalid, "状态值必须为 0 或 1")
		return
	}

	result := model.GetDB().Model(&model.User{}).Where("id = ?", userID).Update("status", req.Status)
	if result.Error != nil {
		model.Fail(c, model.ErrDBError)
		return
	}

	if result.RowsAffected == 0 {
		model.Fail(c, model.ErrNotFound)
		return
	}

	model.OKEmpty(c)
}

// GetLoginLogs 获取登录日志 (管理员)
func GetLoginLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	userID := c.Query("user_id")
	status := c.Query("status")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	query := model.GetDB().Model(&model.LoginLog{})

	if userID != "" {
		query = query.Where("user_id = ?", userID)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	var logs []model.LoginLog

	query.Count(&total)
	query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&logs)

	model.OK(c, gin.H{
		"logs":      logs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetKeyStats 获取密钥统计信息 (管理员)
func GetKeyStats(c *gin.Context) {
	keyStore := keystore.GetKeyStore()
	stats := keyStore.GetKeyStats()

	model.OK(c, stats)
}

// CreateUser 创建新用户 (管理员)
func CreateUser(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		model.Fail(c, model.ErrParamInvalid)
		return
	}

	// 验证时间戳防重放（5 分钟窗口）
	now := time.Now().Unix()
	if now-req.Timestamp > 300 {
		model.Fail(c, model.ErrRequestExpired)
		return
	}

	// 获取 RSA 私钥
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

	// 解析创建用户 payload
	var payload model.CreateUserPayload
	if err := json.Unmarshal(decryptedData, &payload); err != nil {
		model.Fail(c, model.ErrDataFormat)
		return
	}

	// 调用创建用户服务（包含 role 参数，支持创建管理员）
	authService := service.GetAuthService()
	user, err := authService.CreateUser(payload.Username, payload.Password, payload.Phone, payload.Nickname, payload.Role)
	if err != nil {
		if errors.Is(err, service.ErrUsernameAlreadyExists) {
			model.Fail(c, model.ErrUsernameExists)
			return
		}
		model.FailMsg(c, model.ErrParamInvalid, err.Error())
		return
	}

	model.OK(c, gin.H{
		"id":         user.ID,
		"username":   user.Username,
		"created_at": user.CreatedAt,
	})
}

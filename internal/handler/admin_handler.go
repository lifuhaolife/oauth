package handler

import (
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"net/http"
	"strconv"

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

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "获取成功",
		Data: gin.H{
			"users":     users,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// UpdateUserStatus 更新用户状态 (管理员)
func UpdateUserStatus(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Status int `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "请求参数错误",
			Error:   err.Error(),
		})
		return
	}

	if req.Status != 0 && req.Status != 1 {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    400,
			Message: "状态值必须为 0 或 1",
		})
		return
	}

	result := model.GetDB().Model(&model.User{}).Where("id = ?", userID).Update("status", req.Status)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Code:    500,
			Message: "更新失败",
			Error:   result.Error.Error(),
		})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, model.ErrorResponse{
			Code:    404,
			Message: "用户不存在",
		})
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "更新成功",
	})
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

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "获取成功",
		Data: gin.H{
			"logs":      logs,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// GetKeyStats 获取密钥统计信息 (管理员)
func GetKeyStats(c *gin.Context) {
	keyStore := keystore.GetKeyStore()
	stats := keyStore.GetKeyStats()

	c.JSON(http.StatusOK, model.Response{
		Code:    200,
		Message: "获取成功",
		Data:    stats,
	})
}

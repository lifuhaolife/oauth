package model

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrCode 业务错误码
type ErrCode int

const (
	// 成功
	ErrOK ErrCode = 0

	// 参数类错误 1xxxx
	ErrParamInvalid  ErrCode = 10001 // 参数错误
	ErrDataFormat    ErrCode = 10002 // 数据格式错误

	// 密钥/加密类错误 2xxxx
	ErrKeyInvalid     ErrCode = 20001 // 密钥无效或已使用
	ErrDecryptFail    ErrCode = 20002 // 解密失败
	ErrSigInvalid     ErrCode = 20003 // 签名验证失败
	ErrRequestExpired ErrCode = 20004 // 请求已过期

	// 认证/权限类错误 3xxxx
	ErrNoAuth       ErrCode = 30001 // 未认证
	ErrAuthFail     ErrCode = 30002 // 认证失败（用户名或密码错误）
	ErrUserDisabled ErrCode = 30003 // 用户已禁用
	ErrTokenInvalid ErrCode = 30004 // Token 无效
	ErrForbidden    ErrCode = 30005 // 权限不足

	ErrUsernameExists ErrCode = 30011 // 用户名已存在

	// 资源类错误 4xxxx
	ErrNotFound ErrCode = 40001 // 资源不存在

	// 限流/超时错误
	ErrTimeout   ErrCode = 40800 // 请求超时
	ErrRateLimit ErrCode = 42900 // 请求过于频繁

	// 服务器类错误 5xxxx
	ErrServerError ErrCode = 50001 // 服务器内部错误
	ErrDBError     ErrCode = 50002 // 数据库错误
	ErrPubKeyFail  ErrCode = 50003 // 获取公钥失败
)

// errMessages 错误码默认消息
var errMessages = map[ErrCode]string{
	ErrOK:             "成功",
	ErrParamInvalid:   "请求参数错误",
	ErrDataFormat:     "数据格式错误",
	ErrKeyInvalid:     "密钥无效或已使用",
	ErrDecryptFail:    "解密失败",
	ErrSigInvalid:     "签名验证失败",
	ErrRequestExpired: "请求已过期",
	ErrNoAuth:         "未认证",
	ErrAuthFail:       "用户名或密码错误",
	ErrUserDisabled:   "用户已禁用",
	ErrTokenInvalid:   "Token 无效",
	ErrForbidden:      "权限不足",
	ErrUsernameExists: "用户名已存在",
	ErrNotFound:       "资源不存在",
	ErrTimeout:        "请求超时",
	ErrRateLimit:      "请求过于频繁，请稍后再试",
	ErrServerError:    "服务器内部错误",
	ErrDBError:        "数据库错误",
	ErrPubKeyFail:     "获取公钥失败",
}

// errHTTPStatus 错误码映射到 HTTP 状态码
func errHTTPStatus(code ErrCode) int {
	switch {
	case code == ErrOK:
		return http.StatusOK
	case code == ErrNoAuth || code == ErrAuthFail || code == ErrTokenInvalid:
		return http.StatusUnauthorized
	case code == ErrForbidden:
		return http.StatusForbidden
	case code == ErrNotFound:
		return http.StatusNotFound
	case code == ErrTimeout:
		return http.StatusRequestTimeout
	case code == ErrRateLimit:
		return http.StatusTooManyRequests
	case code >= 50000:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// APIResponse 统一 API 响应结构
type APIResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data,omitempty"`
}

// OK 成功响应（带数据）
func OK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Code: int(ErrOK),
		Msg:  errMessages[ErrOK],
		Data: data,
	})
}

// OKEmpty 成功响应（无数据）
func OKEmpty(c *gin.Context) {
	c.JSON(http.StatusOK, APIResponse{
		Code: int(ErrOK),
		Msg:  errMessages[ErrOK],
	})
}

// Fail 失败响应（使用预设消息）
func Fail(c *gin.Context, code ErrCode) {
	c.JSON(errHTTPStatus(code), APIResponse{
		Code: int(code),
		Msg:  errMessages[code],
	})
}

// FailMsg 失败响应（自定义消息）
func FailMsg(c *gin.Context, code ErrCode, msg string) {
	c.JSON(errHTTPStatus(code), APIResponse{
		Code: int(code),
		Msg:  msg,
	})
}

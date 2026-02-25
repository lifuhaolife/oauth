# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 概述

Go + Gin 鉴权管理后端服务，核心特性：
- RSA 动态密钥池（一次一密，使用后销毁）
- JWT RS256 非对称加密签名
- BCrypt 密码哈希 + AES-GCM 敏感数据加密
- 微信登录（预留接口，配置后启用）

## 统一 API 响应格式（强制规范）

> **这是硬性约束，不可绕过。** 所有新增或修改的接口，在代码审查时必须通过以下规范检查，否则视为不合格实现。完整规范见 `.claude/commands/api-spec.md`，可通过 `/api-spec` 快速查阅。

**所有接口（含健康检查）必须使用此格式**，唯一例外是 `/.well-known/jwks.json`（遵循 RFC 7517 标准）。

```json
// 成功（带数据）
{ "code": 0, "msg": "成功", "data": { ... } }

// 成功（无数据）
{ "code": 0, "msg": "成功" }

// 失败
{ "code": 30002, "msg": "用户名或密码错误" }
```
### 微信登录
在 `internal/service/auth_service.go` 的 `WechatLogin` 方法中实现微信 API 调用。

###API文档更新
当新增了接口之后、需要刷新API文档，修改接口之后，也需要更新接口文档API.MD

---

## 路由鉴权全表（权威参考）

> 来源：`cmd/server/main.go` + `internal/middleware/middleware.go`，每次新增/修改路由必须同步更新此表。

### 无需鉴权（公开访问）

| 方法 | 路径 | Handler | 说明 |
|------|------|---------|------|
| GET | `/health` | inline | 健康检查 |
| GET | `/.well-known/jwks.json` | `GetJWKS` | JWT 验签公钥（RFC 7517，格式例外不走统一响应） |
| GET | `/api/v1/auth/pubkey` | `GetRSAPublicKey` | 获取 RSA 登录加密公钥（一次一密） |
| POST | `/api/v1/auth/login` | `Login` | 密码登录，RSA 加密传输 |
| POST | `/api/v1/auth/refresh` | `RefreshToken` | 用 refresh token 换新 token 对 |
| GET | `/api/v1/auth/wechat/url` | `GetWechatAuthURL` | 获取微信授权跳转 URL（预留） |
| GET | `/api/v1/auth/wechat/callback` | `WechatCallback` | 微信登录回调（预留） |

### 需要用户鉴权（AuthMiddleware：Bearer access token）

| 方法 | 路径 | Handler | 说明 |
|------|------|---------|------|
| POST | `/api/v1/auth/logout` | `Logout` | 登出，将 access token 加入黑名单 |
| GET | `/api/v1/user/me` | `GetCurrentUser` | 获取当前用户信息 |
| PUT | `/api/v1/user/password` | `ChangePassword` | 修改密码 |

### 需要管理员鉴权（AuthMiddleware + AdminMiddleware）

| 方法 | 路径 | Handler | 说明 |
|------|------|---------|------|
| GET | `/api/v1/admin/users` | `ListUsers` | 分页获取用户列表 |
| POST | `/api/v1/admin/users/create` | `CreateUser` | 创建新用户（RSA 加密传输），支持指定 role: "user" 或 "admin" |
| PUT | `/api/v1/admin/users/:id/status` | `UpdateUserStatus` | 启用/禁用用户 |
| GET | `/api/v1/admin/login-logs` | `GetLoginLogs` | 查询登录日志 |
| GET | `/api/v1/admin/keys/stats` | `GetKeyStats` | 查询密钥池统计 |

### 中间件实现说明

- **AuthMiddleware**（`internal/middleware/middleware.go:199`）：从 `Authorization: Bearer <token>` 提取 token，调用 `ValidateToken` 验证签名和黑名单，将 `user_id`/`username` 写入 gin.Context。
- **AdminMiddleware**（`internal/middleware/middleware.go:260`）：从数据库查询当前用户的 `role` 和 `status`，要求 `status == 1`（正常）且 `role == "admin"`（管理员）方可通过，否则返回 403 Forbidden。
- **全局中间件**（所有路由均经过）：`CORSMiddleware`（跨域）、`RateLimitMiddleware`（60次/分钟/IP，突发上限10）、`LogMiddleware`（请求日志）。

# 鉴权管理后端服务 API 文档

## 概述

Go + Gin 鉴权管理后端服务，核心特性：
- RSA 动态密钥池（一次一密，使用后销毁）
- JWT RS256 非对称加密签名
- BCrypt 密码哈希 + AES-GCM 敏感数据加密
- 微信登录（预留接口，配置后启用）

---

## 统一响应格式

**所有接口**（含健康检查）均使用以下格式，唯一例外是 `/.well-known/jwks.json`（遵循 RFC 7517 标准）。

```json
// 成功（带数据）
{ "code": 0, "msg": "成功", "data": { ... } }

// 成功（无数据）
{ "code": 0, "msg": "成功" }

// 失败
{ "code": 30002, "msg": "用户名或密码错误" }
```

### 错误码一览

| 错误码 | HTTP 状态 | 含义 |
|--------|-----------|------|
| 0 | 200 | 成功 |
| 10001 | 400 | 请求参数错误 |
| 10002 | 400 | 数据格式错误 |
| 20001 | 400 | 密钥无效或已使用 |
| 20002 | 400 | 解密失败 |
| 20003 | 400 | 签名验证失败 |
| 20004 | 400 | 请求已过期（时间戳超出5分钟）|
| 30001 | 401 | 未认证（缺少 Authorization 头）|
| 30002 | 401 | 认证失败（用户名或密码错误）|
| 30003 | 401 | 用户已禁用 |
| 30004 | 401 | Token 无效或已失效 |
| 30005 | 403 | 权限不足 |
| 30011 | 400 | 用户名已存在 |
| 40001 | 404 | 资源不存在 |
| 40800 | 408 | 请求超时（服务端处理超时30s）|
| 42900 | 429 | 请求过于频繁（超出限流阈值）|
| 50001 | 500 | 服务器内部错误 |
| 50002 | 500 | 数据库错误 |
| 50003 | 500 | 获取公钥失败 |

---

## 全局中间件

所有路由均经过以下中间件（按顺序）：

| 中间件 | 说明 |
|--------|------|
| RecoveryMiddleware | Panic 恢复，返回 50001 |
| TimeoutMiddleware | 30s 处理超时，超时返回 40800 |
| LogMiddleware | 请求日志（仅记录元数据，不打印请求体）|
| MonitorMiddleware | API 监控指标采集 |
| CORSMiddleware | 跨域，通过 `CORS_ALLOWED_ORIGINS` 环境变量配置允许的域 |
| RateLimitMiddleware | IP 限流：60次/分钟，突发上限10，超限返回 42900 |

---

## 路由鉴权说明

| 层级 | 附加中间件 | 适用路由 |
|------|-----------|---------|
| 公开 | 无 | `/health`, `/ready`, `/.well-known/jwks.json`, `/api/v1/auth/*` |
| 用户认证 | `AuthMiddleware` | `/api/v1/auth/logout`, `/api/v1/user/*` |
| 管理员 | `AuthMiddleware` + `AdminMiddleware` | `/api/v1/admin/*` |

`AuthMiddleware`：验证 Bearer Access Token（RS256 签名 → 类型为 access → 黑名单检查）。
`AdminMiddleware`：查询数据库 `users.role == "admin"` 且 `status == 1`。

---

## 接口详情

### 通用端点

#### 健康检查
```
GET /health
```
无需鉴权。返回服务运行状态及系统资源信息。

**响应示例**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "status": "healthy",
    "timestamp": 1740441600,
    "version": "1.0.0",
    "goroutines": 12,
    "cpu_count": 8,
    "cpu_usage": 2.5,
    "memory_total": 17179869184,
    "memory_used": 4294967296,
    "memory_usage": 25.0
  }
}
```

#### 就绪检查
```
GET /ready
```
无需鉴权。检查服务是否已就绪（含数据库连接测试）。

**响应示例**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "status": "ready",
    "timestamp": 1740441600,
    "database": "connected"
  }
}
```

**失败示例**（数据库未连接）：
```json
{ "code": 50002, "msg": "数据库连接异常" }
```

#### Prometheus 监控指标
```
GET /metrics
```
无需鉴权。返回 Prometheus 格式的监控指标。

#### JWT 公钥发现
```
GET /.well-known/jwks.json
```
遵循 RFC 7517 标准，**此接口格式例外**，不使用统一响应格式。

**响应示例**：
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "jwt-key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "<base64url-encoded-modulus>",
      "e": "<base64url-encoded-exponent>"
    }
  ]
}
```

---

### 认证接口 `/api/v1/auth`（无需鉴权）

#### 获取 RSA 登录加密公钥
```
GET /api/v1/auth/pubkey
```
每次调用返回密钥池中一个未使用的 RSA 公钥（一次一密，10 分钟过期）。

**响应示例**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "key_id": "a1b2c3d4e5f6...",
    "public_key": "<base64-encoded-PEM>"
  }
}
```

---

#### 用户登录
```
POST /api/v1/auth/login
```

**加密流程**：
1. 调用 `/api/v1/auth/pubkey` 获取 `key_id` 和 `public_key`
2. 将 `{"username": "...", "password": "..."}` 用 RSA PKCS#1 v1.5 公钥加密
3. 对加密后的数据进行 Base64 Standard 编码
4. 构造请求体提交

**请求体**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `key_id` | string | 是 | 公钥标识符 |
| `encrypted_data` | string | 是 | Base64 编码的 RSA 加密数据 |
| `timestamp` | int64 | 是 | Unix 时间戳（秒），5分钟内有效 |
| `nonce` | string | 是 | 随机字符串，同一 nonce+timestamp 只能使用一次 |
| `signature` | string | 否 | HMAC-SHA256 签名（可选，见安全说明）|

```json
{
  "key_id": "a1b2c3d4e5f6...",
  "encrypted_data": "<base64-encoded-RSA-ciphertext>",
  "timestamp": 1740441600,
  "nonce": "random-uuid-or-string",
  "signature": "<optional-hmac-hex>"
}
```

**成功响应**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "access_token": "<JWT>",
    "refresh_token": "<JWT>",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": {
      "id": 1,
      "username": "admin",
      "nickname": "管理员",
      "avatar": "",
      "phone": "138****8888",
      "role": "admin",
      "created_at": "2026-01-01T00:00:00Z"
    }
  }
}
```

**失败示例**：
```json
{ "code": 30002, "msg": "用户名或密码错误" }
{ "code": 20004, "msg": "请求已过期" }
{ "code": 20001, "msg": "密钥无效或已使用" }
{ "code": 20003, "msg": "签名验证失败" }
```

> **签名说明**：`signature` 为可选字段。若提供，服务端使用 MASTER_KEY 对 `"timestamp={ts}&nonce={nonce}&key_id={key_id}"` 计算 HMAC-SHA256 并与之比对（hex 编码）。为空时跳过验证（向后兼容）。

---

#### 刷新 Token
```
POST /api/v1/auth/refresh
```

**请求体**：
```json
{
  "refresh_token": "<refresh-JWT>"
}
```

**成功响应**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "access_token": "<new-access-JWT>",
    "refresh_token": "<new-refresh-JWT>",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

**失败示例**：
```json
{ "code": 30004, "msg": "Token 无效" }
```

> Refresh Token 仅用于此接口，**不可**用于其他需要鉴权的接口（AuthMiddleware 会以 code 30004 拒绝）。

---

#### 获取微信授权 URL（预留）
```
GET /api/v1/auth/wechat/url
```
配置 `WECHAT_APP_ID` 和 `WECHAT_APP_SECRET` 环境变量后启用。

**响应**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "auth_url": "",
    "state": "",
    "expires_in": 0
  }
}
```

---

#### 微信登录回调（预留）
```
GET /api/v1/auth/wechat/callback?code=<code>&state=<state>
```
微信授权后跳转至此地址，服务端处理后重定向到前端页面。

---

### 用户接口 `/api/v1/user`（需要 Access Token）

所有请求需携带：
```
Authorization: Bearer <access_token>
```

#### 获取当前用户信息
```
GET /api/v1/user/me
```

**响应示例**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "id": 1,
    "username": "admin",
    "nickname": "管理员",
    "avatar": "",
    "phone": "138****8888",
    "role": "admin",
    "created_at": "2026-01-01T00:00:00Z",
    "last_login": "2026-02-25T00:00:00Z"
  }
}
```

---

#### 修改密码
```
PUT /api/v1/user/password
```

**密码强度要求**：至少 8 位，包含大写字母、小写字母和数字。

**请求体**：
```json
{
  "old_password": "OldPass@123",
  "new_password": "NewPass@456"
}
```

**成功响应**：
```json
{ "code": 0, "msg": "成功" }
```

**失败示例**：
```json
{ "code": 30002, "msg": "原密码错误" }
{ "code": 30002, "msg": "密码至少需要 8 位" }
{ "code": 30002, "msg": "密码必须包含大写字母、小写字母和数字" }
```

---

#### 用户登出
```
POST /api/v1/auth/logout
```
将当前 Access Token 加入黑名单（内存 + 数据库持久化）。服务重启后黑名单自动从数据库恢复。

**请求头**：
```
Authorization: Bearer <access_token>
```

**请求体**（`access_token` 为必填）：
```json
{
  "access_token": "<access-JWT>"
}
```

**成功响应**：
```json
{ "code": 0, "msg": "成功" }
```

---

### 管理员接口 `/api/v1/admin`（需要 admin 角色）

所有请求需携带：
```
Authorization: Bearer <admin_access_token>
```

`AdminMiddleware` 从数据库查询 `users.role == "admin"` 且 `users.status == 1`，不满足则返回 30005。

---

#### 获取用户列表
```
GET /api/v1/admin/users?page=1&page_size=20
```

**查询参数**：

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `page` | int | 1 | 页码（≥1）|
| `page_size` | int | 20 | 每页数量（1-100）|

**响应示例**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "users": [
      {
        "id": 1,
        "username": "admin",
        "nickname": "管理员",
        "avatar": "",
        "phone": "138****8888",
        "status": 1,
        "role": "admin",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-02-25T00:00:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 20
  }
}
```

---

#### 创建用户
```
POST /api/v1/admin/users/create
```
采用与登录相同的 RSA 加密传输方案，保护新用户的密码不在网络中明文传输。

**加密流程**：
1. 调用 `/api/v1/auth/pubkey` 获取公钥
2. 将 `{"username":"...","password":"...","phone":"...","nickname":"..."}` RSA 加密后 Base64 编码
3. 构造请求体提交

**请求体**：
```json
{
  "key_id": "a1b2c3d4e5f6...",
  "encrypted_data": "<base64-RSA-encrypted-payload>",
  "timestamp": 1740441600,
  "nonce": "unique-nonce"
}
```

加密前的明文 payload：
```json
{
  "username": "newuser",
  "password": "NewPass@123",
  "phone": "13800138000",
  "nickname": "新用户"
}
```

**密码强度要求**：至少 8 位，包含大写字母、小写字母和数字。
**用户名规则**：4-20 位，仅限字母、数字和下划线。

**成功响应**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "id": 2,
    "username": "newuser",
    "created_at": "2026-02-25T00:00:00Z"
  }
}
```

**失败示例**：
```json
{ "code": 30011, "msg": "用户名已存在" }
{ "code": 10001, "msg": "用户名长度必须在 4-20 位之间" }
{ "code": 10001, "msg": "密码必须包含大写字母、小写字母和数字" }
```

---

#### 更新用户状态
```
PUT /api/v1/admin/users/:id/status
```

**路径参数**：
- `:id`：用户 ID

**请求体**：
```json
{
  "status": 0
}
```

| 值 | 含义 |
|----|------|
| 0 | 禁用 |
| 1 | 启用 |

**成功响应**：
```json
{ "code": 0, "msg": "成功" }
```

**失败示例**：
```json
{ "code": 40001, "msg": "资源不存在" }
```

---

#### 查询登录日志
```
GET /api/v1/admin/login-logs?page=1&page_size=20
```

**查询参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `page` | int | 页码（默认 1）|
| `page_size` | int | 每页数量（默认 20，最大 100）|
| `user_id` | int | 过滤特定用户（可选）|
| `status` | int | 过滤状态：0=失败 1=成功（可选）|

**响应示例**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "logs": [
      {
        "id": 1,
        "user_id": 1,
        "login_type": "PASSWORD",
        "ip_address": "127.0.0.1",
        "user_agent": "Mozilla/5.0 ...",
        "status": 1,
        "fail_reason": "",
        "created_at": "2026-02-25T00:00:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 20
  }
}
```

> `login_type` 可选值：`PASSWORD`（密码登录）、`WECHAT`（微信登录）

---

#### 查询密钥池统计
```
GET /api/v1/admin/keys/stats
```

**响应示例**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "rsa_pool_active": 10,
    "rsa_pool_used": 3,
    "rsa_pool_total": 13,
    "aes_key_loaded": true,
    "jwt_key_loaded": true
  }
}
```

| 字段 | 说明 |
|------|------|
| `rsa_pool_active` | 当前可用（未使用且未过期）的 RSA 密钥数 |
| `rsa_pool_used` | 已使用的密钥数（等待清理）|
| `rsa_pool_total` | 密钥池总条目数 |
| `aes_key_loaded` | AES 主密钥是否已加载 |
| `jwt_key_loaded` | JWT 私钥是否已加载 |

---

## 安全特性说明

### RSA 一次一密
- 每对 RSA 密钥使用后立即从内存销毁
- 密钥池自动维护（保持 ≥10 个可用密钥），每 10 分钟轮换

### JWT Token
- Access Token 有效期：**15 分钟**
- Refresh Token 有效期：**7 天**
- 签名算法：**RS256**（非对称，私钥签名，公钥验证）
- AuthMiddleware 验证 Token 类型（`type == "access"`），Refresh Token 无法用于鉴权接口

### 黑名单机制
- 登出后 Access Token 立即加入内存黑名单 + 数据库持久化
- 服务重启时从数据库恢复未过期的黑名单记录
- 每 10 分钟自动清理内存中已过期的条目

### 防重放攻击
- **时间戳校验**：请求时间戳须在服务器时间 ±5 分钟内
- **Nonce 去重**：同一 `nonce + timestamp` 组合在 5 分钟内只能使用一次
- **请求签名**（可选）：HMAC-SHA256，使用 MASTER_KEY 对关键字段签名

### 密码安全
- 存储：BCrypt 哈希（cost=10）
- 强度要求：至少 8 位，包含大写字母、小写字母和数字

### 数据脱敏
- 手机号：仅返回脱敏格式（`138****8888`），原文 AES-256-GCM 加密存储
- 密码哈希：任何接口均不返回
- Token：黑名单存储 JTI，不存储原始 Token

### 限流
- **规则**：每 IP 每分钟 60 次，突发上限 10 次
- **超限返回**：`{ "code": 42900, "msg": "请求过于频繁，请稍后再试" }`
- **防 OOM**：超过 10 分钟不活跃的 IP 条目自动清理

### CORS
通过 `CORS_ALLOWED_ORIGINS` 环境变量配置允许的域（逗号分隔）：
- 未配置或值为 `*`：通配符模式（不携带 Credentials，符合 W3C 规范）
- 配置具体域名：精确匹配模式，匹配则允许携带 Credentials

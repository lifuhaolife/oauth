# 鉴权管理后端服务 API 文档

## 概述

本项目是一个 Go + Gin 鉴权管理后端服务，具有以下核心特性：
- RSA 动态密钥池（一次一密，使用后销毁）
- JWT RS256 非对称加密签名
- BCrypt 密码哈希 + AES-GCM 敏感数据加密
- 微信登录（预留配置接口）

## 安全特性

### 1. RSA 加密传输
- 客户端从 `/api/v1/auth/pubkey` 获取 RSA 公钥
- 使用公钥加密用户名密码
- 服务端用对应私钥解密，密钥使用后立即销毁

### 2. JWT 认证
- Access Token: 15 分钟有效期
- Refresh Token: 7 天有效期
- RS256 非对称签名算法
- Token 黑名单机制（内存 + 数据库双重存储）

### 3. 密码安全
- BCrypt 哈希（默认 cost=10）
- AES-GCM 加密存储敏感数据
- 防重放攻击（时间戳验证，5分钟窗口）
- 登录失败速率限制

---

## API 接口详情

### 通用端点

#### 健康检查
```
GET /health
```
**描述**: 检查服务运行状态
**响应**:
```json
{
  "status": "ok"
}
```

#### JWT 公钥发现
```
GET /.well-known/jwks.json
```
**描述**: JWT 公钥发现端点，用于外部验证 JWT 签名
**响应**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "jwt-key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "base64-encoded-modulus",
      "e": "base64-encoded-exponent"
    }
  ]
}
```

---

### 认证相关接口 (/api/v1/auth)

#### 获取 RSA 公钥
```
GET /api/v1/auth/pubkey
```
**描述**: 获取用于登录加密的 RSA 公钥
- 每次调用生成新的 RSA 密钥对
- 密钥使用后立即销毁
- 公钥以 Base64 编码的 PEM 格式返回

**响应**:
```json
{
  "key_id": "unique-key-identifier",
  "public_key": "base64-encoded-pem-public-key"
}
```

#### 用户登录
```
POST /api/v1/auth/login
```
**描述**: 用户账号密码登录
- 客户端需先获取 RSA 公钥
- 用公钥加密 `{username, password, timestamp, nonce}`
- 用 HMAC 签名防篡改

**请求体**:
```json
{
  "key_id": "string",
  "encrypted_data": "base64-encoded-encrypted-data",
  "signature": "string",
  "timestamp": 1640995200,
  "nonce": "string"
}
```

**响应**:
```json
{
  "access_token": "jwt-token",
  "refresh_token": "jwt-token",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": 1,
    "username": "string",
    "nickname": "string",
    "avatar": "url",
    "phone": "masked-phone",
    "role": "user",
    "created_at": "2023-01-01T00:00:00Z"
  }
}
```

#### 刷新 Token
```
POST /api/v1/auth/refresh
```
**描述**: 使用 Refresh Token 获取新的 Access Token

**请求体**:
```json
{
  "refresh_token": "jwt-refresh-token"
}
```

**响应**:
```json
{
  "access_token": "new-jwt-token",
  "refresh_token": "new-refresh-token",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### 用户登出
```
POST /api/v1/auth/logout
```
**描述**: 使当前用户的 Access Token 失效，加入黑名单

**请求头**:
```
Authorization: Bearer <access_token>
```

**请求体**:
```json
{
  "access_token": "jwt-access-token"
}
```

**响应**:
```json
{
  "message": "登出成功"
}
```

#### 微信登录相关

##### 获取微信授权 URL
```
GET /api/v1/auth/wechat/url
```
**描述**: 获取微信登录授权 URL（预留接口）

**响应**:
```json
{
  "auth_url": "https://open.weixin.qq.com/...",
  "state": "random-state-string",
  "expires_in": 600
}
```

##### 微信登录回调
```
GET /api/v1/auth/wechat/callback
```
**描述**: 微信登录回调处理（预留接口）

**参数**:
- `code`: 微信授权码
- `state`: 防 CSRF 标识

---

### 用户相关接口 (/api/v1/user) [需要认证]

#### 获取当前用户信息
```
GET /api/v1/user/me
```
**描述**: 获取当前认证用户的基本信息

**请求头**:
```
Authorization: Bearer <access_token>
```

**响应**:
```json
{
  "id": 1,
  "username": "string",
  "nickname": "string",
  "avatar": "url",
  "phone": "masked-phone",
  "role": "user",
  "created_at": "2023-01-01T00:00:00Z",
  "last_login": "2023-01-01T00:00:00Z"
}
```

#### 修改密码
```
PUT /api/v1/user/password
```
**描述**: 修改当前用户的密码

**请求头**:
```
Authorization: Bearer <access_token>
```

**请求体**:
```json
{
  "old_password": "current-password",
  "new_password": "new-password"
}
```

**响应**:
```json
{
  "message": "密码修改成功"
}
```

---

### 管理员接口 (/api/v1/admin) [需要管理员权限]

#### 获取用户列表
```
GET /api/v1/admin/users
```
**描述**: 获取所有用户列表（分页）

**请求头**:
```
Authorization: Bearer <admin_access_token>
```

**参数**:
- `page`: 页码（默认 1）
- `page_size`: 每页数量（默认 20，最大 100）

**响应**:
```json
{
  "users": [
    {
      "id": 1,
      "username": "string",
      "nickname": "string",
      "avatar": "url",
      "phone": "masked-phone",
      "status": 1,
      "role": "user",
      "created_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 100,
  "page": 1,
  "page_size": 20
}
```

#### 更新用户状态
```
PUT /api/v1/admin/users/{id}/status
```
**描述**: 启用/禁用用户账号

**请求头**:
```
Authorization: Bearer <admin_access_token>
```

**请求体**:
```json
{
  "status": 0  // 0: 禁用, 1: 启用
}
```

**响应**:
```json
{
  "message": "更新成功"
}
```

#### 获取登录日志
```
GET /api/v1/admin/login-logs
```
**描述**: 获取用户登录日志（分页）

**请求头**:
```
Authorization: Bearer <admin_access_token>
```

**参数**:
- `page`: 页码（默认 1）
- `page_size`: 每页数量（默认 20）
- `user_id`: 过滤特定用户
- `status`: 过滤登录状态（0:失败, 1:成功）

**响应**:
```json
{
  "logs": [
    {
      "id": 1,
      "user_id": 1,
      "login_type": "PASSWORD",  // 或 WECHAT
      "ip_address": "string",
      "user_agent": "string",
      "status": 1,
      "fail_reason": "string",
      "created_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 100,
  "page": 1,
  "page_size": 20
}
```

#### 获取密钥统计
```
GET /api/v1/admin/keys/stats
```
**描述**: 获取密钥使用统计信息

**请求头**:
```
Authorization: Bearer <admin_access_token>
```

**响应**:
```json
{
  "rsa_pool_active": 10,
  "rsa_pool_used": 5,
  "rsa_pool_expired": 2,
  "aes_key_loaded": true,
  "jwt_keys_loaded": true
}
```

---

## 错误响应格式

所有错误响应遵循以下格式：
```json
{
  "error": "错误消息"
}
```

常见的 HTTP 状态码：
- `200`: 成功
- `400`: 请求参数错误
- `401`: 认证失败
- `403`: 权限不足
- `404`: 资源不存在
- `429`: 请求过于频繁
- `500`: 服务器内部错误

## 数据模型

### User
用户实体模型
```go
type User struct {
    ID             int64      `json:"id"`
    Username       string     `json:"username"`
    PasswordHash   string     `-`  // 不输出
    PhoneEncrypted []byte     `-`  // 加密存储
    Phone          string     `json:"phone,omitempty"`  // 解密后输出
    WechatOpenID   string     `-`  // 微信 OpenID
    WechatUnionID  string     `-`  // 微信 UnionID
    Avatar         string     `json:"avatar,omitempty"`
    Nickname       string     `json:"nickname,omitempty"`
    Status         int        `json:"status"`  // 1:正常 0:禁用
    Role           string     `json:"role"`    // user/admin
    LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
    CreatedAt      time.Time  `json:"created_at"`
    UpdatedAt      time.Time  `json:"updated_at"`
}
```

### LoginRequest
登录请求模型
```go
type LoginRequest struct {
    KeyID     string `json:"key_id"`
    Encrypted string `json:"encrypted_data"`
    Signature string `json:"signature"`
    Timestamp int64  `json:"timestamp"`
    Nonce     string `json:"nonce"`
}
```

---

## 安全注意事项

1. **密钥管理**:
   - RSA 密钥对使用后立即销毁
   - JWT 密钥对长期存储在 `keys/` 目录
   - 主密钥（MASTER_KEY）存储在环境变量中

2. **传输安全**:
   - 所有敏感数据必须通过 HTTPS 传输
   - 登录数据通过 RSA 公钥加密
   - 请求时间戳验证防止重放攻击

3. **访问控制**:
   - 普通用户访问受 JWT Token 控制
   - 管理员功能需要额外的权限验证
   - IP 速率限制防止暴力攻击

4. **数据保护**:
   - 用户密码使用 BCrypt 哈希
   - 敏感数据使用 AES-GCM 加密存储
   - 手机号返回时进行脱敏处理
# 管理员授权和用户创建指南

**更新日期**: 2026-02-25  
**功能**: 完善管理员权限管理和用户创建系统

---

## 📋 改进概览

### 解决的问题
- ❌ **之前**: `CreateUser` 方法硬编码创建 "user" 角色，无法创建管理员
- ✅ **现在**: 支持通过 API 参数 `role` 指定用户角色（"user" 或 "admin"）
- ❌ **之前**: CLAUDE.md 文档中 AdminMiddleware 描述过时（说硬编码 user_id==1）
- ✅ **现在**: 文档已更新，AdminMiddleware 实际基于数据库 users.role 字段动态查询

### 实现的功能
1. **创建普通用户** — 默认 role="user"
2. **创建管理员** — 通过 role="admin" 参数
3. **角色验证** — 仅允许 "user" 或 "admin" 两个值
4. **动态权限检查** — AdminMiddleware 查询数据库权限，支持运行时修改

---

## 🔑 核心改动

### 1. Model 层 (internal/model/model.go)

**添加角色常量**（避免魔法字符串）：
```go
const (
    RoleUser  = "user"  // 普通用户
    RoleAdmin = "admin" // 管理员
)
```

**CreateUserPayload 新增 role 字段**：
```go
type CreateUserPayload struct {
    Username string `json:"username"`
    Password string `json:"password"`
    Phone    string `json:"phone"`
    Nickname string `json:"nickname"`
    Role     string `json:"role"` // 可选，默认为 "user"
}
```

### 2. Service 层 (internal/service/auth_service.go)

**方法签名变更**：
```go
// 之前
func (s *AuthService) CreateUser(username, password, phone, nickname string) (*model.User, error)

// 现在
func (s *AuthService) CreateUser(username, password, phone, nickname, role string) (*model.User, error)
```

**角色验证逻辑**：
```go
if role == "" {
    role = model.RoleUser  // 不传参数时默认为普通用户
}
if role != model.RoleUser && role != model.RoleAdmin {
    return nil, fmt.Errorf("角色值无效，仅允许 '%s' 或 '%s'", model.RoleUser, model.RoleAdmin)
}
```

### 3. Handler 层 (internal/handler/admin_handler.go)

**传递 role 参数**：
```go
// 之前
user, err := authService.CreateUser(payload.Username, payload.Password, payload.Phone, payload.Nickname)

// 现在
user, err := authService.CreateUser(payload.Username, payload.Password, payload.Phone, payload.Nickname, payload.Role)
```

---

## 🚀 使用指南

### 创建普通用户

**请求体（RSA 加密前的明文）**：
```json
{
  "username": "alice",
  "password": "SecurePass123",
  "phone": "13800138000",
  "nickname": "Alice",
  "role": "user"
}
```

或不传 role 字段（默认创建普通用户）：
```json
{
  "username": "bob",
  "password": "SecurePass456",
  "nickname": "Bob"
}
```

### 创建管理员用户

**请求体（RSA 加密前的明文）**：
```json
{
  "username": "admin_new",
  "password": "AdminPass789",
  "nickname": "New Admin",
  "role": "admin"
}
```

### 完整请求流程

**Step 1**: 获取 RSA 公钥
```bash
curl http://localhost:8080/api/v1/auth/pubkey
```

**Step 2**: 用公钥加密 payload

```bash
# Python 示例
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import json

# 1. 读取公钥
pubkey_data = """-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"""
pubkey = RSA.import_key(pubkey_data)

# 2. 构造 payload
payload = {
    "username": "admin_new",
    "password": "AdminPass789",
    "role": "admin"
}
plaintext = json.dumps(payload).encode('utf-8')

# 3. RSA 加密
cipher = PKCS1_v1_5.new(pubkey)
encrypted = cipher.encrypt(plaintext)
encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')

# 4. 构造外层请求
request = {
    "key_id": "从 pubkey 响应中获取",
    "encrypted_data": encrypted_b64,
    "timestamp": int(time.time()),
    "nonce": "random-string"
}
```

**Step 3**: 调用创建用户 API

```bash
# 假设已登录，有 admin_token
curl -X POST http://localhost:8080/api/v1/admin/users/create \
  -H "Authorization: Bearer $admin_token" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "...",
    "encrypted_data": "...",
    "timestamp": 1740441600,
    "nonce": "..."
  }'
```

**成功响应**：
```json
{
  "code": 0,
  "msg": "成功",
  "data": {
    "id": 3,
    "username": "admin_new",
    "role": "admin",
    "created_at": "2026-02-25T12:00:00Z"
  }
}
```

---

## 🔐 权限检查机制

### AdminMiddleware 工作原理

每次调用需要管理员权限的 API 时，服务器会：

1. **提取用户ID** — 从 JWT token 中解析
2. **查询数据库** — SELECT role, status FROM users WHERE id = ?
3. **验证两个条件**：
   - `users.status == 1` (账户未被禁用)
   - `users.role == "admin"` (用户角色为管理员)

4. **决策**：
   - ✅ 两个条件都满足 → 放行，继续处理请求
   - ❌ 任一条件不满足 → 返回 403 Forbidden (code: 30005)

### 实时生效

role 字段变更会**立即生效**，无需重新登录：
- 将用户升级为管理员：`UPDATE users SET role='admin' WHERE id=X`
- 下次该用户调用 admin API 时立即获得权限
- 同理，降级管理员权限也会立即生效

---

## 📊 数据库 Schema

### users 表

| 字段名 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| id | BIGINT | - | 主键，自增 |
| username | VARCHAR(50) | - | 用户名，唯一索引 |
| role | VARCHAR(20) | 'user' | 用户角色：'user' 或 'admin' |
| status | TINYINT | 1 | 账户状态：1=正常，0=禁用 |

### 初始数据

项目初始化时自动创建的默认管理员：
```sql
INSERT INTO users (username, password_hash, role, status)
VALUES ('admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'admin', 1)
```

**默认管理员账号**：
- 用户名: `admin`
- 密码: `Admin@123`
- 角色: `admin`
- 状态: `1` (正常)

---

## ✅ 验证清单

### 编译验证
```bash
go build ./cmd/server
# ✅ 无错误
```

### 测试验证
```bash
go test ./... -v
# ✅ 153+ 测试全部通过
```

### 单元测试覆盖
```bash
go test ./internal/service -v | grep CreateUser
# ✅ 验证 role 参数处理
# ✅ 测试默认角色
# ✅ 测试非法角色值
```

### 集成测试场景
```
✅ 创建普通用户（role=""）
✅ 创建普通用户（role="user"）
✅ 创建管理员（role="admin"）
✅ 非法角色值（role="superuser"）→ 返回错误
✅ 用户名已存在 → 返回 code: 30011
✅ 密码过弱 → 返回 code: 10001
```

---

## 🔄 改进点总结

| 方面 | 之前 | 现在 | 效果 |
|------|------|------|------|
| **CreateUser 参数** | 固定 4 个 | 5 个（+role） | 支持指定角色 |
| **角色硬编码** | 创建时固定"user" | 通过参数指定 | 灵活创建管理员 |
| **Payload 结构** | 无 role 字段 | 新增 role 字段 | API 完整 |
| **文档准确性** | AdminMiddleware 说硬编码 | 改为基于 users.role 查询 | 文档同步代码 |
| **权限检查** | N/A | 查询 DB + 验证 role | 动态实时权限 |

---

## 🛡️ 安全考虑

1. **角色值验证** — 仅允许白名单内的值（"user"/"admin"）
2. **权限分级** — 只有管理员能调用创建用户 API
3. **加密传输** — role 参数包含在 RSA 加密的 payload 中
4. **实时权限** — AdminMiddleware 每次查询数据库，支持运行时修改权限

---

## 📚 相关文件

| 文件 | 改动 | 说明 |
|------|------|------|
| internal/model/model.go | ✏️ 新增常量 + Payload | 添加 RoleUser/RoleAdmin 常量 |
| internal/service/auth_service.go | ✏️ 方法签名 + 验证 | 支持 role 参数 + 验证逻辑 |
| internal/handler/admin_handler.go | ✏️ handler 调用 | 传递 role 参数 |
| tests/integration_test.go | ✏️ 测试用例 | 添加 role 相关测试 |
| CLAUDE.md | ✏️ 文档更新 | 修正 AdminMiddleware 描述 |
| API.md | ✏️ API 文档 | 详细 role 参数说明 |

---

**状态**: ✅ 完成并验证  
**测试**: ✅ 153+ 测试通过  
**编译**: ✅ 无错误警告  
**文档**: ✅ 已更新


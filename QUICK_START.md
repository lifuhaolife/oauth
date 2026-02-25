# 快速开始指南

## 项目启动

```bash
cd /d/Users/lenovo/ClaudeCodes/oauth
go run ./cmd/server
```

服务会监听 `http://localhost:8080`

## 默认管理员账号

- **用户名**: `admin`
- **密码**: `Admin@123`

## 创建新用户的完整流程

### 1️⃣ 用管理员登录

```bash
# 获取 RSA 公钥
curl http://localhost:8080/api/v1/auth/pubkey

# 用公钥加密密码，发送登录请求
# ... (RSA 加密过程)

# 得到 access_token 和 refresh_token
```

### 2️⃣ 创建普通用户

使用 access token 调用创建用户 API：

```bash
curl -X POST http://localhost:8080/api/v1/admin/users/create \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "...",
    "encrypted_data": "<RSA加密的payload>",
    "timestamp": 1740441600,
    "nonce": "unique-nonce"
  }'
```

RSA 加密前的明文 payload：
```json
{
  "username": "alice",
  "password": "SecurePass123",
  "phone": "13800138000",
  "nickname": "Alice",
  "role": "user"
}
```

### 3️⃣ 创建管理员用户

只需改变 `role` 字段：

```json
{
  "username": "admin_new",
  "password": "AdminPass789",
  "nickname": "New Admin",
  "role": "admin"
}
```

## 重要概念

### Role（角色）字段

| 值 | 含义 | 权限 |
|----|------|------|
| `"user"` | 普通用户 | 只能访问 `/api/v1/user/*` 端点（个人相关） |
| `"admin"` | 管理员 | 可访问 `/api/v1/admin/*` 端点（管理功能） |

### AdminMiddleware 权限检查

每次调用 admin API 时，中间件会查询数据库验证：
- `users.role == "admin"` ✓
- `users.status == 1` ✓

**特点**: role 变更**立即生效**，无需重新登录

## 运行测试

```bash
# 全部测试
go test ./... -v

# 仅 service 层测试
go test ./internal/service -v

# 仅 integration 测试（需要 MySQL）
go test ./tests -v
```

## 文件映射

| 文件 | 功能 | 何时修改 |
|------|------|----------|
| `internal/model/model.go` | 数据模型、Role 常量 | 新增数据字段 |
| `internal/service/auth_service.go` | 业务逻辑、CreateUser | 实现新功能 |
| `internal/handler/admin_handler.go` | API 端点处理 | 新增/修改 API |
| `tests/integration_test.go` | 集成测试 | 添加测试用例 |
| `CLAUDE.md` | 项目规范文档 | 文档更新 |
| `API.md` | API 文档 | API 变更 |

## 常见错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `code: 30005` (权限不足) | 不是管理员或账户被禁用 | 检查 users.role 和 users.status |
| `code: 30011` (用户名已存在) | 用户名重复 | 使用不同的用户名 |
| `code: 10001` (参数错误) | role 值非法 | 仅使用 "user" 或 "admin" |

## 调试技巧

### 查看用户信息（包含 role）

```bash
curl -X GET http://localhost:8080/api/v1/user/me \
  -H "Authorization: Bearer <token>"
```

### 直接修改数据库（仅调试）

```sql
-- 升级为管理员
UPDATE users SET role='admin' WHERE username='alice';

-- 降级为普通用户
UPDATE users SET role='user' WHERE username='admin_new';

-- 禁用账户
UPDATE users SET status=0 WHERE username='alice';
```

## 更多信息

- 📖 完整使用指南: [ADMIN_AUTHORIZATION_GUIDE.md](./ADMIN_AUTHORIZATION_GUIDE.md)
- 📖 API 文档: [API.md](./API.md)
- 📖 项目规范: [CLAUDE.md](./CLAUDE.md)

---

**最后更新**: 2026-02-25  
**项目状态**: ✅ 就绪

# 异构项目集成指南

本文档说明如何在 Python、Java 等项目中接入本认证服务进行 JWT 鉴权。

---

## 认证流程说明

本服务基于 **JWT RS256 非对称签名**，集成方只需：

1. 启动时从 `/.well-known/jwks.json` 获取 RSA 公钥并本地缓存
2. 每次请求到达时，用公钥在本地验证 JWT 签名和有效期
3. 从 JWT Claims 中提取用户信息用于业务逻辑

无需每次请求都联系认证服务，JWT 是自包含的。

---

## JWT Claims 字段

集成方验证的是 **access token**（`type = "access"`）。

| 字段       | 类型       | 说明                                      |
|----------|----------|-------------------------------------------|
| `sub`    | string   | 用户 ID（对应 `users.id`）                 |
| `username` | string | 用户名                                    |
| `type`   | string   | `"access"` 或 `"refresh"`                |
| `scope`  | []string | `["read","write"]`（access）/ `["refresh"]`（refresh）|
| `iss`    | string   | `"auth-service"`                          |
| `jti`    | string   | JWT 唯一 ID（用于黑名单）                  |
| `exp`    | int64    | 过期时间戳（access: 15min，refresh: 7天） |
| `iat`    | int64    | 签发时间戳                                |

> **重要**：集成方只应接受 `type == "access"` 的 token，拒绝 refresh token 访问业务接口。

---

## Python 集成示例

```bash
pip install PyJWT cryptography requests
```

```python
import requests
from jwt import PyJWT, algorithms

# 步骤1：启动时获取公钥（缓存，无需每次请求都获取）
jwks = requests.get("http://auth-service:8082/.well-known/jwks.json").json()
public_key = algorithms.RSAAlgorithm.from_jwk(jwks["keys"][0])

# 步骤2：验证 access token
def verify_access_token(token: str) -> dict:
    payload = PyJWT().decode(
        token,
        public_key,
        algorithms=["RS256"],
        options={"require": ["exp", "sub", "type"]}
    )
    if payload.get("type") != "access":
        raise ValueError("不接受 refresh token")
    return payload  # {"sub": "1", "username": "admin", "scope": [...], ...}

# 步骤3：Flask 装饰器示例
from functools import wraps
from flask import request, jsonify, g

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"code": 30001, "msg": "未认证"}), 401
        try:
            g.user = verify_access_token(auth[7:])
        except Exception:
            return jsonify({"code": 30004, "msg": "Token 无效"}), 401
        return f(*args, **kwargs)
    return decorated

# 使用示例
@app.route("/profile")
@login_required
def profile():
    user_id = g.user["sub"]       # 用户 ID
    username = g.user["username"] # 用户名
    return jsonify({"id": user_id, "username": username})
```

---

## Java Spring Boot 集成示例

### 零代码配置方式（Spring Security OAuth2 Resource Server）

```yaml
# application.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://auth-service:8082/.well-known/jwks.json
```

```java
// SecurityConfig.java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter()))
            );
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtConverter() {
        // 从 JWT claims 中提取 scope 作为 GrantedAuthority
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthoritiesClaimName("scope");
        converter.setAuthorityPrefix("SCOPE_");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
        return jwtConverter;
    }
}
```

```java
// 在 Controller 中获取用户信息
@GetMapping("/profile")
public ResponseEntity<?> getProfile(@AuthenticationPrincipal Jwt jwt) {
    String userId   = jwt.getSubject();              // 用户 ID
    String username = jwt.getClaim("username");      // 用户名
    List<String> scope = jwt.getClaim("scope");      // 权限范围
    return ResponseEntity.ok(Map.of(
        "id", userId,
        "username", username,
        "scope", scope
    ));
}
```

### 附加校验：拒绝 refresh token

Spring Security 默认只校验签名和过期，需手动拦截 refresh token：

```java
@Component
public class TokenTypeValidator implements JwtAuthenticationConverter {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String tokenType = jwt.getClaim("type");
        if (!"access".equals(tokenType)) {
            throw new BadCredentialsException("不接受 refresh token");
        }
        // 继续正常转换...
        return super.convert(jwt);
    }
}
```

---

## 通用集成要点

1. **公钥缓存**：启动时获取一次 JWKS，本地缓存。建议每小时或服务重启时刷新一次。

2. **只验证 access token**：检查 `type == "access"`，明确拒绝 refresh token 用于 API 鉴权。

3. **本地验签，无需回调**：JWT 是自包含的，用公钥本地验证即可，正常请求链路中无需访问认证服务。

4. **用户 ID**：JWT `sub` 字段即为 `users.id`，可直接用于业务系统关联用户。

5. **权限**：`scope` 字段当前为 `["read","write"]`，业务方可根据需要扩展细粒度权限。

6. **Token 过期**：access token 有效期 15 分钟，refresh token 有效期 7 天。客户端负责用 refresh token 续期，集成方只需正常处理 401 响应（引导客户端刷新 token）。

---

## 接口地址参考

| 接口 | 方法 | 说明 |
|------|------|------|
| `/.well-known/jwks.json` | GET | 获取 JWT 验签公钥（JWKS 格式，RFC 7517）|
| `/api/v1/auth/pubkey` | GET | 获取 RSA 登录加密公钥（非 JWT 签名公钥）|
| `/api/v1/auth/login` | POST | 密码登录，返回 access/refresh token |
| `/api/v1/auth/refresh` | POST | 用 refresh token 换取新的 token 对 |
| `/api/v1/auth/logout` | POST | 登出，将 access token 加入黑名单 |
| `/api/v1/user/me` | GET | 获取当前用户信息（需 access token）|

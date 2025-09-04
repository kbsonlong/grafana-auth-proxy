# /auth 端点数据规范文档

## 1. 端点概述

### 1.1 /auth 端点的作用

`/auth` 端点是 Nginx `auth_request` 模块的核心认证验证端点，负责：

- **Token 验证**: 验证用户提供的 JWT Token 的有效性
- **用户信息提取**: 从有效 Token 中提取用户身份信息
- **认证状态返回**: 向 Nginx 返回认证结果和用户信息头部
- **访问控制**: 决定用户是否有权限访问受保护的资源

### 1.2 工作原理

```mermaid
sequenceDiagram
    participant U as 用户浏览器
    participant N as Nginx
    participant A as Auth Service (/auth)
    participant G as Grafana
    
    U->>N: 1. 请求 /grafana/dashboard
    N->>A: 2. auth_request 到 /auth
    A->>A: 3. 验证 JWT Token
    A->>N: 4. 返回认证结果+用户头部
    N->>G: 5. 转发请求+认证头部
    G->>U: 6. 返回 Grafana 页面
```

## 2. 请求数据格式规范

### 2.1 HTTP 方法
```
GET /auth
```

### 2.2 必需的请求头部

| 头部名称 | 类型 | 必需 | 描述 | 示例 |
|---------|------|------|------|------|
| `Cookie` | string | 是 | 包含 JWT Token 的 Cookie | `grafana_jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` |
| `X-Original-URI` | string | 是 | 原始请求的 URI | `/grafana/dashboard/db/test` |
| `X-Original-Method` | string | 是 | 原始请求的 HTTP 方法 | `GET` |
| `Host` | string | 是 | 请求的主机名 | `localhost` 或 `127.0.0.1` |

### 2.3 可选的请求头部

| 头部名称 | 类型 | 必需 | 描述 | 示例 |
|---------|------|------|------|------|
| `Authorization` | string | 否 | Bearer Token（备用认证方式） | `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` |
| `X-JWT-Token` | string | 否 | 从 Authorization 头部提取的 Token | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` |
| `X-Real-IP` | string | 否 | 客户端真实 IP 地址 | `192.168.1.100` |
| `X-Forwarded-For` | string | 否 | 代理链中的 IP 地址 | `192.168.1.100, 10.0.0.1` |

### 2.4 Token 提取优先级

认证服务按以下优先级提取 JWT Token：

1. **Cookie**: `grafana_jwt_token` Cookie 值
2. **Authorization Header**: `Authorization: Bearer <token>` 头部
3. **X-JWT-Token Header**: `X-JWT-Token` 头部值

### 2.5 完整请求示例

```http
GET /auth HTTP/1.1
Host: localhost
Cookie: grafana_jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwibmFtZSI6IkFkbWluIFVzZXIiLCJzdWIiOiJhZG1pbiIsImV4cCI6MTY0MDk5NTIwMCwiaWF0IjoxNjQwOTA4ODAwfQ.signature
X-Original-URI: /grafana/dashboard/db/test
X-Original-Method: GET
X-Real-IP: 192.168.1.100
X-Forwarded-For: 192.168.1.100
Content-Length: 0
```

## 3. 响应数据格式规范

### 3.1 成功响应 (200 OK)

#### 状态码
```
200 OK
```

#### 必需的响应头部

| 头部名称 | 类型 | 描述 | 示例 |
|---------|------|------|------|
| `X-WEBAUTH-USER` | string | 用户名（Grafana 用户标识） | `admin` |
| `X-WEBAUTH-NAME` | string | 用户显示名称 | `Admin User` |

#### 可选的响应头部

| 头部名称 | 类型 | 描述 | 示例 |
|---------|------|------|------|
| `X-Auth-Email` | string | 用户邮箱地址 | `admin@example.com` |
| `X-Auth-Role` | string | 用户角色 | `Admin` |
| `X-Auth-Groups` | string | 用户组（逗号分隔） | `admin,editor` |
| `Cache-Control` | string | 缓存控制 | `no-cache, no-store` |

#### 响应体
```
空响应体
```

#### 完整成功响应示例
```http
HTTP/1.1 200 OK
X-WEBAUTH-USER: admin
X-WEBAUTH-NAME: Admin User
X-Auth-Email: admin@example.com
X-Auth-Role: Admin
Cache-Control: no-cache, no-store
Content-Length: 0

```

### 3.2 认证失败响应 (401 Unauthorized)

#### 状态码
```
401 Unauthorized
```

#### 响应头部
```
Content-Type: text/plain
Cache-Control: no-cache, no-store
```

#### 响应体
```
Unauthorized
```

#### 完整失败响应示例
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/plain
Cache-Control: no-cache, no-store
Content-Length: 12

Unauthorized
```

### 3.3 服务器错误响应 (500 Internal Server Error)

#### 状态码
```
500 Internal Server Error
```

#### 响应头部
```
Content-Type: text/plain
```

#### 响应体
```
Internal Server Error
```

## 4. 认证流程中的数据传递规范

### 4.1 JWT Token 结构规范

#### Token Header
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

#### Token Payload (Claims)
```json
{
  "user_id": 1,
  "email": "admin@example.com",
  "name": "Admin User",
  "sub": "admin",
  "role": "Admin",
  "groups": ["admin", "editor"],
  "exp": 1640995200,
  "iat": 1640908800,
  "iss": "auth-service",
  "aud": "grafana"
}
```

#### 必需的 Claims

| Claim | 类型 | 描述 | 示例 |
|-------|------|------|------|
| `sub` | string | 用户唯一标识符 | `admin` |
| `name` | string | 用户显示名称 | `Admin User` |
| `exp` | number | Token 过期时间戳 | `1640995200` |
| `iat` | number | Token 签发时间戳 | `1640908800` |

#### 可选的 Claims

| Claim | 类型 | 描述 | 示例 |
|-------|------|------|------|
| `user_id` | number | 用户数据库 ID | `1` |
| `email` | string | 用户邮箱 | `admin@example.com` |
| `role` | string | 用户角色 | `Admin` |
| `groups` | array | 用户组列表 | `["admin", "editor"]` |
| `iss` | string | Token 签发者 | `auth-service` |
| `aud` | string | Token 受众 | `grafana` |

### 4.2 Cookie 设置规范

#### Cookie 属性
```go
cookie := &http.Cookie{
    Name:     "grafana_jwt_token",
    Value:    tokenString,
    Path:     "/",
    HttpOnly: false,  // 允许 JavaScript 访问（可选）
    Secure:   false,  // 生产环境应设为 true
    MaxAge:   86400,  // 24小时
    SameSite: http.SameSiteLaxMode,
}
```

#### Cookie 安全建议
- **生产环境**: 设置 `Secure: true` 和 `HttpOnly: true`
- **域名设置**: 根据需要设置 `Domain` 属性
- **过期时间**: 与 JWT Token 的 `exp` 保持一致

### 4.3 Nginx 变量映射

#### auth_request_set 配置
```nginx
auth_request_set $auth_user $upstream_http_x_webauth_user;
auth_request_set $auth_name $upstream_http_x_webauth_name;
auth_request_set $auth_email $upstream_http_x_auth_email;
auth_request_set $auth_role $upstream_http_x_auth_role;
```

#### proxy_set_header 配置
```nginx
proxy_set_header X-WEBAUTH-USER $auth_user;
proxy_set_header X-WEBAUTH-NAME $auth_name;
proxy_set_header X-WEBAUTH-EMAIL $auth_email;
proxy_set_header X-WEBAUTH-ROLE $auth_role;
```

## 5. 错误处理和状态码说明

### 5.1 状态码定义

| 状态码 | 含义 | 触发条件 | 处理方式 |
|--------|------|----------|----------|
| `200` | 认证成功 | Token 有效且未过期 | 继续处理请求 |
| `401` | 认证失败 | Token 无效、过期或缺失 | 重定向到登录页 |
| `403` | 权限不足 | Token 有效但权限不够 | 返回权限错误页 |
| `500` | 服务器错误 | 认证服务内部错误 | 返回错误页面 |

### 5.2 错误场景详解

#### 5.2.1 Token 缺失
**触发条件**: 请求中没有 `grafana_jwt_token` Cookie 且没有 `Authorization` 头部

**响应**:
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/plain

Token missing
```

#### 5.2.2 Token 格式错误
**触发条件**: Token 不是有效的 JWT 格式

**响应**:
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/plain

Invalid token format
```

#### 5.2.3 Token 签名验证失败
**触发条件**: Token 签名与服务器密钥不匹配

**响应**:
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/plain

Invalid token signature
```

#### 5.2.4 Token 已过期
**触发条件**: 当前时间超过 Token 的 `exp` 时间

**响应**:
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/plain

Token expired
```

#### 5.2.5 用户信息缺失
**触发条件**: Token 有效但缺少必需的用户信息 Claims

**响应**:
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/plain

Incomplete user information
```

### 5.3 错误日志格式

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "ERROR",
  "message": "Token validation failed",
  "error": "token expired",
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "original_uri": "/grafana/dashboard/db/test"
}
```

## 6. 实际请求响应示例

### 6.1 成功认证示例

#### 请求
```bash
curl -X GET "http://localhost/auth" \
  -H "Cookie: grafana_jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwibmFtZSI6IkFkbWluIFVzZXIiLCJzdWIiOiJhZG1pbiIsImV4cCI6MTY0MDk5NTIwMCwiaWF0IjoxNjQwOTA4ODAwfQ.signature" \
  -H "X-Original-URI: /grafana/dashboard/db/test" \
  -H "X-Original-Method: GET" \
  -v
```

#### 响应
```http
HTTP/1.1 200 OK
Server: nginx/1.21.6
Date: Mon, 15 Jan 2024 10:30:00 GMT
Content-Type: text/plain
Content-Length: 0
Connection: keep-alive
X-WEBAUTH-USER: admin
X-WEBAUTH-NAME: Admin User
X-Auth-Email: admin@example.com
X-Auth-Role: Admin
Cache-Control: no-cache, no-store
```

### 6.2 Token 过期示例

#### 请求
```bash
curl -X GET "http://localhost/auth" \
  -H "Cookie: grafana_jwt_token=expired_token_here" \
  -H "X-Original-URI: /grafana/dashboard/db/test" \
  -H "X-Original-Method: GET" \
  -v
```

#### 响应
```http
HTTP/1.1 401 Unauthorized
Server: nginx/1.21.6
Date: Mon, 15 Jan 2024 10:30:00 GMT
Content-Type: text/plain
Content-Length: 13
Connection: keep-alive
Cache-Control: no-cache, no-store

Token expired
```

### 6.3 Token 缺失示例

#### 请求
```bash
curl -X GET "http://localhost/auth" \
  -H "X-Original-URI: /grafana/dashboard/db/test" \
  -H "X-Original-Method: GET" \
  -v
```

#### 响应
```http
HTTP/1.1 401 Unauthorized
Server: nginx/1.21.6
Date: Mon, 15 Jan 2024 10:30:00 GMT
Content-Type: text/plain
Content-Length: 13
Connection: keep-alive
Cache-Control: no-cache, no-store

Token missing
```

### 6.4 使用 Authorization 头部示例

#### 请求
```bash
curl -X GET "http://localhost/auth" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwibmFtZSI6IkFkbWluIFVzZXIiLCJzdWIiOiJhZG1pbiIsImV4cCI6MTY0MDk5NTIwMCwiaWF0IjoxNjQwOTA4ODAwfQ.signature" \
  -H "X-Original-URI: /grafana/api/dashboards" \
  -H "X-Original-Method: GET" \
  -v
```

#### 响应
```http
HTTP/1.1 200 OK
Server: nginx/1.21.6
Date: Mon, 15 Jan 2024 10:30:00 GMT
Content-Type: text/plain
Content-Length: 0
Connection: keep-alive
X-WEBAUTH-USER: admin
X-WEBAUTH-NAME: Admin User
X-Auth-Email: admin@example.com
Cache-Control: no-cache, no-store
```

## 7. 与 Grafana 集成的头部映射规范

### 7.1 Grafana 代理认证配置

```ini
[auth.proxy]
# 启用代理认证
enabled = true

# 用户名头部映射
header_name = X-WEBAUTH-USER
header_property = username

# 用户显示名称头部映射
headers = Name:X-WEBAUTH-NAME Email:X-WEBAUTH-EMAIL Role:X-WEBAUTH-ROLE

# 自动创建用户
auto_sign_up = true

# 同步间隔（秒）
sync_ttl = 60

# 允许的代理 IP（安全设置）
whitelist = 127.0.0.1, ::1

# 启用角色同步
enable_login_token = false
```

### 7.2 头部映射关系

| 认证服务响应头部 | Grafana 配置项 | Grafana 用户属性 | 描述 |
|-----------------|---------------|-----------------|------|
| `X-WEBAUTH-USER` | `header_name` | `username` | 用户登录名（必需） |
| `X-WEBAUTH-NAME` | `headers = Name:X-WEBAUTH-NAME` | `display_name` | 用户显示名称 |
| `X-WEBAUTH-EMAIL` | `headers = Email:X-WEBAUTH-EMAIL` | `email` | 用户邮箱地址 |
| `X-WEBAUTH-ROLE` | `headers = Role:X-WEBAUTH-ROLE` | `role` | 用户角色 |

### 7.3 用户角色映射

#### 认证服务角色 → Grafana 角色

| 认证服务角色 | Grafana 角色 | 权限级别 |
|-------------|-------------|----------|
| `Admin` | `Admin` | 管理员权限 |
| `Editor` | `Editor` | 编辑权限 |
| `Viewer` | `Viewer` | 只读权限 |
| `Guest` | `Viewer` | 只读权限 |

#### 角色映射配置示例

```ini
[auth.proxy]
# 角色映射（可选）
role_attribute_path = role
role_attribute_strict = false

# 默认角色
default_role = Viewer
```

### 7.4 用户自动创建规则

当 `auto_sign_up = true` 时，Grafana 会根据以下规则自动创建用户：

1. **用户名**: 使用 `X-WEBAUTH-USER` 头部值
2. **显示名称**: 使用 `X-WEBAUTH-NAME` 头部值，如果为空则使用用户名
3. **邮箱**: 使用 `X-WEBAUTH-EMAIL` 头部值
4. **角色**: 使用 `X-WEBAUTH-ROLE` 头部值，如果为空则使用默认角色
5. **组织**: 自动加入默认组织

### 7.5 安全注意事项

#### 7.5.1 IP 白名单
```ini
# 只允许本地和代理服务器访问
whitelist = 127.0.0.1, ::1, 172.18.0.0/16
```

#### 7.5.2 头部验证
- Grafana 只接受来自白名单 IP 的代理认证请求
- 确保 Nginx 和认证服务在受信任的网络环境中
- 定期轮换 JWT 签名密钥

#### 7.5.3 用户同步
```ini
# 定期同步用户信息
sync_ttl = 60

# 禁用登录令牌（使用代理认证）
enable_login_token = false
```

## 8. 调试和监控

### 8.1 调试工具

#### 验证 Token 脚本
```bash
#!/bin/bash
# verify-token.sh

TOKEN="$1"
if [ -z "$TOKEN" ]; then
    echo "Usage: $0 <jwt_token>"
    exit 1
fi

echo "=== 验证 Token ==="
curl -s -w "HTTP Status: %{http_code}\n" \
  -H "Cookie: grafana_jwt_token=$TOKEN" \
  -H "X-Original-URI: /grafana/" \
  -H "X-Original-Method: GET" \
  http://localhost/auth
```

#### 完整认证流程测试
```bash
#!/bin/bash
# test-auth-flow.sh

echo "=== 1. 获取 Token ==="
RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  http://localhost/login)

TOKEN=$(echo $RESPONSE | jq -r '.token')
echo "Token: $TOKEN"

echo "\n=== 2. 验证 Token ==="
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -H "Cookie: grafana_jwt_token=$TOKEN" \
  -H "X-Original-URI: /grafana/" \
  -H "X-Original-Method: GET" \
  http://localhost/auth -v

echo "\n=== 3. 访问 Grafana ==="
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -H "Cookie: grafana_jwt_token=$TOKEN" \
  http://localhost/grafana/ -I
```

### 8.2 监控指标

#### Prometheus 指标示例
```
# 认证请求总数
auth_requests_total{status="success"} 1250
auth_requests_total{status="failed"} 45

# 认证响应时间
auth_request_duration_seconds{quantile="0.5"} 0.002
auth_request_duration_seconds{quantile="0.95"} 0.010
auth_request_duration_seconds{quantile="0.99"} 0.025

# Token 验证错误
auth_token_errors_total{error="expired"} 23
auth_token_errors_total{error="invalid"} 12
auth_token_errors_total{error="missing"} 8
```

#### 日志监控
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "message": "Authentication successful",
  "user": "admin",
  "client_ip": "192.168.1.100",
  "original_uri": "/grafana/dashboard/db/test",
  "response_time_ms": 5
}
```

## 9. 总结

本文档详细定义了 `/auth` 端点的数据规范，包括：

- **请求格式**: 明确了必需和可选的请求头部
- **响应格式**: 定义了成功和失败场景的响应结构
- **错误处理**: 详细说明了各种错误情况和处理方式
- **集成规范**: 提供了与 Grafana 集成的完整配置指南
- **调试工具**: 提供了实用的调试和监控方法

遵循本规范可以确保认证系统的标准化实现和可靠运行。
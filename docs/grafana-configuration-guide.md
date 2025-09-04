# Grafana 配置调整指引文档

## 项目概述

本项目实现了基于自定义认证服务的 Grafana 权限控制系统，通过 Nginx 反向代理和认证服务集成，实现了细粒度的 RBAC（基于角色的访问控制）权限管理。

### 配置目标

- 启用 Grafana 的代理认证模式
- 集成自定义认证服务进行用户验证
- 实现基于角色的权限控制（admin、editor、viewer）
- 支持细粒度权限管理（read、write、delete、export、admin）
- 确保 viewer 角色具有 export 功能权限

## Grafana 默认配置 vs 本项目配置对比

### [server] 部分

| 配置项 | 默认值 | 本项目配置 | 调整原因 |
|--------|--------|------------|----------|
| `root_url` | `%(protocol)s://%(domain)s:%(http_port)s/` | `http://localhost/grafana/` | 配置子路径访问，适配 Nginx 代理 |
| `serve_from_sub_path` | `false` | `true` | 启用子路径服务，支持 `/grafana/` 路径访问 |

### [auth] 部分

| 配置项 | 默认值 | 本项目配置 | 调整原因 |
|--------|--------|------------|----------|
| `disable_login_form` | `false` | `true` | 禁用内置登录表单，使用代理认证 |

### [auth.proxy] 部分

| 配置项 | 默认值 | 本项目配置 | 调整原因 |
|--------|--------|------------|----------|
| `enabled` | `false` | `true` | 启用代理认证模式 |
| `header_name` | `X-WEBAUTH-USER` | `X-WEBAUTH-USER` | 保持默认用户名头部 |
| `auto_sign_up` | `true` | `true` | 自动创建用户账户 |
| `headers` | 无 | `Name:X-WEBAUTH-NAME Email:X-WEBAUTH-EMAIL Role:X-WEBAUTH-ROLE Permissions:X-WEBAUTH-PERMISSIONS` | 映射自定义认证头部到用户属性 |
| `role_attribute_path` | 无 | `Role` | 指定角色属性路径 |
| `role_mapping` | 无 | `admin=Admin editor=Editor viewer=Viewer` | 映射自定义角色到 Grafana 内置角色 |

### [users] 部分

| 配置项 | 默认值 | 本项目配置 | 调整原因 |
|--------|--------|------------|----------|
| `allow_sign_up` | `true` | `false` | 禁用自主注册，统一通过认证服务管理 |
| `allow_org_create` | `true` | `false` | 禁用组织创建，简化权限管理 |

### [security] 部分

| 配置项 | 默认值 | 本项目配置 | 调整原因 |
|--------|--------|------------|----------|
| `admin_user` | `admin` | `admin` | 保持默认管理员用户名 |
| `admin_password` | `admin` | `admin123` | 设置更安全的管理员密码 |
| `secret_key` | 随机生成 | `your-secret-key-here` | 固定密钥确保会话一致性 |
| `cookie_secure` | `false` | `false` | HTTP 环境下保持 false |
| `cookie_samesite` | `lax` | `lax` | 保持默认跨站策略 |

### [analytics] 部分

| 配置项 | 默认值 | 本项目配置 | 调整原因 |
|--------|--------|------------|----------|
| `reporting_enabled` | `true` | `false` | 禁用数据上报，保护隐私 |
| `check_for_updates` | `true` | `false` | 禁用更新检查，避免外网请求 |

## 详细配置说明

### 1. 代理认证配置

#### 核心配置项

```ini
[auth.proxy]
enabled = true
header_name = X-WEBAUTH-USER
auto_sign_up = true
headers = Name:X-WEBAUTH-NAME Email:X-WEBAUTH-EMAIL Role:X-WEBAUTH-ROLE Permissions:X-WEBAUTH-PERMISSIONS
role_attribute_path = Role
role_mapping = admin=Admin editor=Editor viewer=Viewer
```

#### 配置说明

- **enabled**: 启用代理认证，Grafana 将信任来自代理的认证信息
- **header_name**: 指定包含用户名的 HTTP 头部
- **headers**: 映射 HTTP 头部到用户属性，支持姓名、邮箱、角色和权限
- **role_attribute_path**: 指定角色信息的属性路径
- **role_mapping**: 将自定义角色映射到 Grafana 内置角色

### 2. 子路径访问配置

```ini
[server]
root_url = http://localhost/grafana/
serve_from_sub_path = true
```

这个配置使 Grafana 能够在 `/grafana/` 子路径下正常工作，配合 Nginx 代理实现统一的访问入口。

### 3. 权限控制机制

本项目通过以下机制实现权限控制：

1. **认证服务角色定义**：
   - `admin`: 管理员角色，拥有所有权限
   - `editor`: 编辑者角色，拥有读写权限
   - `viewer`: 查看者角色，拥有读取和explore权限

2. **权限类型**：
   - `read`: 读取权限
   - `write`: 写入权限
   - `delete`: 删除权限
   - `explore`: explore权限
   - `admin`: 管理权限

3. **权限传递**：
   - 通过 `X-WEBAUTH-PERMISSIONS` 头部传递权限信息
   - Grafana 根据角色映射分配相应权限

## 配置步骤指引

### 步骤 1: 准备配置文件

1. 复制项目中的 `grafana.ini` 文件
2. 根据实际环境调整以下配置：
   - `root_url`: 修改为实际的访问地址
   - `admin_password`: 设置安全的管理员密码
   - `secret_key`: 生成唯一的密钥

### 步骤 2: 配置认证服务

1. 确保认证服务正确返回以下 HTTP 头部：
   ```
   X-WEBAUTH-USER: 用户名
   X-WEBAUTH-NAME: 显示名称
   X-WEBAUTH-EMAIL: 邮箱地址
   X-WEBAUTH-ROLE: 用户角色 (admin/editor/viewer)
   X-WEBAUTH-PERMISSIONS: 权限列表 (逗号分隔)
   ```

### 步骤 3: 配置 Nginx 代理

1. 确保 Nginx 正确传递认证头部：
   ```nginx
   proxy_set_header X-WEBAUTH-USER $auth_user;
   proxy_set_header X-WEBAUTH-NAME $auth_name;
   proxy_set_header X-WEBAUTH-EMAIL $auth_email;
   proxy_set_header X-WEBAUTH-ROLE $auth_role;
   proxy_set_header X-WEBAUTH-PERMISSIONS $auth_permissions;
   ```

### 步骤 4: 启动和测试

1. 启动所有服务：
   ```bash
   docker-compose up -d
   ```

2. 测试登录流程：
   - 访问 `http://localhost/grafana/`
   - 验证自动跳转到登录页面
   - 使用测试账户登录
   - 确认权限正确分配

## 常见问题和故障排除

### 问题 1: 重定向循环 (ERR_TOO_MANY_REDIRECTS)

**原因**: Nginx 配置中认证头部传递不正确

**解决方案**:
1. 检查 `auth_request_set` 变量设置
2. 确保使用 `proxy_set_header` 而不是 `proxy_pass_header`
3. 验证认证服务返回正确的状态码

### 问题 2: 用户权限不正确

**原因**: 角色映射配置错误或认证头部缺失

**解决方案**:
1. 检查 `role_mapping` 配置
2. 验证认证服务返回的角色信息
3. 确认 `X-WEBAUTH-ROLE` 头部正确传递

### 问题 3: Export 功能无权限

**原因**: viewer 角色缺少 export 权限

**解决方案**:
1. 确认认证服务为 viewer 角色分配 export 权限
2. 检查 `X-WEBAUTH-PERMISSIONS` 头部包含 "export"
3. 验证权限查询接口 `/api/permissions` 返回正确信息

### 问题 4: 静态资源加载失败

**原因**: 子路径配置不正确

**解决方案**:
1. 确认 `serve_from_sub_path = true`
2. 检查 `root_url` 配置包含正确的子路径
3. 验证 Nginx 代理配置正确

## 安全注意事项

### 1. 认证头部安全

- **头部伪造防护**: 确保只有认证服务能够设置认证相关头部
- **传输加密**: 在生产环境中使用 HTTPS 加密传输
- **头部验证**: 认证服务应验证头部信息的完整性

### 2. 会话管理

- **密钥安全**: 使用强随机密钥作为 `secret_key`
- **会话超时**: 配置合适的会话超时时间
- **Cookie 安全**: 在 HTTPS 环境下启用 `cookie_secure`

### 3. 权限控制

- **最小权限原则**: 为用户分配最小必要权限
- **权限审计**: 定期审查用户权限分配
- **角色分离**: 明确区分不同角色的权限边界

### 4. 网络安全

- **内网隔离**: 认证服务和 Grafana 应部署在内网环境
- **防火墙配置**: 限制不必要的网络访问
- **日志监控**: 启用访问日志和安全事件监控

## 配置模板

### 完整的 grafana.ini 配置模板

```ini
[server]
protocol = http
http_port = 3000
domain = localhost
root_url = http://localhost/grafana/
serve_from_sub_path = true

[database]
type = sqlite3
path = grafana.db

[session]
provider = file
provider_config = sessions

[dataproxy]
logging = false

[security]
admin_user = admin
admin_password = admin123
secret_key = your-secret-key-here
cookie_secure = false
cookie_samesite = lax

[snapshots]
external_enabled = true
external_snapshot_url = https://snapshots-origin.raintank.io
external_snapshot_name = Publish to snapshot.raintank.io

[dashboards]
versions_to_keep = 20
min_refresh_interval = 5s
default_home_dashboard_path =

[auth]
disable_login_form = true

[auth.proxy]
enabled = true
header_name = X-WEBAUTH-USER
auto_sign_up = true
headers = Name:X-WEBAUTH-NAME Email:X-WEBAUTH-EMAIL Role:X-WEBAUTH-ROLE Permissions:X-WEBAUTH-PERMISSIONS
role_attribute_path = Role
role_mapping = admin=Admin editor=Editor viewer=Viewer

[users]
allow_sign_up = false
allow_org_create = false

[analytics]
reporting_enabled = false
check_for_updates = false
```

## 总结

本配置指引详细说明了如何将 Grafana 从默认配置调整为支持自定义认证服务的权限控制系统。关键调整包括：

1. **启用代理认证模式**，禁用内置登录
2. **配置自定义头部映射**，支持角色和权限传递
3. **实现角色映射机制**，将自定义角色映射到 Grafana 角色
4. **配置子路径访问**，支持 Nginx 代理集成
5. **加强安全配置**，提升系统安全性

通过这些配置调整，实现了细粒度的权限控制，特别是让 viewer 角色具有 export 功能权限，满足了项目的具体需求。
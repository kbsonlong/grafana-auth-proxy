# Grafana 认证代理系统

这是一个基于Nginx + Go + JWT的Grafana认证代理系统，实现了前后端分离的单点登录功能。

## 系统架构

```
用户浏览器 → Nginx (反向代理) → Go认证服务 (JWT验证) → Grafana
```

## 核心功能

- **JWT认证机制**: 使用JWT token进行用户身份验证
- **前后端分离**: 登录页面与认证逻辑分离
- **单点登录**: 一次登录，访问所有服务
- **反向代理**: Nginx处理路由和认证检查
- **容器化部署**: 使用Docker Compose一键部署

## 项目结构

```
grafana-auth-proxy/
├── auth-service/          # Go认证服务
│   ├── main.go           # 主程序
│   ├── go.mod            # Go模块文件
│   ├── go.sum            # 依赖校验文件
│   └── Dockerfile        # Docker构建文件
├── nginx/                # Nginx配置
│   └── conf.d/
│       └── grafana.conf  # 主配置文件
├── grafana/              # Grafana配置
│   └── grafana.ini       # Grafana配置文件
├── docker-compose.yml    # Docker编排文件
└── README.md            # 项目文档
```

## 快速开始

### 1. 启动服务

```bash
# 构建并启动所有服务
docker-compose up -d --build

# 查看服务状态
docker-compose ps

# 查看日志
docker-compose logs -f
```

### 2. 访问系统

1. 打开浏览器访问: http://localhost
2. 使用以下测试账号登录:
   - 用户名: `admin`, 密码: `admin123`
   - 用户名: `user1`, 密码: `password1`
   - 用户名: `user2`, 密码: `password2`
3. 登录成功后自动跳转到Grafana界面

### 3. 停止服务

```bash
# 停止所有服务
docker-compose down

# 停止并删除数据卷
docker-compose down -v
```

## 认证流程

1. **用户访问**: 用户访问 `http://localhost/grafana/`
2. **认证检查**: Nginx使用 `auth_request` 检查用户是否已认证
3. **重定向登录**: 未认证用户被重定向到登录页面 `/`
4. **用户登录**: 用户在登录页面输入凭据
5. **JWT生成**: 认证服务验证凭据并生成JWT token
6. **Cookie设置**: JWT token存储在浏览器cookie中
7. **访问授权**: 后续请求携带token，通过认证后访问Grafana

## 配置说明

### Nginx配置要点

- **避免重定向循环**: 精心设计的location块优先级
- **auth_request**: 使用内部认证检查
- **用户信息传递**: 将认证用户信息传递给Grafana

### Grafana配置要点

- **auth.proxy**: 启用代理认证模式
- **disable_login_form**: 禁用内置登录表单
- **auto_sign_up**: 自动创建用户账号

### 认证服务配置

- **JWT密钥**: 生产环境请修改 `jwtSecret`
- **用户数据**: 当前使用内存存储，生产环境建议使用数据库
- **Token过期**: 默认24小时，可根据需要调整

## 安全注意事项

1. **JWT密钥**: 生产环境必须使用强密钥
2. **HTTPS**: 生产环境建议启用HTTPS
3. **用户存储**: 建议使用数据库存储用户信息
4. **密码加密**: 建议对密码进行哈希加密
5. **网络隔离**: 认证服务和Grafana不应直接暴露给外网

## 故障排除

### 重定向循环问题

如果遇到 `ERR_TOO_MANY_REDIRECTS` 错误:

1. 检查Nginx配置中的location块顺序
2. 确认auth_request配置正确
3. 验证认证服务是否正常响应
4. 清除浏览器cookie和缓存

### 认证失败问题

1. 检查JWT token是否正确生成
2. 验证token是否在cookie中正确设置
3. 确认Grafana配置中的代理认证设置

### 服务连接问题

1. 检查Docker网络配置
2. 验证服务间的网络连通性
3. 查看各服务的健康检查状态

## 开发和测试

### 本地开发

```bash
# 进入认证服务目录
cd auth-service

# 安装依赖
go mod tidy

# 运行服务
go run main.go
```

### 测试API

```bash
# 测试登录API
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# 测试认证API
curl -X GET http://localhost:8080/auth \
  -H "Cookie: auth-token=YOUR_JWT_TOKEN"
```

## 扩展功能

- **多因素认证**: 可集成TOTP或短信验证
- **LDAP集成**: 支持企业级目录服务
- **审计日志**: 记录用户登录和操作日志
- **会话管理**: 实现会话超时和强制登出
- **权限控制**: 基于角色的访问控制

## 许可证

MIT License
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

// 角色定义
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

// 权限定义
type Permission string

const (
	PermissionRead   Permission = "read"
	PermissionWrite  Permission = "write"
	PermissionDelete Permission = "delete"
	PermissionExport Permission = "explore"
	PermissionAdmin  Permission = "admin"
)

const (
	jwtSecret   = "your-secret-key-change-in-production"
	tokenExpiry = 24 * time.Hour
)

type Claims struct {
	Username    string       `json:"username"`
	Email       string       `json:"email"`
	Name        string       `json:"name"`
	Role        Role         `json:"role"`
	Permissions []Permission `json:"permissions"`
	jwt.RegisteredClaims
}

// 用户信息结构
type User struct {
	Username    string       `json:"username"`
	Password    string       `json:"password"`
	Email       string       `json:"email"`
	Name        string       `json:"name"`
	Role        Role         `json:"role"`
	Permissions []Permission `json:"permissions"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

// 权限查询响应
type PermissionsResponse struct {
	Username    string       `json:"username"`
	Role        Role         `json:"role"`
	Permissions []Permission `json:"permissions"`
}

// 角色权限映射
var rolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermissionRead,
		PermissionWrite,
		PermissionDelete,
		PermissionExport,
		PermissionAdmin,
	},
	RoleEditor: {
		PermissionRead,
		PermissionWrite,
		PermissionExport,
	},
	RoleViewer: {
		PermissionRead,
		PermissionExport, // viewer角色可以导出
	},
}

// JWT密钥 - 使用固定密钥确保重启后token仍然有效
var jwtKey = []byte("grafana-auth-proxy-secret-key-2025")

// 模拟用户数据库
var users = map[string]User{
	"admin": {
		Username:    "admin",
		Password:    "admin123", // 实际应用中应该使用哈希密码
		Email:       "admin@example.com",
		Name:        "Administrator",
		Role:        RoleAdmin,
		Permissions: rolePermissions[RoleAdmin],
	},
	"editor": {
		Username:    "editor",
		Password:    "editor123",
		Email:       "editor@example.com",
		Name:        "Editor User",
		Role:        RoleEditor,
		Permissions: rolePermissions[RoleEditor],
	},
	"viewer": {
		Username:    "viewer",
		Password:    "viewer123",
		Email:       "viewer@example.com",
		Name:        "Viewer User",
		Role:        RoleViewer,
		Permissions: rolePermissions[RoleViewer],
	},
}

func main() {
	// 创建路由器
	r := mux.NewRouter()

	// 设置路由
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/auth", authHandler).Methods("GET")
	r.HandleFunc("/api/logout", logoutHandler).Methods("POST")
	r.HandleFunc("/api/permissions", permissionsHandler).Methods("GET")
	r.HandleFunc("/health", healthHandler).Methods("GET")

	log.Println("认证服务启动在端口 :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// 健康检查处理器
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "auth-service",
	})
}

// 登录处理器
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 验证用户
	user, exists := users[req.Username]
	if !exists || user.Password != req.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// 创建JWT token
	claims := &Claims{
		Username:    user.Username,
		Email:       user.Email,
		Name:        user.Name,
		Role:        user.Role,
		Permissions: user.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	// 设置HttpOnly cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth-token",
		Value:    tokenString,
		Path:     "/",
		MaxAge:   int(tokenExpiry.Seconds()),
		HttpOnly: true,
		Secure:   false, // 在生产环境中应设置为true
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		Message: "登录成功",
	})
}

// 认证处理器（供Nginx auth_request使用）
func authHandler(w http.ResponseWriter, r *http.Request) {
	// 从cookie获取token
	cookie, err := r.Cookie("auth-token")
	if err != nil {
		// 没有token，返回401，Nginx会重定向到登录页面
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// 验证JWT token
	token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(*Claims); ok {
		// 验证成功，设置用户信息到响应头
		w.Header().Set("X-WEBAUTH-USER", claims.Username)
		w.Header().Set("X-WEBAUTH-EMAIL", claims.Email)
		w.Header().Set("X-WEBAUTH-NAME", claims.Name)
		w.Header().Set("X-WEBAUTH-ROLE", string(claims.Role))

		// 将权限列表转换为逗号分隔的字符串
		permissions := make([]string, len(claims.Permissions))
		for i, perm := range claims.Permissions {
			permissions[i] = string(perm)
		}
		w.Header().Set("X-WEBAUTH-PERMISSIONS", strings.Join(permissions, ","))

		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// 登出处理器
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// 清除cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   false, // 开发环境设为false
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LoginResponse{
		Message: "登出成功",
	})
}

// 权限查询处理器
func permissionsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("权限查询请求:", r.URL.Path)
	// 从cookie中获取token
	cookie, err := r.Cookie("auth-token")
	if err != nil {
		log.Println("未找到认证token:", err)
		http.Error(w, "No auth token found", http.StatusUnauthorized)
		return
	}

	// 验证token
	log.Println("开始验证token:", cookie.Value[:50]+"...")
	token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		log.Println("Token验证失败:", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	log.Println("Token验证成功")

	if claims, ok := token.Claims.(*Claims); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PermissionsResponse{
			Username:    claims.Username,
			Role:        claims.Role,
			Permissions: claims.Permissions,
		})
	} else {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
	}
}

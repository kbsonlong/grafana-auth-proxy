package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtSecret = "your-secret-key-change-in-production"
	tokenExpiry = 24 * time.Hour
)

type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Message string `json:"message"`
}

// 简单的用户验证（生产环境应使用数据库）
var users = map[string]string{
	"admin": "admin123",
	"user1": "password1",
	"user2": "password2",
}

func main() {
	// API路由
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/auth", authHandler)
	http.HandleFunc("/api/logout", logoutHandler)
	
	// 健康检查
	http.HandleFunc("/health", healthHandler)

	log.Println("认证服务启动在端口 :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// 健康检查处理器
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
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

	// 验证用户凭据
	if password, exists := users[req.Username]; !exists || password != req.Password {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{
			Message: "用户名或密码错误",
		})
		return
	}

	// 创建JWT token
	claims := &Claims{
		Username: req.Username,
		Email:    req.Username + "@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
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
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(*Claims); ok {
		// 设置用户信息头部，供Grafana使用
		w.Header().Set("X-WEBAUTH-USER", claims.Username)
		w.Header().Set("X-WEBAUTH-EMAIL", claims.Email)
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// 登出处理器
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// 清除cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth-token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// 重定向到登录页面
	http.Redirect(w, r, "/", http.StatusFound)
}
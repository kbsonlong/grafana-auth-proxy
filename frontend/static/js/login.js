document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const messageDiv = document.getElementById('message');
    const loginContainer = document.querySelector('.login-container');

    // 检查是否已经登录
    checkAuthStatus();

    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        
        if (!username || !password) {
            showMessage('请输入用户名和密码', 'error');
            return;
        }
        
        // 显示加载状态
        setLoading(true);
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
                credentials: 'same-origin'
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showMessage(data.message || '登录成功', 'success');
                
                // 登录成功后等待一段时间再重定向，确保cookie设置完成
                setTimeout(() => {
                    window.location.href = '/grafana/';
                }, 1500);
            } else {
                showMessage(data.message || '登录失败', 'error');
            }
        } catch (error) {
            console.error('登录请求失败:', error);
            showMessage('网络错误，请稍后重试', 'error');
        } finally {
            setLoading(false);
        }
    });

    function showMessage(message, type) {
        messageDiv.innerHTML = `<div class="${type}">${message}</div>`;
        
        // 自动清除错误消息
        if (type === 'error') {
            setTimeout(() => {
                messageDiv.innerHTML = '';
            }, 5000);
        }
    }

    function setLoading(loading) {
        if (loading) {
            loginContainer.classList.add('loading');
            document.querySelector('button').textContent = '登录中...';
        } else {
            loginContainer.classList.remove('loading');
            document.querySelector('button').textContent = '登录';
        }
    }

    async function checkAuthStatus() {
        try {
            const response = await fetch('/api/auth', {
                method: 'GET',
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                // 已经登录，重定向到Grafana
                window.location.href = '/grafana/';
            }
        } catch (error) {
            // 忽略错误，显示登录页面
            console.log('未登录状态');
        }
    }

    // 处理URL参数中的错误信息
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    if (error) {
        let errorMessage = '认证失败，请重新登录';
        if (error === 'unauthorized') {
            errorMessage = '会话已过期，请重新登录';
        } else if (error === 'forbidden') {
            errorMessage = '访问被拒绝，请检查权限';
        }
        showMessage(errorMessage, 'error');
        
        // 清除URL参数
        window.history.replaceState({}, document.title, window.location.pathname);
    }
});
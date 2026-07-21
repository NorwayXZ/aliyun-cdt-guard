# 反向代理与域名访问

Aliyun CDT Guard 默认监听：

```text
http://服务器IP:8787
```

生产环境建议使用域名 + HTTPS 反代，例如：

```text
https://cdt.example.com
```

推荐结构：

```text
用户浏览器 -> HTTPS 域名 -> Caddy/Nginx -> 127.0.0.1:8787 -> Aliyun CDT Guard
```

这样可以避免直接暴露 `IP:端口`，也方便接入 HTTPS、访问控制和 Cloudflare。

## 面板一键应用 Caddy

安装完成后，可以在面板左侧进入 `域名反代`。

需要先准备：

1. 在 Cloudflare DNS 添加 `A` 记录，指向安装面板的服务器公网 IP。
2. 服务器安全组/防火墙放行 `80` 和 `443`。
3. 面板仍能通过源站端口访问，例如 `http://服务器IP:8787`。

然后在页面填写：

- 面板域名：例如 `cdt.example.com`
- 源站公网 IP：安装面板的服务器 IP
- 面板源站端口：默认 `8787`

点击 `保存并应用 Caddy` 后，面板会自动：

- 安装 Caddy（如果本机还没有安装）
- 备份 `/etc/caddy/Caddyfile`
- 写入当前域名的反代配置
- 重启 Caddy
- 写入 `WEB_COOKIE_SECURE=true`

Cloudflare 如果开启橙色云，DNS 查询结果会显示 Cloudflare 节点 IP，而不是源站 IP，这是正常现象。

## 方式一：Caddy 推荐

Caddy 会自动申请和续期 HTTPS 证书，适合大多数用户。

安装：

```bash
sudo apt update
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

编辑：

```bash
sudo nano /etc/caddy/Caddyfile
```

写入：

```caddyfile
cdt.example.com {
  reverse_proxy 127.0.0.1:8787
}
```

重载：

```bash
sudo systemctl reload caddy
```

## 方式二：Nginx

安装：

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
```

创建站点：

```bash
sudo nano /etc/nginx/sites-available/aliyun-cdt-guard
```

写入：

```nginx
server {
    listen 80;
    server_name cdt.example.com;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

启用：

```bash
sudo ln -s /etc/nginx/sites-available/aliyun-cdt-guard /etc/nginx/sites-enabled/aliyun-cdt-guard
sudo nginx -t
sudo systemctl reload nginx
```

申请 HTTPS：

```bash
sudo certbot --nginx -d cdt.example.com
```

## 限制源站端口

如果已经使用反代，建议让面板只监听本机：

编辑：

```bash
sudo nano /opt/aliyun-cdt-guard/web.env
```

改成：

```env
CDT_GUARD_HOST=127.0.0.1
CDT_GUARD_PORT=8787
```

如果你确认以后只通过 HTTPS 域名访问，也可以加：

```env
WEB_COOKIE_SECURE=true
```

重启：

```bash
sudo systemctl restart cdt-guard-web.service
```

之后公网只能通过域名访问，不能直接访问 `服务器IP:8787`。

## 使用 Cloudflare

如果域名接入 Cloudflare：

1. DNS 添加 `A` 记录，指向面板服务器 IP。
2. 代理状态可开启橙云。
3. SSL/TLS 模式建议选择 `Full` 或 `Full (strict)`。
4. 源站仍建议用 Caddy/Nginx 提供 HTTPS。

## 登录页

面板自带正式登录页，账号密码来自：

```text
/opt/aliyun-cdt-guard/web.env
```

字段：

```env
WEB_USERNAME=admin
WEB_PASSWORD=安装时随机生成
WEB_SESSION_SECRET=安装时随机生成
```

反代后访问 `https://cdt.example.com` 会进入登录页。

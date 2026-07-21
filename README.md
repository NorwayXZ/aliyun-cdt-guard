# Aliyun CDT Guard

Aliyun CDT Guard 是一个自托管的阿里云 ECS / CDT 流量保护面板。

它把原来需要 SSH 上服务器手动改 Python 脚本的流程，变成了一个可以在网页里维护的面板：添加服务器、填写阿里云 AccessKey、设置 CDT 流量池和阈值、查看历史曲线、手动开关机、接入 Telegram/邮件/Webhook 通知。

适合这些场景：

- 阿里云香港、日本、新加坡等 ECS 使用 CDT 免费/优惠流量额度。
- 一个阿里云账号下多台机器共享同一个 200GB/220GB CDT 流量池。
- 希望流量到阈值自动关机，月初流量恢复后自动开机。
- 希望用域名登录面板，而不是直接访问 `IP:端口`。
- 希望收到 Telegram、邮件或 Webhook 通知和每日流量报告。

## 功能

- Tabler 风格网页面板
- 正式登录页，不再依赖浏览器 Basic Auth 弹窗
- 网页添加/编辑阿里云服务器
- 每台服务器可独立保存 AccessKey ID / Secret
- 支持 ECS Instance ID、区域、CDT 流量区域
- 支持 CDT 共享流量池策略
- 支持预警阈值、停机阈值、恢复启动阈值
- 支持预计恢复开机时间和剩余天数
- 支持 ECS 公网/内网 IP 自动识别
- 支持在每台服务器行内显示对应阿里云账号指纹和账户余额
- 支持首页按阿里云账号/共享池分组展示服务器
- 支持手动开机、关机
- 手动关机会暂停自动启动，避免定时任务又拉起
- 支持产品自定义名字、服务器 IP、登录网站、账号密码、SSH 备注
- 支持 1 天、3 天、7 天、1 个月流量曲线
- 支持服务器日志侧栏
- 支持 Telegram Bot、Webhook、SMTP 邮件通知
- 支持每日流量统计报告
- 支持域名反代向导，生成 Cloudflare、Caddy、Nginx 配置
- systemd timer 默认每分钟巡检一次
- 无数据库，配置和历史写在本地 JSON / JSONL 文件

## 一键安装

在准备用作控制面板的 Linux 服务器上执行：

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/aliyun-cdt-guard/main/install.sh | sudo bash
```

安装完成后会输出：

```text
Web panel:
  URL:      http://服务器IP:8787
  Username: admin
  Password: 随机生成密码
```

默认端口：

```text
8787
```

自定义端口安装：

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/aliyun-cdt-guard/main/install.sh | sudo WEB_PORT=9000 bash
```

## 一键卸载

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/aliyun-cdt-guard/main/uninstall.sh | sudo bash
```

卸载脚本会移除 systemd 服务和命令行入口，但默认保留：

```text
/opt/aliyun-cdt-guard
```

这样可以避免误删 AccessKey、通知 Token、历史记录和服务器配置。

## 登录面板

安装后访问：

```text
http://服务器IP:8787
```

面板会显示正式登录页。

登录账号密码在：

```text
/opt/aliyun-cdt-guard/web.env
```

字段：

```env
WEB_USERNAME=admin
WEB_PASSWORD=安装时随机生成
WEB_SESSION_SECRET=安装时随机生成
```

如果面板只通过 HTTPS 反代访问，可以在 `web.env` 里增加：

```env
WEB_COOKIE_SECURE=true
```

修改密码后重启：

```bash
sudo systemctl restart cdt-guard-web.service
```

## 域名反代

生产环境建议使用域名访问：

```text
https://cdt.example.com
```

推荐结构：

```text
用户浏览器 -> HTTPS 域名 -> Caddy/Nginx -> 127.0.0.1:8787 -> Aliyun CDT Guard
```

Caddy 示例：

```caddyfile
cdt.example.com {
  reverse_proxy 127.0.0.1:8787
}
```

Nginx、Caddy、Cloudflare 和源站端口限制的详细说明见：

[docs/reverse-proxy.md](docs/reverse-proxy.md)

## 添加服务器

进入 `新增/编辑` 页面，填写：

- 产品自定义名字
- 服务器 IP
- ECS Instance ID
- 阿里云区域 ID，例如 `cn-hongkong`。面板支持常见地域下拉提示，也可以查看阿里云官方“地域和可用区”文档确认。
- CDT 流量区域，例如 `cn-hongkong`
- 阿里云 AccessKey ID
- 阿里云 AccessKey Secret
- CDT 统计方式
- 流量池分组名（可选，面板内部自定义）
- 预警阈值
- 停机阈值
- 恢复启动阈值
- CDT 每月重置日
- 登录网站、账号密码、SSH 备注、用途备注

区域 ID 必须和 ECS 实例所在地域一致。阿里云官方地域表：

```text
https://help.aliyun.com/zh/ecs/user-guide/regions-and-zones
```

保存后面板会立即执行一次检查。

## CDT 共享流量池

如果一个阿里云账号下有多台非中国内地服务器，并且共享同一个 CDT 月度额度，建议这样配置：

```text
CDT 统计方式 = 账号非中国内地共享池
流量池分组名 = 留空，或自定义为 global-200g
预警阈值     = 160
停机阈值     = 180
恢复启动阈值 = 175
```

同一个池内的机器会看到同一个池内累计流量。

`流量池分组名` 不是阿里云控制台提供的 ID，而是面板内部使用的自定义分组名：

- 同一个阿里云账号、同一种 CDT 统计方式：可以直接留空，面板会按 AccessKey 自动归组。
- 同一个阿里云账号用了多个 RAM AccessKey：给这些机器填写同一个分组名，例如 `global-200g`。
- 已经创建过分组后，新增/编辑页面会把已有分组列出来，可以直接选择加入。
- 如果新增日本、香港、新加坡等同账号非中国内地机器，优先选择 `账号非中国内地共享池`，流量池分组保持留空即可。
- 新机器归到哪个账号池，主要由填写的 AccessKey 决定：填哪个阿里云账号的 AccessKey，就归到哪个账号池。
- 如果新增页暂时没有可选分组，这不是错误；多数情况下留空就是正确做法。
- 不同阿里云账号：不要共用同一个分组名，否则会被面板当成同一个池。

策略：

```text
流量 >= 180GB  -> 停机
流量 <= 175GB  -> 如果机器已停机，则恢复启动
175GB - 180GB  -> 保持当前状态
```

这样可以避免临界值附近反复开关机。

如果不确定怎么填，优先留空；只有需要强制把多个 AccessKey 下的机器合并统计时，再填写同一个 `流量池分组名`。

## 账期重置与恢复开机

面板支持显示“多少天后账期重置”和“是否会自动恢复开机”。

逻辑：

1. 面板会优先用 BSS 账单 API 查询当前真实账期，例如 `2026-07`。
2. 如果 BSS 可用，下一次重置时间按下个账期开始计算，并在面板显示 `来源：BSS 账单 API`。
3. 如果 BSS 不可用，才使用服务器配置里的 `CDT 每月重置日` 作为备用推算。
4. 到达重置时间后，定时巡检会再次查询 CDT 流量。
5. 如果流量已经低于恢复启动阈值，并且这台机器不是手动关机保持状态，面板会自动开机。

示例：

```text
当前流量：180GB
停机阈值：180GB
恢复阈值：175GB
账期来源：BSS 账单 API
当前账期：2026-07
账期重置时间：2026-08-01 00:00:00+08:00
预计恢复：账期重置后的下一次巡检
```

如果你手动点击了“关机并暂停自动启动”，即使到了月初重置，面板也不会自动开机，需要你手动点击“开机并恢复自动保护”。

## 通知

进入 `通知设置` 页面可以配置：

- Telegram Bot
- 通用 Webhook
- SMTP 邮件

支持的通知规则：

- 自动停机/启动通知
- 首次流量预警通知
- 首次检查错误通知
- 每日流量报告

Telegram 配置流程：

1. 在 Telegram 找 `@BotFather` 创建机器人。
2. 复制 Bot Token。
3. 在面板 `通知设置` 里填写 Bot Token 并保存。
4. 在 Telegram 给你的机器人发送 `/start` 或任意一条消息；如果要发到群组，就把机器人拉进群并在群里发一条消息。
5. 回到面板点击 `获取 Chat ID`。
6. 面板会列出候选 Chat ID，点击 `追加这个 Chat ID`。如果要通知多个人或多个群，可以重复追加多个 Chat ID。
7. 打开通知总开关和 Telegram 开关。
8. 保存后点击 `发送测试通知`，测试消息会附带 Telegram 主动查询命令。

注意：`@your_bot_name` 通常是机器人用户名，不是你的个人 Chat ID。私聊通知一般需要纯数字 Chat ID。

Telegram 主动查询命令：

配置完成后，可以在 Telegram 里直接给机器人发送命令，主动获取面板里的流量和服务器状态。主动查询只做查看，不支持远程开关机。

```text
/status        查看面板总览、机器数量、预警和错误
/traffic       查看每台机器当前 CDT 用量、本次新增和重置时间
/pools         查看共享 CDT 流量池用量和成员机器
/server 关键词  按产品名、实例 ID 或公网 IP 查询单台服务器
/report        立即生成一次完整流量报告
/help          查看命令帮助
```

示例：

```text
/server hk
/server 154.83.98.194
/traffic
```

命令回复依赖巡检任务轮询 Telegram `getUpdates`，默认大约每分钟处理一次。如果 Bot 设置了 Telegram Webhook，`getUpdates` 可能会被 Telegram 拒绝，需要先删除 Webhook 后再使用主动查询。

通知配置文件：

```text
/opt/aliyun-cdt-guard/notifications.json
/opt/aliyun-cdt-guard/notification_state.json
```

权限为 `0600`。

## 阿里云 RAM 权限

最低权限建议：

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cdt:ListCdtInternetTraffic",
        "ecs:DescribeInstances",
        "ecs:StartInstances",
        "ecs:StopInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

如果后续要接入 EIP 实时云监控，可额外增加：

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cms:QueryMetricList",
        "cms:QueryMetricLast",
        "vpc:DescribeEipAddresses",
        "vpc:DescribeEipMonitorData"
      ],
      "Resource": "*"
    }
  ]
}
```

CDT 月度额度保护仍以 CDT 接口为准；EIP 云监控更适合实时趋势、突增提醒和分钟级曲线。

如果要让面板显示真实账期来源和阿里云账户余额，而不是只按配置推算 CDT 重置日，请额外给 RAM 用户增加阿里云系统策略：

```text
AliyunBSSReadOnlyAccess
```

面板会调用 BSS `QueryBillOverview` 读取当前账期，调用 `QueryAccountBalance` 查询账户余额，并自动兼容中国站和国际站 BSS 接入点。

账户余额会显示在服务器列表中每台机器的名称下方。同一个 AccessKey 会显示同一个阿里云账号指纹，方便判断多台服务器是否属于同一个阿里云账号，以及这个账号当前还剩多少余额。

## 文件结构

```text
/opt/aliyun-cdt-guard/guard.py                  巡检和自动启停
/opt/aliyun-cdt-guard/web.py                    Web 面板
/opt/aliyun-cdt-guard/notifications.py          通知发送器
/opt/aliyun-cdt-guard/instances.json            服务器配置和备注
/opt/aliyun-cdt-guard/status.json               最新状态
/opt/aliyun-cdt-guard/history.jsonl             历史记录
/opt/aliyun-cdt-guard/web.env                   登录账号密码
/opt/aliyun-cdt-guard/guard.env                 全局阿里云兜底配置
/opt/aliyun-cdt-guard/notifications.json        通知配置
/opt/aliyun-cdt-guard/notification_state.json   通知状态
```

## 常用命令

查看状态：

```bash
cdt-guard status
cdt-guard status --json
```

手动巡检：

```bash
sudo systemctl start cdt-guard.service
```

查看服务：

```bash
systemctl status cdt-guard.timer
systemctl status cdt-guard-web.service
```

查看日志：

```bash
journalctl -u cdt-guard.service -n 100 --no-pager
journalctl -u cdt-guard-web.service -n 100 --no-pager
```

重启面板：

```bash
sudo systemctl restart cdt-guard-web.service
```

## 安全建议

- 不建议长期直接暴露 `IP:8787`。
- 建议使用域名 + HTTPS 反向代理。
- 使用反代后，将 `CDT_GUARD_HOST` 改成 `127.0.0.1`。
- `instances.json` 包含 AccessKey 和备注密码，默认 `0600`。
- `notifications.json` 可能包含 Bot Token、Webhook URL、SMTP 密码，默认 `0600`。
- 推荐使用 RAM 子账号，不要使用主账号 AccessKey。
- 推荐给 RAM 用户最小权限。

## 手动安装

```bash
git clone https://github.com/NorwayXZ/aliyun-cdt-guard.git
cd aliyun-cdt-guard
sudo bash install.sh
```

## 项目地址

```text
https://github.com/NorwayXZ/aliyun-cdt-guard
```

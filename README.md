# Aliyun CDT Guard

Aliyun CDT Guard is a small self-hosted web panel for managing Aliyun ECS traffic protection.

It keeps the original script logic simple:

1. Query Aliyun CDT internet traffic.
2. Query the ECS instance status.
3. Start ECS when traffic is below the start threshold.
4. Stop ECS when traffic reaches the stop threshold.

The difference is that servers, AccessKeys, thresholds, account notes and login information can be managed from the web panel.

## Features

- Tabler-based web dashboard
- Add and edit Aliyun servers from the browser
- Per-server AccessKey ID and AccessKey Secret
- Per-server ECS Instance ID, region and CDT traffic region
- CDT traffic pool mode for one account shared by multiple non-mainland servers
- Warning, stop and recovery-start thresholds
- ECS public/private IP discovery
- Manual ECS start and stop buttons from the web panel
- Manual stop pauses automatic restart until the server is manually started again
- Server product name, provider, panel URL, panel account/password, SSH notes and custom notes
- Passwords are hidden by default in the UI
- Telegram, Webhook and SMTP email notifications
- Daily traffic report
- `systemd` timer checks every minute
- `status.json` and `history.jsonl` for API and audit history
- No database required

## One-Click Install

Run on a Linux server that will act as the control panel host:

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/aliyun-cdt-guard/main/install.sh | sudo bash
```

The installer prints the web URL, username and random password.

Default panel port:

```text
8787
```

## Manual Install

```bash
git clone https://github.com/NorwayXZ/aliyun-cdt-guard.git
cd aliyun-cdt-guard
sudo bash install.sh
```

## Add a Server

Open the web panel and fill:

- Product custom name
- Server IP, optional because ECS public IP can be discovered automatically
- Aliyun AccessKey ID
- Aliyun AccessKey Secret
- Region ID, for example `cn-hongkong`
- CDT traffic region, for example `cn-hongkong`
- CDT scope:
  - `按当前 CDT 区域统计`: only one CDT business region, compatible with older configs
  - `账号非中国内地共享池`: Hong Kong, Japan, Singapore, US, Europe and other non-mainland regions under the same Aliyun account
  - `账号全部 CDT 流量`: all CDT traffic returned by the account
- Traffic pool ID, for example `global-200g`; use the same pool ID for servers sharing the same CDT quota
- ECS Instance ID, for example `i-xxxxxxxx`
- Warning threshold, for example `160`
- Stop threshold, for example `180`
- Recovery start threshold, for example `175`
- Provider login website, username, password and notes if needed

After saving, the panel immediately runs one check.

## Shared CDT Pool Strategy

If one Aliyun account owns several ECS instances and they share one monthly CDT quota, protect the quota as an account traffic pool instead of treating each server separately.

Recommended setup for Hong Kong, Japan and other non-mainland ECS instances sharing a 200GB/220GB CDT allowance:

```text
CDT scope       = 账号非中国内地共享池
Traffic pool ID = global-200g
warning         = 160
stop            = 180
start           = 175
```

Every enabled server in the same pool sees the same pool usage. When the pool reaches the stop threshold, each server in that pool follows the stop policy. After the next monthly reset, if the pool drops below the recovery-start threshold, stopped servers can be started again unless they were manually stopped from the panel.

If the same Aliyun account uses multiple RAM AccessKeys, give those servers the same custom Traffic pool ID. If they are different Aliyun accounts, use different pool IDs so their quotas are not mixed.

## Notifications

Open `通知设置` in the web panel to configure alert channels.

Supported channels:

- Telegram Bot
- Generic Webhook
- SMTP email

Notification rules:

- Automatic start/stop actions
- First traffic warning after entering the warning threshold
- First new check error
- Daily traffic report at a configured local time

Telegram setup:

1. Create a bot with Telegram `@BotFather`.
2. Copy the Bot Token into the panel.
3. Send one message to the bot, or add it to your group/channel.
4. Fill the Chat ID in the panel.
5. Save settings and click `发送测试通知`.

The notification config is stored in:

```text
/opt/aliyun-cdt-guard/notifications.json
/opt/aliyun-cdt-guard/notification_state.json
```

Both files are written as root-only `0600`.

## Threshold Logic

Recommended values for Hong Kong CDT free traffic protection:

```text
warning_threshold_gb = 160
stop_threshold_gb    = 180
start_threshold_gb   = 175
```

Behavior:

```text
traffic >= 180GB  -> stop ECS
traffic <= 175GB  -> start ECS if stopped
175GB - 180GB     -> hold current state
```

This hysteresis avoids repeated start/stop actions around the boundary.

When the next monthly CDT cycle resets and traffic drops below the start threshold, stopped instances can be started automatically again.

## Files

```text
/opt/aliyun-cdt-guard/guard.py        traffic guard
/opt/aliyun-cdt-guard/web.py          web panel
/opt/aliyun-cdt-guard/instances.json  server configs and notes
/opt/aliyun-cdt-guard/status.json     latest status
/opt/aliyun-cdt-guard/history.jsonl   history events
/opt/aliyun-cdt-guard/web.env         web username/password
/opt/aliyun-cdt-guard/notifications.json notification settings
```

## Commands

```bash
cdt-guard status
cdt-guard status --json
systemctl status cdt-guard.timer
systemctl status cdt-guard-web.service
journalctl -u cdt-guard.service -n 100 --no-pager
```

Run a check manually:

```bash
sudo systemctl start cdt-guard.service
```

Restart the web panel:

```bash
sudo systemctl restart cdt-guard-web.service
```

## Security Notes

- Do not expose this panel without a firewall or trusted network.
- The panel uses HTTP Basic Auth by default.
- `instances.json` contains AccessKeys and optional account passwords, and is installed as root-only `0600`.
- `notifications.json` may contain Bot Tokens, Webhook URLs and SMTP passwords, and is installed as root-only `0600`.
- For production use, put the panel behind HTTPS and restrict source IPs.
- Use a RAM user with minimum permissions:

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

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/NorwayXZ/aliyun-cdt-guard/main/uninstall.sh | sudo bash
```

The uninstall script removes services and the CLI wrapper, but keeps `/opt/aliyun-cdt-guard` so your secrets and history are not deleted accidentally.

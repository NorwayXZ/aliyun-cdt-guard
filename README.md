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
- Warning, stop and recovery-start thresholds
- ECS public/private IP discovery
- Server product name, provider, panel URL, panel account/password, SSH notes and custom notes
- Passwords are hidden by default in the UI
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
- ECS Instance ID, for example `i-xxxxxxxx`
- Warning threshold, for example `160`
- Stop threshold, for example `180`
- Recovery start threshold, for example `175`
- Provider login website, username, password and notes if needed

After saving, the panel immediately runs one check.

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

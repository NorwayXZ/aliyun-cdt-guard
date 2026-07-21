#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import os
import smtplib
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

BASE_DIR = Path(os.environ.get("CDT_GUARD_HOME", "/opt/aliyun-cdt-guard"))
CONFIG_FILE = BASE_DIR / "notifications.json"
STATE_FILE = BASE_DIR / "notification_state.json"


def default_config() -> dict[str, Any]:
    return {
        "enabled": False,
        "rules": {
            "notify_actions": True,
            "notify_warnings": True,
            "notify_errors": True,
            "daily_report": False,
            "daily_report_time": "09:00",
            "timezone": "Asia/Shanghai",
        },
        "telegram": {
            "enabled": False,
            "bot_token": "",
            "chat_id": "",
            "disable_web_page_preview": True,
        },
        "webhook": {
            "enabled": False,
            "url": "",
        },
        "smtp": {
            "enabled": False,
            "host": "",
            "port": 587,
            "username": "",
            "password": "",
            "sender": "",
            "recipients": "",
            "use_tls": True,
        },
    }


def merge_dict(default: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    result = dict(default)
    for key, value in current.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_dict(result[key], value)
        else:
            result[key] = value
    return result


def read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(tmp_path, 0o600)
    tmp_path.replace(path)


def load_config() -> dict[str, Any]:
    return merge_dict(default_config(), read_json(CONFIG_FILE, {}))


def save_config(config: dict[str, Any]) -> None:
    write_json(CONFIG_FILE, merge_dict(default_config(), config))


def load_state() -> dict[str, Any]:
    return read_json(STATE_FILE, {})


def save_state(state: dict[str, Any]) -> None:
    write_json(STATE_FILE, state)


def gb(value: Any) -> str:
    if value is None:
        return "未知"
    try:
        return f"{float(value):.2f} GB"
    except (TypeError, ValueError):
        return "未知"


def post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None, timeout: int = 12) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "AliyunCDTGuard/1.0",
            **(headers or {}),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"ok": response.status < 400, "status": response.status, "body": text[:500]}
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "status": exc.code, "error": body_text[:500]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def send_telegram(channel: dict[str, Any], title: str, message: str) -> dict[str, Any]:
    token = str(channel.get("bot_token") or "").strip()
    chat_id = str(channel.get("chat_id") or "").strip()
    if not token or not chat_id:
        return {"ok": False, "error": "Telegram Bot Token 或 Chat ID 未填写"}
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    return post_json(
        url,
        {
            "chat_id": chat_id,
            "text": f"{title}\n\n{message}",
            "disable_web_page_preview": bool(channel.get("disable_web_page_preview", True)),
        },
    )


def send_webhook(channel: dict[str, Any], title: str, message: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    url = str(channel.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "Webhook URL 未填写"}
    return post_json(url, {"title": title, "message": message, "payload": payload or {}})


def send_smtp(channel: dict[str, Any], title: str, message: str) -> dict[str, Any]:
    host = str(channel.get("host") or "").strip()
    username = str(channel.get("username") or "").strip()
    password = str(channel.get("password") or "")
    sender = str(channel.get("sender") or username).strip()
    recipients = [
        item.strip()
        for item in str(channel.get("recipients") or "").replace(";", ",").split(",")
        if item.strip()
    ]
    if not host or not sender or not recipients:
        return {"ok": False, "error": "SMTP 主机、发件人或收件人未填写"}

    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(message)
    port = int(channel.get("port") or 587)
    try:
        if bool(channel.get("use_tls", True)):
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.starttls(context=ssl.create_default_context())
                if username:
                    server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(host, port, timeout=15) as server:
                if username:
                    server.login(username, password)
                server.send_message(msg)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def send_message(title: str, message: str, payload: dict[str, Any] | None = None, config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or load_config()
    if not config.get("enabled"):
        return {"ok": False, "skipped": True, "error": "通知总开关未启用"}

    results: dict[str, Any] = {}
    if config.get("telegram", {}).get("enabled"):
        results["telegram"] = send_telegram(config["telegram"], title, message)
    if config.get("webhook", {}).get("enabled"):
        results["webhook"] = send_webhook(config["webhook"], title, message, payload)
    if config.get("smtp", {}).get("enabled"):
        results["smtp"] = send_smtp(config["smtp"], title, message)

    if not results:
        return {"ok": False, "skipped": True, "error": "没有启用任何通知渠道"}
    return {"ok": any(item.get("ok") for item in results.values()), "channels": results}


def action_label(action: str | None) -> str:
    labels = {
        "stop": "自动停机",
        "start": "自动启动",
        "manual_stop": "手动关机",
        "manual_start": "手动开机",
        "keep_stopped": "保持停止",
        "error": "检查错误",
    }
    return labels.get(action or "", action or "未知动作")


def instance_line(item: dict[str, Any]) -> str:
    return (
        f"{item.get('label') or item.get('id')}\n"
        f"状态：{item.get('instance_status') or item.get('status') or '未知'}\n"
        f"动作：{action_label(item.get('action'))}\n"
        f"流量：{gb(item.get('traffic_gb'))} / {gb(item.get('stop_threshold_gb'))}\n"
        f"流量池：{item.get('traffic_pool_label') or item.get('traffic_region_id') or '未知'}\n"
        f"原因：{item.get('reason') or '无'}"
    )


def build_daily_report(status: dict[str, Any]) -> tuple[str, str]:
    summary = status.get("summary", {})
    instances = status.get("instances", [])
    title = "Aliyun CDT Guard 每日流量报告"
    lines = [
        f"更新时间：{status.get('generated_at') or '暂无'}",
        f"机器：{summary.get('enabled', 0)}/{summary.get('total', 0)} 启用，流量池 {summary.get('pools', 0)}，预警 {summary.get('warnings', 0)}，错误 {summary.get('errors', 0)}，停止 {summary.get('stopped', 0)}",
        "",
    ]
    for item in instances:
        lines.append(
            f"- {item.get('label') or item.get('id')} | {item.get('instance_status') or '未知'} | "
            f"{gb(item.get('traffic_gb'))}/{gb(item.get('stop_threshold_gb'))} | {item.get('traffic_pool_label') or '未知流量池'}"
        )
    return title, "\n".join(lines).strip()


def should_send_daily_report(config: dict[str, Any], state: dict[str, Any], now: datetime | None = None) -> bool:
    rules = config.get("rules", {})
    if not config.get("enabled") or not rules.get("daily_report"):
        return False
    try:
        zone = ZoneInfo(str(rules.get("timezone") or "Asia/Shanghai"))
    except Exception:
        zone = ZoneInfo("Asia/Shanghai")
    local_now = (now or datetime.now(tz=ZoneInfo("UTC"))).astimezone(zone)
    report_time = str(rules.get("daily_report_time") or "09:00")
    hour_text, _, minute_text = report_time.partition(":")
    try:
        report_hour = int(hour_text)
        report_minute = int(minute_text or "0")
    except ValueError:
        report_hour, report_minute = 9, 0
    today = local_now.date().isoformat()
    if state.get("last_daily_report_date") == today:
        return False
    return (local_now.hour, local_now.minute) >= (report_hour, report_minute)


def handle_guard_notifications(
    status: dict[str, Any],
    previous_status: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    config = load_config()
    if not config.get("enabled"):
        return []

    rules = config.get("rules", {})
    previous_by_id = {
        str(item.get("id")): item
        for item in (previous_status or {}).get("instances", [])
    }
    sent: list[dict[str, Any]] = []
    for item in status.get("instances", []):
        previous = previous_by_id.get(str(item.get("id")), {})
        title = ""
        if item.get("last_error") and rules.get("notify_errors") and previous.get("last_error") != item.get("last_error"):
            title = "Aliyun CDT Guard 检查错误"
        elif item.get("action") in {"stop", "start"} and rules.get("notify_actions"):
            title = f"Aliyun CDT Guard {action_label(item.get('action'))}"
        elif item.get("warning") and rules.get("notify_warnings") and not previous.get("warning"):
            title = "Aliyun CDT Guard 流量预警"

        if not title:
            continue
        result = send_message(title, instance_line(item), {"instance": item, "status": status}, config)
        sent.append({"id": item.get("id"), "title": title, "result": result})

    state = load_state()
    if should_send_daily_report(config, state):
        title, message = build_daily_report(status)
        result = send_message(title, message, {"status": status}, config)
        sent.append({"id": "daily_report", "title": title, "result": result})
        state["last_daily_report_date"] = datetime.now(ZoneInfo(config.get("rules", {}).get("timezone") or "Asia/Shanghai")).date().isoformat()
        save_state(state)
    return sent


def send_test_message() -> dict[str, Any]:
    return send_message(
        "Aliyun CDT Guard 测试通知",
        "如果你收到这条消息，说明通知渠道已经配置成功。",
        {"type": "test"},
    )

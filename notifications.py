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


def get_json(url: str, timeout: int = 12) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "AliyunCDTGuard/1.0"},
        method="GET",
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


def mask_secret(value: str, keep: int = 4) -> str:
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"


def split_chat_ids(value: Any) -> list[str]:
    rows: list[str] = []
    seen: set[str] = set()
    text = str(value or "").replace(";", ",").replace("\n", ",")
    for item in text.split(","):
        chat_id = item.strip()
        if not chat_id or chat_id in seen:
            continue
        rows.append(chat_id)
        seen.add(chat_id)
    return rows


def join_chat_ids(chat_ids: list[str]) -> str:
    return ",".join(split_chat_ids(",".join(chat_ids)))


def add_chat_id(current: Any, chat_id: str) -> str:
    return join_chat_ids([*split_chat_ids(current), chat_id])


def telegram_status(config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or load_config()
    channel = config.get("telegram", {})
    token = str(channel.get("bot_token") or "")
    chat_ids = split_chat_ids(channel.get("chat_id"))
    channel_ready = bool(channel.get("enabled") and token and chat_ids)
    return {
        "enabled": bool(channel.get("enabled")),
        "token_configured": bool(token),
        "token_masked": mask_secret(token),
        "chat_id": join_chat_ids(chat_ids),
        "chat_ids": chat_ids,
        "ready": bool(config.get("enabled") and channel_ready),
        "command_ready": bool(channel_ready and any(not chat_id.startswith("@") for chat_id in chat_ids)),
    }


def extract_chat_candidates(updates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for update in updates:
        message = (
            update.get("message")
            or update.get("edited_message")
            or update.get("channel_post")
            or update.get("my_chat_member")
            or {}
        )
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None:
            continue
        key = str(chat_id)
        if key in seen:
            continue
        seen.add(key)
        title = chat.get("title") or " ".join(
            part for part in [chat.get("first_name"), chat.get("last_name")] if part
        )
        rows.append(
            {
                "chat_id": key,
                "type": chat.get("type") or "unknown",
                "title": title or chat.get("username") or key,
                "username": chat.get("username") or "",
            }
        )
    return rows


def discover_telegram_chats(config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or load_config()
    token = str(config.get("telegram", {}).get("bot_token") or "").strip()
    if not token:
        return {"ok": False, "error": "Telegram Bot Token 未填写"}
    result = get_json(f"https://api.telegram.org/bot{token}/getUpdates")
    if not result.get("ok"):
        return {"ok": False, "error": result.get("description") or result.get("error") or "Telegram getUpdates 失败", "raw": result}
    candidates = extract_chat_candidates(result.get("result") or [])
    return {"ok": True, "candidates": candidates, "count": len(candidates)}


def send_telegram(channel: dict[str, Any], title: str, message: str) -> dict[str, Any]:
    token = str(channel.get("bot_token") or "").strip()
    chat_ids = split_chat_ids(channel.get("chat_id"))
    if not token or not chat_ids:
        return {"ok": False, "error": "Telegram Bot Token 或 Chat ID 未填写"}
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    results = []
    for chat_id in chat_ids:
        results.append(
            {
                "chat_id": chat_id,
                "result": post_json(
                    url,
                    {
                        "chat_id": chat_id,
                        "text": f"{title}\n\n{message}",
                        "disable_web_page_preview": bool(channel.get("disable_web_page_preview", True)),
                    },
                ),
            }
        )
    return {"ok": any(item["result"].get("ok") for item in results), "chats": results}


def send_telegram_to_chat(token: str, chat_id: str, text: str) -> dict[str, Any]:
    if not token or not chat_id:
        return {"ok": False, "error": "Telegram Bot Token 或 Chat ID 未填写"}
    return post_json(
        f"https://api.telegram.org/bot{token}/sendMessage",
        {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True,
        },
    )


def telegram_get_updates(token: str, offset: int | None = None) -> dict[str, Any]:
    if not token:
        return {"ok": False, "error": "Telegram Bot Token 未填写"}
    url = f"https://api.telegram.org/bot{token}/getUpdates?timeout=1&limit=20"
    if offset is not None:
        url += f"&offset={offset}"
    result = get_json(url, timeout=8)
    if not result.get("ok"):
        return {"ok": False, "error": result.get("description") or result.get("error") or "Telegram getUpdates 失败", "raw": result}
    return result


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
        "keep_running": "保持运行",
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


def pool_summary(status: dict[str, Any]) -> list[dict[str, Any]]:
    pools: dict[str, dict[str, Any]] = {}
    for item in status.get("instances", []):
        key = str(item.get("traffic_pool_key") or item.get("id"))
        pool = pools.setdefault(
            key,
            {
                "label": item.get("traffic_pool_label") or item.get("traffic_region_id") or "未知流量池",
                "traffic_gb": item.get("traffic_gb"),
                "stop_threshold_gb": item.get("stop_threshold_gb"),
                "members": [],
                "warning": False,
            },
        )
        pool["members"].append(item.get("label") or item.get("id"))
        pool["warning"] = bool(pool.get("warning") or item.get("warning"))
    return list(pools.values())


def telegram_help_text() -> str:
    return (
        "Aliyun CDT Guard 可用命令\n\n"
        "/status - 查看面板总览\n"
        "/traffic - 查看每台机器 CDT 用量\n"
        "/pools - 查看流量池用量\n"
        "/report - 立即生成一次流量报告\n"
        "/server 关键词 - 查看某台服务器详情\n"
        "/help - 查看帮助\n\n"
        "说明：Telegram 命令只用于查询，不提供远程开关机。"
    )


def build_status_reply(status: dict[str, Any]) -> str:
    summary = status.get("summary", {})
    return (
        "Aliyun CDT Guard 总览\n\n"
        f"更新时间：{status.get('generated_at') or '暂无'}\n"
        f"机器：{summary.get('enabled', 0)}/{summary.get('total', 0)} 启用\n"
        f"流量池：{summary.get('pools', 0)}\n"
        f"预警：{summary.get('warnings', 0)}\n"
        f"错误：{summary.get('errors', 0)}\n"
        f"已停止：{summary.get('stopped', 0)}\n"
        f"本次启停动作：{summary.get('actions', 0)}"
    )


def build_traffic_reply(status: dict[str, Any]) -> str:
    lines = ["每台机器流量", ""]
    for item in status.get("instances", []):
        plan = item.get("recovery_plan") or {}
        countdown = plan.get("reset_countdown_label") or f"{plan.get('days_until_reset', '未知')} 天"
        lines.append(
            f"- {item.get('label') or item.get('id')}\n"
            f"  状态：{item.get('instance_status') or '未知'}\n"
            f"  CDT：{gb(item.get('traffic_gb'))} / {gb(item.get('stop_threshold_gb'))}\n"
            f"  本次新增：{gb(item.get('traffic_delta_gb'))}\n"
            f"  流量池：{item.get('traffic_pool_label') or '未知'}\n"
            f"  下次重置：{str(plan.get('next_reset_at') or '暂无').split('T')[0]}，剩余 {countdown}"
        )
    return "\n".join(lines).strip()


def build_pools_reply(status: dict[str, Any]) -> str:
    lines = ["流量池用量", ""]
    for pool in pool_summary(status):
        try:
            used_pct = float(pool.get("traffic_gb") or 0) / float(pool.get("stop_threshold_gb") or 1) * 100
        except (TypeError, ValueError, ZeroDivisionError):
            used_pct = 0
        lines.append(
            f"- {pool.get('label')}\n"
            f"  用量：{gb(pool.get('traffic_gb'))} / {gb(pool.get('stop_threshold_gb'))} ({used_pct:.0f}%)\n"
            f"  机器：{', '.join(str(name) for name in pool.get('members', []))}"
        )
    return "\n".join(lines).strip()


def build_server_reply(status: dict[str, Any], keyword: str) -> str:
    keyword = keyword.strip().lower()
    if not keyword:
        return "请带上服务器关键词，例如：/server hk 或 /server norwayx"
    for item in status.get("instances", []):
        haystack = " ".join(
            str(value or "")
            for value in [
                item.get("id"),
                item.get("label"),
                item.get("instance_id"),
                item.get("instance_name"),
                ",".join(item.get("public_ips") or []),
            ]
        ).lower()
        if keyword not in haystack:
            continue
        plan = item.get("recovery_plan") or {}
        countdown = plan.get("reset_countdown_label") or f"{plan.get('days_until_reset', '未知')} 天"
        return (
            f"{item.get('label') or item.get('id')}\n\n"
            f"状态：{item.get('instance_status') or '未知'}\n"
            f"实例：{item.get('instance_id')}\n"
            f"公网 IP：{', '.join(item.get('public_ips') or []) or '未知'}\n"
            f"区域：{item.get('region_id')}\n"
            f"CDT：{gb(item.get('traffic_gb'))} / {gb(item.get('stop_threshold_gb'))}\n"
            f"剩余：{gb(item.get('remaining_gb'))}\n"
            f"动作：{action_label(item.get('action'))}\n"
            f"原因：{item.get('reason') or '无'}\n"
            f"流量池：{item.get('traffic_pool_label') or '未知'}\n"
            f"预计重置：{str(plan.get('next_reset_at') or '暂无').split('T')[0]}，剩余 {countdown}"
        )
    return f"没有找到匹配服务器：{keyword}"


def build_command_reply(text: str, status: dict[str, Any]) -> str:
    command, _, rest = text.strip().partition(" ")
    command = command.split("@", 1)[0].lower()
    if command in {"/help", "/start"}:
        return telegram_help_text()
    if command == "/status":
        return build_status_reply(status)
    if command == "/traffic":
        return build_traffic_reply(status)
    if command == "/pools":
        return build_pools_reply(status)
    if command == "/report":
        title, message = build_daily_report(status)
        return f"{title}\n\n{message}"
    if command == "/server":
        return build_server_reply(status, rest)
    return "未知命令。发送 /help 查看可用命令。"


def extract_message(update: dict[str, Any]) -> dict[str, Any]:
    return update.get("message") or update.get("edited_message") or {}


def telegram_commands_enabled(config: dict[str, Any]) -> bool:
    channel = config.get("telegram", {})
    return bool(channel.get("enabled") and channel.get("bot_token") and channel.get("chat_id"))


def handle_telegram_commands(status: dict[str, Any], config: dict[str, Any], state: dict[str, Any]) -> list[dict[str, Any]]:
    if not telegram_commands_enabled(config):
        return []
    channel = config.get("telegram", {})
    token = str(channel.get("bot_token") or "").strip()
    allowed_chat_ids = set(split_chat_ids(channel.get("chat_id")))
    if not any(not chat_id.startswith("@") for chat_id in allowed_chat_ids):
        state["telegram_command_error"] = "Chat ID 是用户名格式，Telegram 命令需要数字 Chat ID。"
        return []

    offset = state.get("telegram_update_offset")
    try:
        offset = int(offset) if offset is not None else None
    except (TypeError, ValueError):
        offset = None
    state["telegram_last_command_poll_at"] = datetime.now(ZoneInfo("UTC")).isoformat()
    result = telegram_get_updates(token, offset)
    if not result.get("ok"):
        state["telegram_command_error"] = result.get("error") or "Telegram 命令轮询失败"
        return []

    handled: list[dict[str, Any]] = []
    max_update_id = offset - 1 if offset is not None else None
    for update in result.get("result") or []:
        update_id = update.get("update_id")
        if isinstance(update_id, int):
            max_update_id = update_id if max_update_id is None else max(max_update_id, update_id)
        message = extract_message(update)
        text = str(message.get("text") or "").strip()
        chat_id = str((message.get("chat") or {}).get("id") or "")
        if not text.startswith("/"):
            continue
        if chat_id not in allowed_chat_ids:
            if chat_id:
                send_telegram_to_chat(token, chat_id, "这个机器人已绑定到其他 Chat ID，当前会话无权查询面板状态。")
            handled.append({"chat_id": chat_id, "command": text, "allowed": False})
            continue
        reply = build_command_reply(text, status)
        send_result = send_telegram_to_chat(token, chat_id, reply)
        handled.append({"chat_id": chat_id, "command": text, "allowed": True, "result": send_result})

    if max_update_id is not None:
        state["telegram_update_offset"] = max_update_id + 1
    if handled:
        state["telegram_last_command"] = {
            "at": datetime.now(ZoneInfo("UTC")).isoformat(),
            "command": handled[-1].get("command"),
            "allowed": handled[-1].get("allowed"),
            "ok": bool((handled[-1].get("result") or {}).get("ok")) if handled[-1].get("allowed") else False,
        }
    state.pop("telegram_command_error", None)
    return handled


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
    state = load_state()
    state_before = json.dumps(state, ensure_ascii=False, sort_keys=True)
    sent: list[dict[str, Any]] = []

    for command in handle_telegram_commands(status, config, state):
        sent.append(
            {
                "id": "telegram_command",
                "title": f"Telegram 命令 {command.get('command')}",
                "result": command.get("result") or {"ok": False, "allowed": command.get("allowed")},
            }
        )

    if not config.get("enabled"):
        if json.dumps(state, ensure_ascii=False, sort_keys=True) != state_before:
            save_state(state)
        return sent

    rules = config.get("rules", {})
    previous_by_id = {
        str(item.get("id")): item
        for item in (previous_status or {}).get("instances", [])
    }
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

    if should_send_daily_report(config, state):
        title, message = build_daily_report(status)
        result = send_message(title, message, {"status": status}, config)
        sent.append({"id": "daily_report", "title": title, "result": result})
        state["last_daily_report_date"] = datetime.now(ZoneInfo(config.get("rules", {}).get("timezone") or "Asia/Shanghai")).date().isoformat()
    if json.dumps(state, ensure_ascii=False, sort_keys=True) != state_before:
        save_state(state)
    return sent


def send_test_message() -> dict[str, Any]:
    return send_message(
        "Aliyun CDT Guard 测试通知",
        "如果你收到这条消息，说明通知渠道已经配置成功。\n\n"
        f"{telegram_help_text()}",
        {"type": "test"},
    )

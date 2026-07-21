#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import subprocess
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import notifications

BASE_DIR = Path(os.environ.get("CDT_GUARD_HOME", "/opt/aliyun-cdt-guard"))
WEB_ENV_FILE = BASE_DIR / "web.env"
CONFIG_FILE = BASE_DIR / "instances.json"
STATUS_FILE = BASE_DIR / "status.json"
HISTORY_FILE = BASE_DIR / "history.jsonl"
DOMAIN_PROXY_FILE = BASE_DIR / "domain_proxy.json"
TRAFFIC_SCOPE_REGION = "region"
TRAFFIC_SCOPE_ACCOUNT_NON_CHINA = "account_non_china"
TRAFFIC_SCOPE_ACCOUNT_ALL = "account_all"
TRAFFIC_SCOPE_LABELS = {
    TRAFFIC_SCOPE_REGION: "按当前 CDT 区域统计",
    TRAFFIC_SCOPE_ACCOUNT_NON_CHINA: "账号非中国内地共享池",
    TRAFFIC_SCOPE_ACCOUNT_ALL: "账号全部 CDT 流量",
}
ALIYUN_REGION_DOC_URL = "https://help.aliyun.com/zh/ecs/user-guide/regions-and-zones"
ALIYUN_REGION_OPTIONS = [
    ("cn-hongkong", "中国香港"),
    ("ap-northeast-1", "日本（东京）"),
    ("ap-southeast-1", "新加坡"),
    ("ap-southeast-3", "马来西亚（吉隆坡）"),
    ("ap-southeast-5", "印度尼西亚（雅加达）"),
    ("ap-southeast-6", "菲律宾（马尼拉）"),
    ("ap-southeast-7", "泰国（曼谷）"),
    ("ap-southeast-8", "马来西亚（柔佛州）"),
    ("ap-south-1", "印度（孟买）"),
    ("ap-northeast-2", "韩国（首尔）"),
    ("eu-central-1", "德国（法兰克福）"),
    ("eu-west-1", "英国（伦敦）"),
    ("eu-west-2", "法国（巴黎）"),
    ("us-east-1", "美国（弗吉尼亚）"),
    ("us-west-1", "美国（硅谷）"),
    ("me-east-1", "阿联酋（迪拜）"),
    ("me-central-1", "沙特（利雅得）"),
    ("na-south-1", "墨西哥"),
    ("cn-hangzhou", "华东 1（杭州）"),
    ("cn-shanghai", "华东 2（上海）"),
    ("cn-qingdao", "华北 1（青岛）"),
    ("cn-beijing", "华北 2（北京）"),
    ("cn-zhangjiakou", "华北 3（张家口）"),
    ("cn-huhehaote", "华北 5（呼和浩特）"),
    ("cn-wulanchabu", "华北 6（乌兰察布）"),
    ("cn-shenzhen", "华南 1（深圳）"),
    ("cn-heyuan", "华南 2（河源）"),
    ("cn-guangzhou", "华南 3（广州）"),
    ("cn-chengdu", "西南 1（成都）"),
    ("cn-zhongwei", "西北 2（中卫）"),
]


def load_env(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(tmp_path, 0o600)
    tmp_path.replace(path)


def read_config() -> dict:
    return read_json(
        CONFIG_FILE,
        {
            "version": 1,
            "defaults": {
                "enabled": True,
                "warning_threshold_gb": 160,
                "stop_threshold_gb": 180,
                "start_threshold_gb": 175,
                "traffic_region_id": "cn-hongkong",
                "traffic_scope": TRAFFIC_SCOPE_REGION,
            },
            "instances": [],
        },
    )


def read_history(limit: int = 200) -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()
    records = []
    for line in lines[-limit:]:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def parse_event_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def read_traffic_series(server_id: str, days: int, pool_key: str = "") -> dict:
    days = max(1, min(days, 31))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    points = []
    previous_traffic = None
    previous_point_time = None
    previous_point_traffic = None

    if HISTORY_FILE.exists():
        for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if pool_key:
                if str(event.get("traffic_pool_key") or "") != pool_key:
                    continue
            elif str(event.get("id")) != server_id:
                continue
            event_time = parse_event_time(event.get("at"))
            if event_time is None or event_time < cutoff:
                continue
            traffic = event.get("traffic_gb")
            if traffic is None:
                continue
            try:
                traffic_gb = float(traffic)
            except (TypeError, ValueError):
                continue
            delta = event.get("traffic_delta_gb")
            try:
                delta_gb = float(delta) if delta is not None else None
            except (TypeError, ValueError):
                delta_gb = None
            if delta_gb is None and previous_traffic is not None:
                delta_gb = traffic_gb - previous_traffic if traffic_gb >= previous_traffic else traffic_gb
            if delta_gb is None:
                delta_gb = 0
            previous_traffic = traffic_gb
            if pool_key and previous_point_time is not None and previous_point_traffic is not None:
                seconds = abs((event_time - previous_point_time).total_seconds())
                if seconds <= 300 and abs(traffic_gb - previous_point_traffic) < 0.000001:
                    continue
            previous_point_time = event_time
            previous_point_traffic = traffic_gb
            points.append(
                {
                    "at": event.get("at"),
                    "traffic_gb": traffic_gb,
                    "delta_gb": max(delta_gb, 0),
                    "action": event.get("action"),
                    "status": event.get("status"),
                }
            )

    total_delta = sum(float(point.get("delta_gb") or 0) for point in points)
    return {
        "server_id": server_id,
        "traffic_pool_key": pool_key,
        "days": days,
        "points": points,
        "total_delta_gb": total_delta,
        "first_traffic_gb": points[0]["traffic_gb"] if points else None,
        "last_traffic_gb": points[-1]["traffic_gb"] if points else None,
        "point_count": len(points),
    }


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def first_value(*values, default: str = ""):
    for value in values:
        if value not in {None, ""}:
            return value
    return default


def fmt_gb(value) -> str:
    if value is None:
        return "未知"
    try:
        return f"{float(value):.2f} GB"
    except (TypeError, ValueError):
        return "未知"


def fmt_time(value) -> str:
    if not value:
        return "暂无"
    text = str(value)
    return text.replace("T", " ").replace("+00:00", " UTC")


def fmt_date(value) -> str:
    if not value:
        return "暂无"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d")
    except ValueError:
        return str(value).split("T", 1)[0]


def fmt_chinese_date(value) -> str:
    if not value:
        return "暂无"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return f"{parsed.year}年{parsed.month}月{parsed.day}日"
    except ValueError:
        date_part = str(value).split("T", 1)[0].split(" ", 1)[0]
        try:
            year, month, day = [int(part) for part in date_part.split("-", 2)]
            return f"{year}年{month}月{day}日"
        except (TypeError, ValueError):
            return str(value)


def fmt_delta(value) -> str:
    if value is None:
        return "暂无变化数据"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "暂无变化数据"
    sign = "+" if number > 0 else ""
    return f"{sign}{number:.2f} GB"


def traffic_scope_label(scope: str | None) -> str:
    return TRAFFIC_SCOPE_LABELS.get(scope or TRAFFIC_SCOPE_REGION, TRAFFIC_SCOPE_LABELS[TRAFFIC_SCOPE_REGION])


def normalize_traffic_scope(scope: str | None) -> str:
    return scope if scope in TRAFFIC_SCOPE_LABELS else TRAFFIC_SCOPE_REGION


def traffic_pool_text(item: dict) -> str:
    pool_id = item.get("traffic_pool_id") or item.get("traffic_region_id") or "默认池"
    return f"{traffic_scope_label(item.get('traffic_scope'))} / {pool_id}"


def traffic_pool_badge(item: dict) -> str:
    scope = item.get("traffic_scope") or TRAFFIC_SCOPE_REGION
    count = int(item.get("traffic_pool_member_count") or 0)
    if scope == TRAFFIC_SCOPE_REGION:
        return f"区域池 · {esc(item.get('traffic_region_id') or '未设置')}"
    if count > 1:
        return f"共享池 · {count} 台机器"
    return "账号池 · 单台机器"


def recovery_status_badge(item: dict) -> str:
    plan = item.get("recovery_plan") or {}
    if plan.get("auto_start_paused"):
        return "手动关机，不会自动恢复"
    if plan.get("will_auto_start_after_reset"):
        days = plan.get("days_until_reset")
        return f"预计 {days} 天后自动开机"
    if plan.get("stopped_by_threshold"):
        return "等待账期重置"
    return f"下次重置 {fmt_date(plan.get('next_reset_at'))}"


def render_recovery_plan(item: dict) -> str:
    plan = item.get("recovery_plan") or {}
    if not plan:
        return '<div class="text-secondary small">暂无恢复时间信息，下一次巡检后会显示。</div>'
    countdown_label = plan.get("reset_countdown_label") or f"{plan.get('days_until_reset', '未知')}天"
    will_auto_start = bool(plan.get("will_auto_start_after_reset"))
    paused = bool(plan.get("auto_start_paused"))
    status_text = "会自动开机" if will_auto_start else ("手动关机保持中" if paused else "未处于自动恢复队列")
    status_class = "recovery-ok" if will_auto_start else ("recovery-paused" if paused else "recovery-neutral")
    source = plan.get("reset_source")
    source_label = plan.get("reset_source_label") or ("BSS 账单 API" if source == "bss" else "配置推算")
    if source == "bss":
        reset_hint = f"{source_label} · 账期 {plan.get('billing_cycle') or '未知'}"
        reset_title = f"来源：{source_label}；账期：{plan.get('billing_cycle') or '未知'}；接口区域：{plan.get('billing_region_id') or '未知'}"
    else:
        reset_hint = f"{source_label} · 每月 {plan.get('traffic_reset_day') or 1} 日"
        reset_title = f"来源：{source_label}；按配置每月 {plan.get('traffic_reset_day') or 1} 日重置"
    return f"""
      <div class="reset-summary {status_class}" title="{esc(reset_title)}">
        <div class="reset-main">
          <div class="reset-eyebrow">账期重置</div>
          <div class="reset-time">{esc(fmt_chinese_date(plan.get('next_reset_at')))}</div>
          <div class="reset-source">{esc(reset_hint)}</div>
        </div>
        <div class="reset-count">
          <div class="reset-duration">{esc(countdown_label)}</div>
          <div class="recovery-unit">后重置</div>
        </div>
      </div>
      <div class="reset-foot">
        <span>{esc(status_text)}</span>
        <span>恢复阈值 {fmt_gb(item.get('start_threshold_gb'))}</span>
      </div>
    """


def form_value(fields: dict[str, list[str]], name: str, default: str = "") -> str:
    value = fields.get(name, [default])[0]
    return value.strip()


def as_float(value: str, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def slug(text: str) -> str:
    keep = []
    for char in text.lower():
        if char.isascii() and char.isalnum():
            keep.append(char)
        elif char in {"-", "_", " ", "."}:
            keep.append("-")
    value = "".join(keep).strip("-")
    while "--" in value:
        value = value.replace("--", "-")
    return value or f"server-{secrets.token_hex(4)}"


def badge(action: str | None) -> str:
    mapping = {
        "stop": ("danger", "已触发停机"),
        "start": ("success", "已触发启动"),
        "manual_stop": ("danger", "手动关机"),
        "manual_start": ("success", "手动开机"),
        "manual_stopped": ("danger", "手动保持停止"),
        "keep_running": ("success", "保持运行"),
        "keep_stopped": ("danger", "保持停止"),
        "hold": ("warning", "回差保持"),
        "disabled": ("secondary", "已禁用"),
        "error": ("danger", "错误"),
    }
    cls, text = mapping.get(action or "", ("secondary", action or "未知"))
    return f'<span class="badge bg-{cls}-lt">{esc(text)}</span>'


def small_line(label: str, value) -> str:
    if not value:
        return ""
    return f'<div class="text-secondary small"><span class="fw-semibold">{esc(label)}</span>{esc(value)}</div>'


def link_or_text(value) -> str:
    if not value:
        return '<span class="text-secondary">未填写</span>'
    href = str(value) if str(value).startswith(("http://", "https://")) else f"https://{value}"
    return f'<a href="{esc(href)}" target="_blank" rel="noopener noreferrer">{esc(value)}</a>'


def secret_button(value, label: str = "显示密码") -> str:
    if not value:
        return '<div class="text-secondary small">密码未填写</div>'
    return (
        '<button class="btn btn-sm btn-outline-secondary mt-1" type="button" '
        f'data-secret="{esc(value)}" onclick="toggleSecret(this)">{esc(label)}</button>'
    )


def status_view(status: str | None) -> tuple[str, str, str]:
    mapping = {
        "Running": ("running", "运行中", "Running"),
        "Stopped": ("stopped", "已关机", "Stopped"),
        "Starting": ("pending", "开机中", "Starting"),
        "Stopping": ("pending", "关机中", "Stopping"),
        "Disabled": ("muted", "已禁用", "Disabled"),
    }
    return mapping.get(status or "", ("muted", status or "未知", status or "Unknown"))


def power_controls(server_id: str, status: str | None) -> str:
    status = status or ""
    if status == "Running":
        return f"""
          <div class="power-panel power-running">
            <div>
              <div class="power-title">当前正在运行</div>
              <div class="power-copy">关机后会暂停自动启动，避免定时检查马上重新开机。</div>
            </div>
            <form method="post" action="/servers/power" onsubmit="return confirm('确认关机这台服务器？关机后会暂停自动启动，避免被定时任务重新开机。')">
              <input type="hidden" name="id" value="{esc(server_id)}">
              <input type="hidden" name="action" value="stop">
              <button class="btn btn-danger power-main-btn" type="submit">关机并暂停自动启动</button>
            </form>
          </div>
        """
    if status == "Stopped":
        return f"""
          <div class="power-panel power-stopped">
            <div>
              <div class="power-title">当前已关机</div>
              <div class="power-copy">开机后会恢复自动保护，后续仍按流量阈值巡检。</div>
            </div>
            <form method="post" action="/servers/power" onsubmit="return confirm('确认开机这台服务器？开机后会恢复自动保护。')">
              <input type="hidden" name="id" value="{esc(server_id)}">
              <input type="hidden" name="action" value="start">
              <button class="btn btn-primary power-main-btn" type="submit">开机并恢复自动保护</button>
            </form>
          </div>
        """
    return f"""
      <div class="power-panel power-muted">
        <div>
          <div class="power-title">当前状态：{esc(status or "未知")}</div>
          <div class="power-copy">实例处于过渡或未知状态，暂不提供电源操作。</div>
        </div>
        <button class="btn power-main-btn" type="button" disabled>等待状态更新</button>
      </div>
    """


def config_by_id(config: dict) -> dict[str, dict]:
    return {
        str(item.get("id") or item.get("instance_id")): item
        for item in config.get("instances", [])
    }


def selected_instance(config: dict, server_id: str | None) -> dict:
    if not server_id:
        return {}
    for item in config.get("instances", []):
        if str(item.get("id")) == server_id:
            return item
    return {}


def flash_message(code: str) -> str:
    messages = {
        "checked": "已完成一次手动检查",
        "balance_checked": "已查询阿里云账户余额",
        "saved": "服务器已保存并完成一次检查",
        "deleted": "服务器已删除",
        "started": "已提交开机指令，并恢复自动保护",
        "stopped": "已提交关机指令，自动启动已暂停",
        "power_failed": "电源操作失败，请查看服务器日志",
        "notify_saved": "通知设置已保存",
        "notify_test_sent": "已发送测试通知，请检查接收端",
        "notify_test_failed": "测试通知发送失败，请检查配置",
        "telegram_discovered": "已获取 Telegram 会话，请选择或复制 Chat ID",
        "telegram_discover_failed": "获取 Telegram Chat ID 失败，请确认 Bot Token 正确且你已经给机器人发过消息",
        "telegram_chat_saved": "Telegram Chat ID 已追加到已保存渠道",
        "telegram_chat_removed": "Telegram Chat ID 已移除",
        "domain_saved": "域名反代配置已保存，下面的配置片段已按新域名生成",
        "login_required": "请先登录",
        "login_failed": "用户名或密码不正确",
        "logged_out": "已退出登录",
    }
    return messages.get(code, code)


def flash_class(code: str) -> str:
    if code.endswith("_failed") or code in {"login_failed", "telegram_discover_failed"}:
        return "alert-danger"
    return "alert-success"


def web_credentials() -> tuple[str, str, dict[str, str]]:
    env = load_env(WEB_ENV_FILE)
    return env.get("WEB_USERNAME", "admin"), env.get("WEB_PASSWORD", ""), env


def session_secret(env: dict[str, str], password: str) -> bytes:
    secret = env.get("WEB_SESSION_SECRET") or password or "aliyun-cdt-guard"
    return secret.encode("utf-8")


def cookie_parts(header: str) -> dict[str, str]:
    cookies = {}
    for part in header.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        cookies[key.strip()] = value.strip()
    return cookies


def sign_session(username: str, expires: str, nonce: str, secret: bytes) -> str:
    payload = f"{username}|{expires}|{nonce}".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def build_session_cookie(username: str, env: dict[str, str], password: str) -> str:
    expires = str(int(time.time()) + int(env.get("WEB_SESSION_TTL", "86400")))
    nonce = secrets.token_hex(12)
    signature = sign_session(username, expires, nonce, session_secret(env, password))
    secure = "; Secure" if env.get("WEB_COOKIE_SECURE", "").lower() in {"1", "true", "yes"} else ""
    return f"cdt_guard_session={username}|{expires}|{nonce}|{signature}; Path=/; HttpOnly; SameSite=Lax{secure}"


def clear_session_cookie() -> str:
    return "cdt_guard_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"


def logout_marker_cookie() -> str:
    return "cdt_guard_logged_out=1; Path=/; HttpOnly; SameSite=Lax; Max-Age=300"


def clear_logout_marker_cookie() -> str:
    return "cdt_guard_logged_out=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"


def render_login_page(query: dict[str, list[str]] | None = None) -> bytes:
    query = query or {}
    flash = query.get("flash", [""])[0]
    flash_html = f'<div class="login-alert">{esc(flash_message(flash))}</div>' if flash else ""
    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>登录 - Aliyun CDT Guard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/css/tabler.min.css">
  <style>
    :root {{
      --font-sans: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      --ink: #111827;
      --muted: #64748b;
      --accent: #1763d1;
      --line: #e5e7eb;
    }}
    html, body {{ font-family: var(--font-sans); letter-spacing: 0; }}
    body {{
      min-height: 100vh;
      background:
        linear-gradient(135deg, rgba(23, 99, 209, .10), rgba(20, 131, 65, .07)),
        #f6f7f9;
      color: var(--ink);
      -webkit-font-smoothing: antialiased;
    }}
    .login-shell {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 420px;
      min-height: 100vh;
    }}
    .login-brand {{
      align-content: center;
      display: grid;
      padding: 56px;
    }}
    .brand-mark {{
      background: #111827;
      border-radius: 8px;
      color: #fff;
      display: inline-grid;
      font-weight: 760;
      height: 44px;
      margin-bottom: 26px;
      place-items: center;
      width: 44px;
    }}
    .login-title {{
      font-size: 34px;
      font-weight: 760;
      line-height: 1.18;
      margin: 0 0 14px;
      max-width: 620px;
    }}
    .login-copy {{
      color: var(--muted);
      font-size: 15px;
      line-height: 1.7;
      max-width: 600px;
    }}
    .feature-strip {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 28px;
    }}
    .feature-pill {{
      background: rgba(255,255,255,.72);
      border: 1px solid rgba(229,231,235,.86);
      border-radius: 999px;
      color: #475569;
      font-size: 12px;
      font-weight: 720;
      padding: 7px 10px;
    }}
    .login-panel {{
      align-content: center;
      background: rgba(255,255,255,.84);
      border-left: 1px solid rgba(229,231,235,.9);
      box-shadow: -20px 0 60px rgba(15, 23, 42, .06);
      display: grid;
      padding: 38px;
    }}
    .login-card {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 18px 52px rgba(15, 23, 42, .08);
      padding: 26px;
    }}
    .login-card h1 {{
      font-size: 22px;
      font-weight: 760;
      margin: 0 0 6px;
    }}
    .login-card .sub {{
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 22px;
    }}
    .form-control {{
      border-color: #d6d9df;
      border-radius: 8px;
      min-height: 44px;
    }}
    .form-control:focus {{
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(23, 99, 209, .12);
    }}
    .btn-primary {{
      background: var(--accent);
      border-color: var(--accent);
      border-radius: 7px;
      font-weight: 700;
      min-height: 44px;
      width: 100%;
    }}
    .login-alert {{
      background: #fff7df;
      border: 1px solid #ffd98a;
      border-radius: 8px;
      color: #8a5a00;
      font-size: 13px;
      margin-bottom: 14px;
      padding: 10px 12px;
    }}
    .login-foot {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.6;
      margin-top: 16px;
    }}
    @media (max-width: 900px) {{
      .login-shell {{ grid-template-columns: 1fr; }}
      .login-brand {{ padding: 34px 22px 14px; }}
      .login-panel {{ border-left: 0; box-shadow: none; padding: 22px; }}
      .login-title {{ font-size: 28px; }}
    }}
  </style>
</head>
<body>
  <main class="login-shell">
    <section class="login-brand">
      <div>
        <div class="brand-mark">CDT</div>
        <h1 class="login-title">Aliyun CDT Guard</h1>
        <p class="login-copy">集中管理阿里云 ECS、CDT 共享流量池、自动启停保护、历史曲线和通知报告。适合用域名反代后作为长期运维面板。</p>
        <div class="feature-strip">
          <span class="feature-pill">CDT 共享池保护</span>
          <span class="feature-pill">ECS 启停控制</span>
          <span class="feature-pill">Telegram 通知</span>
          <span class="feature-pill">每日流量报告</span>
        </div>
      </div>
    </section>
    <section class="login-panel">
      <form class="login-card" method="post" action="/login">
        <h1>登录面板</h1>
        <div class="sub">请输入安装时生成的后台账号密码</div>
        {flash_html}
        <div class="mb-3">
          <label class="form-label">用户名</label>
          <input class="form-control" name="username" autocomplete="username" required autofocus>
        </div>
        <div class="mb-3">
          <label class="form-label">密码</label>
          <input class="form-control" type="password" name="password" autocomplete="current-password" required>
        </div>
        <button class="btn btn-primary" type="submit">登录</button>
        <div class="login-foot">建议通过 HTTPS 反向代理访问，并限制面板源站端口只允许本机或可信 IP 访问。</div>
      </form>
    </section>
  </main>
</body>
</html>
"""
    return html_doc.encode("utf-8")


def page_shell(active: str, title: str, subtitle: str, body: str, actions: str = "", flash: str = "", auto_refresh: bool = True) -> bytes:
    nav = [
        ("/", "overview", "总览"),
        ("/servers/new", "servers", "新增/编辑"),
        ("/logs", "logs", "服务器日志"),
        ("/notifications", "notifications", "通知设置"),
        ("/domain", "domain", "域名反代"),
    ]
    nav_html = "".join(
        f'<li class="nav-item {"active" if key == active else ""}"><a class="nav-link" href="{href}"><span class="nav-link-title">{label}</span></a></li>'
        for href, key, label in nav
    )
    flash_html = f'<div class="alert {flash_class(flash)}">{esc(flash_message(flash))}</div>' if flash else ""
    refresh_meta = '<meta http-equiv="refresh" content="60">' if auto_refresh else ""
    header_actions = f"""
      {actions}
      <a class="logout-link" href="/logout" aria-label="退出登录">退出登录</a>
    """
    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {refresh_meta}
  <title>Aliyun CDT Guard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/css/tabler.min.css">
  <style>
    :root {{
      --font-sans: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      --page-bg: #f6f7f9;
      --surface: #ffffff;
      --surface-soft: #fafbfc;
      --line: #e5e7eb;
      --line-strong: #d6d9df;
      --ink: #1f2937;
      --muted: #6b7280;
      --accent: #1763d1;
      --accent-soft: #eaf2ff;
      --success-soft: #e9f8ef;
      --warning-soft: #fff7df;
      --danger-soft: #ffeded;
    }}
    html, body {{
      font-family: var(--font-sans);
      letter-spacing: 0;
    }}
    body {{
      background:
        radial-gradient(circle at top left, rgba(23, 99, 209, 0.06), transparent 360px),
        var(--page-bg);
      color: var(--ink);
      -webkit-font-smoothing: antialiased;
      text-rendering: optimizeLegibility;
    }}
    .page {{ min-height: 100vh; }}
    .navbar-vertical {{
      width: 248px;
      background: #111827;
      border-right: 1px solid rgba(255,255,255,0.06);
      box-shadow: 0 24px 70px rgba(15, 23, 42, 0.12);
    }}
    .navbar-brand {{
      align-items: flex-start;
      color: #fff;
      font-size: 18px;
      font-weight: 720;
      letter-spacing: 0;
      line-height: 1.2;
      padding: 24px 22px 14px;
    }}
    .navbar .nav-link {{
      border-radius: 8px;
      color: #b7c0cf;
      font-size: 14px;
      margin: 3px 12px;
      padding: 10px 12px;
      transition: background .15s ease, color .15s ease;
    }}
    .navbar .nav-link:hover {{
      background: rgba(255,255,255,0.07);
      color: #fff;
    }}
    .navbar .nav-item.active .nav-link {{
      background: rgba(255,255,255,0.11);
      color: #fff;
      font-weight: 650;
    }}
    .page-wrapper {{
      min-height: 100vh;
      background: transparent;
    }}
    .navbar-expand-md.d-print-none {{
      background: rgba(255,255,255,0.86);
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(12px);
      min-height: 74px;
    }}
    .container-xl {{
      max-width: 1500px;
      padding-left: 32px;
      padding-right: 32px;
    }}
    .page-body {{ margin-top: 24px; }}
    .page-title {{
      color: #111827;
      font-size: 24px;
      font-weight: 720;
      letter-spacing: 0;
      line-height: 1.25;
    }}
    .text-secondary {{ color: var(--muted) !important; }}
    .card {{
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 10px 34px rgba(15, 23, 42, 0.04);
    }}
    .card-header {{
      background: var(--surface);
      border-bottom: 1px solid var(--line);
      min-height: 64px;
      padding: 18px 22px;
    }}
    .card-title {{
      color: #111827;
      font-size: 16px;
      font-weight: 720;
      letter-spacing: 0;
    }}
    .stat-card .card-body {{ padding: 18px 20px; }}
    .stat-card .subheader {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 680;
      letter-spacing: 0;
      text-transform: none;
    }}
    .stat-card .h1 {{
      color: #111827;
      font-size: 30px;
      font-weight: 720;
      margin-top: 8px;
    }}
    .stat-card .stat-line {{
      height: 3px;
      border-radius: 999px;
      background: var(--accent-soft);
      margin-top: 14px;
      overflow: hidden;
    }}
    .stat-card .stat-line span {{ display: block; height: 100%; width: 40%; background: var(--accent); }}
    .stat-card.is-warning {{
      border-color: #ffd98a;
      box-shadow: 0 10px 34px rgba(245, 159, 0, 0.10);
    }}
    .stat-card.is-danger {{
      border-color: #ffc0c0;
      box-shadow: 0 10px 34px rgba(214, 57, 57, 0.10);
    }}
    .stat-card.is-muted {{
      box-shadow: none;
    }}
    .table {{
      --tblr-table-bg: transparent;
      color: var(--ink);
      font-size: 14px;
    }}
    .table thead th {{
      background: var(--surface-soft);
      border-bottom: 1px solid var(--line);
      color: #687386;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      padding: 13px 16px;
      white-space: nowrap;
    }}
    .table tbody td {{
      border-color: var(--line);
      padding: 18px 16px;
      vertical-align: middle;
    }}
    .table tbody tr:hover {{ background: #fbfcfe; }}
    .asset-name {{
      color: #111827;
      font-size: 15px;
      font-weight: 720;
      line-height: 1.35;
    }}
    .asset-sub {{ color: var(--muted); font-size: 12px; margin-top: 3px; }}
    .server-name-stack {{
      display: block;
      max-width: 100%;
      min-width: 0;
    }}
    .account-balance-line {{
      align-items: center;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 7px;
      min-width: 0;
    }}
    .account-key {{
      color: #667085;
      flex: 0 1 auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 11px;
      max-width: 100%;
      min-width: 0;
    }}
    .account-balance-pill {{
      align-items: center;
      background: #edf7f1;
      border: 1px solid #cfe8d8;
      border-radius: 999px;
      color: #14733a;
      display: inline-flex;
      font-size: 11px;
      font-weight: 720;
      line-height: 1;
      max-width: 100%;
      padding: 5px 8px;
      white-space: nowrap;
    }}
    .account-balance-pill.is-warning {{
      background: #fff7e6;
      border-color: #f4d18b;
      color: #9a6700;
    }}
    .account-balance-pill.is-danger {{
      background: #fff0f0;
      border-color: #f3b5b5;
      color: #b42323;
    }}
    .form-label-row {{
      align-items: center;
      display: flex;
      gap: 10px;
      justify-content: space-between;
    }}
    .form-doc-link {{
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      text-decoration: none;
      white-space: nowrap;
    }}
    .form-doc-link:hover {{ text-decoration: underline; }}
    .pool-option-list {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }}
    .pool-option-chip {{
      background: #f4f7fb;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: #42526b;
      font-size: 11px;
      font-weight: 700;
      line-height: 1;
      padding: 6px 9px;
    }}
    .pool-auto-advice {{
      background: #eef6ff;
      border: 1px solid #bfdbfe;
      border-radius: 8px;
      color: #174ea6;
      font-size: 12px;
      line-height: 1.55;
      margin-bottom: 8px;
      padding: 10px 12px;
    }}
    .pool-auto-advice strong {{
      color: #0f3f8c;
      display: block;
      font-size: 13px;
      margin-bottom: 2px;
    }}
    .ip-main {{
      color: #111827;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 15px;
      font-weight: 650;
    }}
    .progress {{
      background: #edf0f4;
      height: 7px;
      overflow: hidden;
    }}
    .badge {{
      border-radius: 999px;
      font-weight: 680;
      padding: 4px 9px;
    }}
    .btn {{
      border-radius: 7px;
      font-weight: 650;
      letter-spacing: 0;
    }}
    .btn-primary {{
      background: var(--accent);
      border-color: var(--accent);
      box-shadow: 0 8px 18px rgba(23, 99, 209, 0.18);
    }}
    .page-actions {{
      align-items: center;
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: flex-end;
    }}
    .logout-link {{
      align-items: center;
      background: #fff7f7;
      border: 1px solid #f1b5b5;
      border-radius: 8px;
      color: #b42323;
      display: inline-flex;
      font-size: 13px;
      font-weight: 720;
      height: 38px;
      justify-content: center;
      line-height: 1;
      padding: 0 14px;
      text-decoration: none;
      transition: background .15s ease, border-color .15s ease, box-shadow .15s ease, color .15s ease, transform .15s ease;
      white-space: nowrap;
    }}
    .logout-link:hover {{
      background: #fee2e2;
      border-color: #e47a7a;
      box-shadow: 0 8px 18px rgba(180, 35, 35, .10);
      color: #8f1d1d;
      text-decoration: none;
      transform: translateY(-1px);
    }}
    .logout-link:active {{ transform: translateY(0); }}
    .run-check-form.is-submitting .btn {{
      cursor: wait;
      opacity: .85;
    }}
    .asset-workspace {{
      display: grid;
      gap: 16px;
      grid-template-columns: minmax(0, 1fr) 392px;
      padding: 16px;
    }}
    .asset-list-panel {{
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow-x: auto;
      overflow-y: hidden;
      min-width: 0;
    }}
    .asset-filter-bar {{
      align-items: center;
      background: var(--surface-soft);
      border-bottom: 1px solid var(--line);
      display: grid;
      gap: 10px;
      grid-template-columns: minmax(220px, 1fr) 156px 156px;
      padding: 12px;
    }}
    .asset-count-line {{
      color: var(--muted);
      font-size: 12px;
      padding: 10px 14px;
    }}
    .server-list {{
      display: grid;
      max-height: 68vh;
      overflow-x: visible;
      overflow-y: auto;
    }}
    .server-group {{
      background: #fff;
      border-bottom: 1px solid var(--line);
      min-width: 980px;
    }}
    .server-group-head {{
      align-items: center;
      background: #fbfcff;
      border-bottom: 1px solid var(--line);
      display: grid;
      gap: 12px;
      grid-template-columns: minmax(260px, 1fr) auto;
      padding: 12px 14px;
    }}
    .server-group-title {{
      color: #111827;
      font-size: 14px;
      font-weight: 780;
      line-height: 1.3;
    }}
    .server-group-sub {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
      margin-top: 3px;
    }}
    .server-group-metrics {{
      align-items: center;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      justify-content: flex-end;
    }}
    .server-group-pill {{
      background: #eef2f6;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: #42526b;
      font-size: 11px;
      font-weight: 730;
      line-height: 1;
      padding: 6px 9px;
      white-space: nowrap;
    }}
    .server-group-pill.is-danger {{
      background: #fff0f0;
      border-color: #f3b5b5;
      color: #b42323;
    }}
    .server-group-pill.is-warning {{
      background: #fff7e6;
      border-color: #f4d18b;
      color: #9a6700;
    }}
    .server-group-body {{
      display: grid;
    }}
    .server-list-head,
    .server-row {{
      display: grid;
      gap: 12px;
      grid-template-columns: 126px minmax(210px, 1.4fr) minmax(126px, .8fr) 112px minmax(190px, 1fr) 132px;
      min-width: 980px;
    }}
    .server-list-head {{
      background: #f7f9fc;
      border-bottom: 1px solid var(--line);
      color: #687386;
      font-size: 12px;
      font-weight: 720;
      padding: 10px 14px;
      position: sticky;
      top: 0;
      z-index: 2;
    }}
    .server-row {{
      background: #fff;
      border: 0;
      border-bottom: 1px solid var(--line);
      color: var(--ink);
      cursor: pointer;
      padding: 14px;
      text-align: left;
      width: 100%;
    }}
    .server-row:hover {{ background: #fbfcfe; }}
    .server-row.active {{
      background: #eef5ff;
      box-shadow: inset 3px 0 0 var(--accent);
    }}
    .server-row:focus-visible {{
      outline: 3px solid rgba(23, 99, 209, .16);
      outline-offset: -3px;
    }}
    .server-row.is-danger {{ box-shadow: inset 3px 0 0 #d63939; }}
    .server-row.is-warning {{ box-shadow: inset 3px 0 0 #f59f00; }}
    .server-row.active.is-danger,
    .server-row.active.is-warning {{ background: #fffaf2; }}
    .server-cell {{
      align-items: center;
      display: flex;
      min-width: 0;
    }}
    .server-state {{
      align-items: center;
      border-radius: 8px;
      display: inline-flex;
      gap: 8px;
      min-width: 102px;
      padding: 8px 10px;
      white-space: nowrap;
    }}
    .server-state-dot {{
      border-radius: 999px;
      display: block;
      height: 9px;
      width: 9px;
    }}
    .server-state.running {{ background: var(--success-soft); color: #148341; }}
    .server-state.running .server-state-dot {{ background: #22c55e; box-shadow: 0 0 0 4px rgba(34, 197, 94, .12); }}
    .server-state.stopped {{ background: var(--danger-soft); color: #c92a2a; }}
    .server-state.stopped .server-state-dot {{ background: #ef4444; box-shadow: 0 0 0 4px rgba(239, 68, 68, .12); }}
    .server-state.pending {{ background: var(--warning-soft); color: #b7791f; }}
    .server-state.pending .server-state-dot {{ background: #f59f00; box-shadow: 0 0 0 4px rgba(245, 159, 0, .14); }}
    .server-state.muted {{ background: #eef2f6; color: #64748b; }}
    .server-state.muted .server-state-dot {{ background: #94a3b8; }}
    .server-state-main {{ font-weight: 760; line-height: 1; }}
    .server-state-sub {{ color: currentColor; display: block; font-size: 11px; opacity: .75; }}
    .server-state-detail {{
      align-items: flex-start;
      border-radius: 8px;
      display: flex;
      gap: 10px;
      padding: 12px;
    }}
    .server-state-detail.running {{ background: var(--success-soft); color: #148341; }}
    .server-state-detail.stopped {{ background: var(--danger-soft); color: #c92a2a; }}
    .server-state-detail.pending {{ background: var(--warning-soft); color: #b7791f; }}
    .server-state-detail.muted {{ background: #eef2f6; color: #64748b; }}
    .server-detail-panel {{
      align-self: start;
      border: 1px solid var(--line);
      border-radius: 8px;
      min-width: 0;
      overflow: hidden;
      position: sticky;
      top: 88px;
    }}
    .server-detail {{
      display: none;
    }}
    .server-detail.active {{
      display: grid;
      gap: 14px;
      padding: 16px;
    }}
    .detail-section {{
      border-top: 1px solid var(--line);
      padding-top: 14px;
    }}
    .detail-section:first-child {{
      border-top: 0;
      padding-top: 0;
    }}
    .detail-grid {{
      display: grid;
      gap: 10px 14px;
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }}
    .detail-item {{ min-width: 0; }}
    .detail-disclosure > summary {{
      align-items: center;
      color: #111827;
      cursor: pointer;
      display: flex;
      font-size: 13px;
      font-weight: 760;
      justify-content: space-between;
      list-style: none;
    }}
    .detail-disclosure > summary::-webkit-details-marker {{ display: none; }}
    .detail-disclosure > summary::after {{
      color: var(--muted);
      content: "展开";
      font-size: 12px;
      font-weight: 720;
    }}
    .detail-disclosure[open] > summary::after {{ content: "收起"; }}
    .info-label {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 720;
      margin-bottom: 8px;
    }}
    .info-value {{
      color: #111827;
      font-size: 15px;
      font-weight: 650;
      line-height: 1.45;
    }}
    .note-cell {{ white-space: pre-wrap; }}
    .traffic-row {{
      align-items: center;
      display: grid;
      gap: 12px;
      grid-template-columns: minmax(0, 1fr) auto;
    }}
    .traffic-value {{
      color: #111827;
      font-size: 18px;
      font-weight: 720;
    }}
    .reset-summary {{
      align-items: center;
      background: linear-gradient(135deg, #f8fafc 0%, #ffffff 100%);
      border: 1px solid var(--line);
      border-radius: 8px;
      display: grid;
      gap: 14px;
      grid-template-columns: minmax(0, 1fr) auto;
      padding: 14px;
    }}
    .reset-summary.recovery-ok {{
      background: linear-gradient(135deg, #f1fbf5 0%, #ffffff 100%);
      border-color: #bde8ca;
    }}
    .reset-summary.recovery-paused {{
      background: linear-gradient(135deg, #fff8e7 0%, #ffffff 100%);
      border-color: #ffd98a;
    }}
    .reset-eyebrow {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 760;
      margin-bottom: 6px;
    }}
    .reset-time {{
      color: #111827;
      font-size: 20px;
      font-weight: 760;
      line-height: 1.2;
    }}
    .reset-source {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
      margin-top: 6px;
    }}
    .reset-count {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      min-width: 118px;
      padding: 10px 12px;
      text-align: center;
    }}
    .reset-foot {{
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      font-size: 12px;
      gap: 8px 14px;
      justify-content: space-between;
      margin-top: 8px;
    }}
    .traffic-delta {{
      border-radius: 999px;
      display: inline-flex;
      font-size: 12px;
      font-weight: 720;
      padding: 3px 8px;
    }}
    .traffic-delta.up {{ background: var(--warning-soft); color: #b7791f; }}
    .traffic-delta.flat {{ background: #eef2f6; color: #64748b; }}
    .traffic-delta.down {{ background: var(--success-soft); color: #148341; }}
    .pool-chip {{
      background: #eef2f6;
      border: 1px solid var(--line);
      border-radius: 7px;
      color: #475569;
      display: inline-flex;
      font-size: 12px;
      font-weight: 720;
      padding: 5px 8px;
    }}
    .breakdown-list {{
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }}
    .breakdown-row {{
      align-items: center;
      border-top: 1px solid var(--line);
      display: flex;
      gap: 12px;
      justify-content: space-between;
      padding: 10px 12px;
    }}
    .breakdown-row:first-child {{ border-top: 0; }}
    .product-code {{
      background: #eef2f6;
      border-radius: 6px;
      color: #475569;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      padding: 2px 6px;
    }}
    .traffic-compact {{
      min-width: 0;
      width: 100%;
    }}
    .traffic-meta {{
      align-items: center;
      display: flex;
      gap: 8px;
      justify-content: space-between;
      margin-bottom: 6px;
    }}
    .traffic-amount {{
      color: #111827;
      font-weight: 720;
    }}
    .sparkline {{
      display: block;
      height: 28px;
      margin-top: 7px;
      width: 100%;
    }}
    .sparkline path {{
      fill: none;
      stroke: var(--accent);
      stroke-linecap: round;
      stroke-linejoin: round;
      stroke-width: 2;
    }}
    .sparkline .area {{ fill: rgba(23, 99, 209, .08); stroke: none; }}
    .chart-trigger {{
      background: transparent;
      border: 0;
      color: var(--accent);
      display: inline-flex;
      font-size: 12px;
      font-weight: 720;
      margin-top: 6px;
      padding: 0;
    }}
    .chart-trigger:hover {{ text-decoration: underline; }}
    .traffic-modal {{
      background: rgba(15, 23, 42, .42);
      display: none;
      inset: 0;
      padding: 28px;
      position: fixed;
      z-index: 50;
    }}
    .traffic-modal.is-open {{
      align-items: center;
      display: flex;
      justify-content: center;
    }}
    .traffic-modal-card {{
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 28px 80px rgba(15, 23, 42, .22);
      display: grid;
      max-height: calc(100vh - 56px);
      max-width: 980px;
      overflow: hidden;
      width: min(980px, 100%);
    }}
    .traffic-modal-head {{
      align-items: flex-start;
      border-bottom: 1px solid var(--line);
      display: flex;
      gap: 16px;
      justify-content: space-between;
      padding: 18px 20px;
    }}
    .traffic-modal-body {{
      display: grid;
      gap: 16px;
      overflow: auto;
      padding: 18px 20px 20px;
    }}
    .range-tabs {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .range-tab {{
      background: #fff;
      border: 1px solid var(--line-strong);
      border-radius: 7px;
      color: #475569;
      font-size: 13px;
      font-weight: 720;
      padding: 8px 12px;
    }}
    .range-tab.active {{
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }}
    .chart-stats {{
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }}
    .chart-stat {{
      background: var(--surface-soft);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
    }}
    .chart-stat-label {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 720;
      margin-bottom: 4px;
    }}
    .chart-stat-value {{
      color: #111827;
      font-size: 18px;
      font-weight: 760;
    }}
    .traffic-chart-wrap {{
      border: 1px solid var(--line);
      border-radius: 8px;
      min-height: 320px;
      overflow: hidden;
      position: relative;
    }}
    .traffic-chart {{
      display: block;
      min-height: 320px;
      width: 100%;
    }}
    .chart-legend {{
      align-items: center;
      background: rgba(255, 255, 255, .88);
      border: 1px solid var(--line);
      border-radius: 7px;
      display: flex;
      gap: 12px;
      left: 14px;
      padding: 6px 8px;
      position: absolute;
      top: 12px;
      z-index: 1;
    }}
    .legend-item {{
      align-items: center;
      color: #475569;
      display: inline-flex;
      font-size: 12px;
      font-weight: 720;
      gap: 6px;
    }}
    .legend-line {{
      background: var(--accent);
      border-radius: 999px;
      height: 3px;
      width: 22px;
    }}
    .legend-bar {{
      background: rgba(245, 159, 0, .42);
      border-radius: 3px;
      height: 12px;
      width: 12px;
    }}
    .chart-empty {{
      align-items: center;
      color: var(--muted);
      display: none;
      inset: 0;
      justify-content: center;
      padding: 24px;
      position: absolute;
      text-align: center;
    }}
    .chart-empty.show {{ display: flex; }}
    .chart-tooltip {{
      background: #111827;
      border-radius: 7px;
      color: #fff;
      display: none;
      font-size: 12px;
      line-height: 1.5;
      max-width: 220px;
      padding: 8px 10px;
      pointer-events: none;
      position: absolute;
      transform: translate(-50%, -110%);
      z-index: 2;
    }}
    .traffic-table-wrap {{
      border: 1px solid var(--line);
      border-radius: 8px;
      max-height: 260px;
      overflow: auto;
    }}
    .traffic-table {{
      margin: 0;
      width: 100%;
    }}
    .btn-list form {{ display: inline-block; margin: 0; }}
    .power-panel {{
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 8px;
      display: flex;
      gap: 14px;
      justify-content: space-between;
      padding: 14px 15px;
    }}
    .power-running {{ background: #fffafa; border-color: #ffd5d5; }}
    .power-stopped {{ background: #f6f9ff; border-color: #cfe0ff; }}
    .power-muted {{ background: #f8fafc; }}
    .power-title {{
      color: #111827;
      font-weight: 760;
      margin-bottom: 3px;
    }}
    .power-copy {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
      max-width: 420px;
    }}
    .power-main-btn {{ min-width: 168px; }}
    .recovery-panel {{
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 8px;
      display: flex;
      gap: 14px;
      justify-content: space-between;
      padding: 14px 15px;
    }}
    .recovery-ok {{ background: #f1fbf5; border-color: #bde8ca; }}
    .recovery-paused {{ background: #fff7df; border-color: #ffd98a; }}
    .recovery-neutral {{ background: #f8fafc; }}
    .recovery-title {{
      color: #111827;
      font-weight: 760;
      margin-bottom: 3px;
    }}
    .recovery-copy {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
    }}
    .recovery-count {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      min-width: 92px;
      padding: 9px 10px;
      text-align: center;
    }}
    .recovery-days {{
      color: #111827;
      font-size: 24px;
      font-weight: 760;
      line-height: 1;
    }}
    .reset-duration {{
      color: #111827;
      font-size: 16px;
      font-weight: 760;
      line-height: 1.15;
      overflow-wrap: normal;
      white-space: nowrap;
    }}
    .recovery-unit {{
      color: var(--muted);
      font-size: 12px;
      margin-top: 4px;
    }}
    .detail-actions {{
      align-items: center;
      display: flex;
      gap: 8px;
      justify-content: space-between;
    }}
    .delete-form {{ margin: 0; }}
    .empty-state {{
      color: var(--muted);
      padding: 32px 18px;
      text-align: center;
    }}
    .kbd-soft {{
      background: #eef2f6;
      border-radius: 6px;
      color: #475569;
      font-size: 12px;
      padding: 2px 6px;
    }}
    .form-control, .form-select {{
      border-color: var(--line-strong);
      border-radius: 8px;
      min-height: 42px;
    }}
    .form-control:focus {{
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(23, 99, 209, 0.12);
    }}
    .form-label {{ color: #1f2937; font-weight: 680; }}
    .form-hint {{ margin-top: 5px; }}
    .form-layout {{
      align-items: start;
      display: grid;
      gap: 18px;
      grid-template-columns: minmax(0, 1fr) 340px;
      margin: 0 auto;
      max-width: 1180px;
    }}
    .form-section {{
      border-top: 1px solid var(--line);
      padding-top: 22px;
    }}
    .form-section:first-child {{
      border-top: 0;
      padding-top: 0;
    }}
    .form-section-title {{
      color: #111827;
      font-size: 15px;
      font-weight: 760;
      margin: 0 0 14px;
    }}
    .guide-panel {{
      position: sticky;
      top: 94px;
    }}
    .guide-panel .card-body {{
      display: grid;
      gap: 16px;
      padding: 18px;
    }}
    .guide-step {{
      border-left: 3px solid var(--line);
      padding-left: 12px;
    }}
    .guide-step strong {{
      color: #111827;
      display: block;
      font-size: 13px;
      margin-bottom: 4px;
    }}
    .guide-step span {{
      color: var(--muted);
      display: block;
      font-size: 12px;
      line-height: 1.55;
    }}
    .submit-feedback {{
      align-items: center;
      color: var(--muted);
      display: none;
      font-size: 13px;
      gap: 8px;
      margin-right: auto;
    }}
    .save-form.is-submitting .submit-feedback {{ display: inline-flex; }}
    .save-form.is-submitting .btn-submit {{
      cursor: wait;
      opacity: .85;
    }}
    .spinner-dot {{
      animation: spin .75s linear infinite;
      border: 2px solid rgba(23, 99, 209, .18);
      border-radius: 999px;
      border-top-color: var(--accent);
      display: inline-block;
      height: 16px;
      width: 16px;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    .credential-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }}
    .channel-status {{
      background: var(--surface-soft);
      border: 1px solid var(--line);
      border-radius: 8px;
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      margin-bottom: 16px;
      padding: 14px;
    }}
    .channel-status-item {{ min-width: 0; }}
    .channel-status-label {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 720;
      margin-bottom: 4px;
    }}
    .channel-status-value {{
      color: #111827;
      font-size: 14px;
      font-weight: 720;
      overflow-wrap: anywhere;
    }}
    .setup-box {{
      background: #f8fafc;
      border: 1px solid var(--line);
      border-radius: 8px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
      margin: 10px 0 16px;
      padding: 12px 14px;
    }}
    .proxy-grid {{
      display: grid;
      gap: 16px;
      grid-template-columns: minmax(0, 1fr) 360px;
    }}
    .proxy-step-grid {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }}
    .proxy-step-card {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .proxy-step-card strong {{
      color: #111827;
      display: block;
      font-size: 14px;
      margin-bottom: 6px;
    }}
    .proxy-step-card span {{
      color: var(--muted);
      display: block;
      font-size: 12px;
      line-height: 1.55;
    }}
    .config-block {{
      background: #0f172a;
      border-radius: 8px;
      color: #e5edf7;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.65;
      margin: 10px 0 0;
      overflow-x: auto;
      padding: 14px;
      white-space: pre;
    }}
    .status-note {{
      background: #eef6ff;
      border: 1px solid #bfdbfe;
      border-radius: 8px;
      color: #174ea6;
      font-size: 13px;
      line-height: 1.6;
      padding: 12px 14px;
    }}
    .chat-candidates {{
      border: 1px solid var(--line);
      border-radius: 8px;
      display: grid;
      margin-top: 12px;
      overflow: hidden;
    }}
    .chat-candidate {{
      align-items: center;
      border-top: 1px solid var(--line);
      display: grid;
      gap: 12px;
      grid-template-columns: minmax(0, 1fr) auto;
      padding: 12px;
    }}
    .chat-candidate:first-child {{ border-top: 0; }}
    .chat-id-code {{
      background: #eef2f6;
      border-radius: 6px;
      color: #475569;
      display: inline-block;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      margin-top: 4px;
      padding: 3px 6px;
    }}
    .telegram-command-grid {{
      display: grid;
      gap: 8px;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      margin-top: 10px;
    }}
    .telegram-command {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px 12px;
    }}
    .telegram-command code {{
      color: #111827;
      font-size: 12px;
      font-weight: 720;
    }}
    .telegram-command span {{
      color: var(--muted);
      display: block;
      font-size: 12px;
      line-height: 1.45;
      margin-top: 4px;
    }}
    .saved-channel-grid {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      margin-top: 12px;
    }}
    .saved-channel-card {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      display: grid;
      gap: 12px;
      padding: 14px;
    }}
    .saved-channel-head {{
      align-items: center;
      display: flex;
      gap: 10px;
      min-width: 0;
    }}
    .saved-channel-icon {{
      align-items: center;
      background: #eaf3ff;
      border: 1px solid #cfe4ff;
      border-radius: 8px;
      color: #1763d1;
      display: inline-flex;
      flex: 0 0 38px;
      font-size: 12px;
      font-weight: 820;
      height: 38px;
      justify-content: center;
      width: 38px;
    }}
    .saved-channel-title {{
      color: #111827;
      font-size: 14px;
      font-weight: 820;
      overflow-wrap: anywhere;
    }}
    .saved-channel-subtitle {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
      overflow-wrap: anywhere;
    }}
    .saved-channel-meta {{
      color: #374151;
      display: grid;
      gap: 6px;
      font-size: 12px;
      line-height: 1.45;
    }}
    .saved-channel-badge {{
      background: #f1f5f9;
      border-radius: 999px;
      color: #475569;
      display: inline-flex;
      font-size: 12px;
      font-weight: 720;
      justify-self: start;
      padding: 4px 8px;
    }}
    .saved-channel-badge.is-on {{
      background: #e8f8ee;
      color: #177245;
    }}
    .saved-channel-actions {{
      align-items: center;
      display: flex;
      gap: 8px;
      justify-content: space-between;
    }}
    .log-layout {{ display: grid; grid-template-columns: 300px minmax(0, 1fr); gap: 18px; }}
    .log-item summary {{ cursor: pointer; list-style: none; }}
    .log-item summary::-webkit-details-marker {{ display: none; }}
    .log-meta {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 18px; }}
    .log-filter-tabs {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .log-filter-tab {{
      border: 1px solid var(--line);
      border-radius: 999px;
      color: #475569;
      font-size: 12px;
      font-weight: 720;
      padding: 6px 10px;
      text-decoration: none;
    }}
    .log-filter-tab.active {{
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }}
    .log-filter-tab:hover {{ text-decoration: none; }}
    .log-note {{
      background: #f8fafc;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
      font-size: 12px;
      line-height: 1.55;
      padding: 10px 14px;
    }}
    .grid-full {{ grid-column: 1 / -1; }}
    .asset-toolbar {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; }}
    @media (max-width: 1180px) {{
      .asset-workspace {{ grid-template-columns: 1fr; }}
      .form-layout {{ grid-template-columns: 1fr; }}
      .guide-panel {{ position: static; }}
      .server-detail-panel {{ position: static; }}
      .server-list {{ max-height: none; }}
    }}
    @media (max-width: 992px) {{
      .navbar-vertical {{ width: 100%; }}
      .container-xl {{ padding-left: 16px; padding-right: 16px; }}
      .credential-grid, .log-layout, .log-meta, .asset-filter-bar, .detail-grid {{ grid-template-columns: 1fr; }}
      .proxy-grid {{ grid-template-columns: 1fr; }}
      .channel-status {{ grid-template-columns: 1fr; }}
      .chat-candidate {{ grid-template-columns: 1fr; }}
      .telegram-command-grid {{ grid-template-columns: 1fr; }}
      .power-panel {{ align-items: flex-start; flex-direction: column; }}
      .table-responsive {{ min-height: 0; }}
    }}
    @media (max-width: 640px) {{
      .navbar-expand-md.d-print-none .container-xl {{
        align-items: flex-start;
        flex-direction: column;
        gap: 12px;
      }}
      .navbar-nav.flex-row.order-md-last.ms-auto {{ margin-left: 0 !important; }}
      .page-title {{ font-size: 22px; }}
      .asset-toolbar {{ align-items: flex-start; flex-direction: column; }}
      .asset-workspace {{ padding: 10px; }}
      .server-list-head {{ display: none; }}
      .server-group {{ min-width: 0; }}
      .server-group-head {{
        grid-template-columns: 1fr;
        padding: 12px;
      }}
      .server-group-metrics {{ justify-content: flex-start; }}
      .server-row {{
        gap: 10px;
        grid-template-columns: 1fr;
        min-width: 0;
        padding: 12px;
      }}
      .server-cell {{
        align-items: flex-start;
        display: block;
      }}
      .server-state {{ min-width: 0; }}
      .traffic-compact {{ display: block; }}
      .server-detail.active {{ padding: 14px; }}
      .traffic-modal {{ padding: 10px; }}
      .traffic-modal-head {{ flex-direction: column; }}
      .traffic-modal-body {{ padding: 14px; }}
      .chart-stats {{ grid-template-columns: 1fr 1fr; }}
      .card-footer.d-flex {{
        align-items: stretch !important;
        flex-direction: column;
      }}
      .submit-feedback {{ margin-right: 0; }}
      .btn-submit.ms-auto {{ margin-left: 0 !important; }}
      .detail-actions {{ align-items: stretch; flex-direction: column; }}
      .detail-actions .btn, .detail-actions .delete-form {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <aside class="navbar navbar-vertical navbar-expand-lg" data-bs-theme="dark">
      <div class="container-fluid">
        <h1 class="navbar-brand navbar-brand-autodark">Aliyun CDT Guard</h1>
        <div class="collapse navbar-collapse show">
          <ul class="navbar-nav pt-lg-3">{nav_html}</ul>
        </div>
      </div>
    </aside>
    <div class="page-wrapper">
      <header class="navbar navbar-expand-md d-print-none">
        <div class="container-xl">
          <div>
            <h2 class="page-title">{esc(title)}</h2>
            <div class="text-secondary small">{esc(subtitle)}</div>
          </div>
          <div class="navbar-nav flex-row order-md-last ms-auto page-actions">{header_actions}</div>
        </div>
      </header>
      <div class="page-body">
        <div class="container-xl">
          {flash_html}
          {body}
        </div>
      </div>
    </div>
  </div>
  <div class="traffic-modal" data-traffic-modal aria-hidden="true">
    <div class="traffic-modal-card" role="dialog" aria-modal="true" aria-labelledby="traffic-modal-title">
      <div class="traffic-modal-head">
        <div>
          <h3 class="card-title mb-1" id="traffic-modal-title">流量曲线</h3>
          <div class="text-secondary small" data-chart-server>选择服务器查看历史流量</div>
        </div>
        <button class="btn btn-sm" type="button" data-chart-close>关闭</button>
      </div>
      <div class="traffic-modal-body">
        <div class="range-tabs" data-chart-ranges>
          <button class="range-tab active" type="button" data-days="1">1 天</button>
          <button class="range-tab" type="button" data-days="3">3 天</button>
          <button class="range-tab" type="button" data-days="7">7 天</button>
          <button class="range-tab" type="button" data-days="30">1 个月</button>
        </div>
        <div class="chart-stats">
          <div class="chart-stat"><div class="chart-stat-label">期间新增</div><div class="chart-stat-value" data-chart-total>--</div></div>
          <div class="chart-stat"><div class="chart-stat-label">当前累计</div><div class="chart-stat-value" data-chart-last>--</div></div>
          <div class="chart-stat"><div class="chart-stat-label">检查点</div><div class="chart-stat-value" data-chart-count>--</div></div>
          <div class="chart-stat"><div class="chart-stat-label">时间范围</div><div class="chart-stat-value" data-chart-range>--</div></div>
        </div>
        <div class="traffic-chart-wrap">
          <div class="chart-legend">
            <span class="legend-item"><span class="legend-line"></span>累计流量 GB</span>
            <span class="legend-item"><span class="legend-bar"></span>本次新增 GB</span>
          </div>
          <svg class="traffic-chart" viewBox="0 0 760 320" data-chart-svg aria-label="流量曲线"></svg>
          <div class="chart-tooltip" data-chart-tooltip></div>
          <div class="chart-empty" data-chart-empty>暂无历史数据。手动检查或等待定时巡检后会开始记录。</div>
        </div>
        <div class="traffic-table-wrap">
          <table class="table traffic-table">
            <thead><tr><th>时间</th><th>累计流量</th><th>本次新增</th><th>状态</th></tr></thead>
            <tbody data-chart-table><tr><td colspan="4" class="text-secondary">暂无数据</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/js/tabler.min.js"></script>
  <script>
    function toggleSecret(button) {{
      const shown = button.dataset.shown === "1";
      if (shown) {{
        button.textContent = button.dataset.label || "显示密码";
        button.dataset.shown = "0";
      }} else {{
        button.dataset.label = button.textContent;
        button.textContent = button.dataset.secret;
        button.dataset.shown = "1";
      }}
    }}
    function initAssetBoard() {{
      const board = document.querySelector("[data-asset-board]");
      if (!board) return;
      const rows = Array.from(board.querySelectorAll("[data-server-row]"));
      const groups = Array.from(board.querySelectorAll("[data-server-group]"));
      const search = board.querySelector("[data-asset-search]");
      const filter = board.querySelector("[data-asset-filter]");
      const sort = board.querySelector("[data-asset-sort]");
      const list = board.querySelector("[data-server-list]");
      const count = board.querySelector("[data-visible-count]");
      const empty = board.querySelector("[data-empty-state]");

      function selectServer(id) {{
        rows.forEach((row) => {{
          const active = row.dataset.serverId === id;
          row.classList.toggle("active", active);
          row.setAttribute("aria-selected", active ? "true" : "false");
        }});
        board.querySelectorAll("[data-server-detail]").forEach((panel) => {{
          panel.classList.toggle("active", panel.dataset.serverId === id);
        }});
      }}

      function applyFilters() {{
        const q = (search?.value || "").trim().toLowerCase();
        const state = filter?.value || "all";
        const mode = sort?.value || "health";
        const compareRows = (a, b) => {{
          if (mode === "traffic") return Number(b.dataset.used || 0) - Number(a.dataset.used || 0);
          if (mode === "name") return (a.dataset.name || "").localeCompare(b.dataset.name || "", "zh-Hans-CN");
          return Number(a.dataset.priority || 9) - Number(b.dataset.priority || 9);
        }};
        const compareGroups = (a, b) => {{
          if (mode === "traffic") return Number(b.dataset.groupUsed || 0) - Number(a.dataset.groupUsed || 0);
          if (mode === "name") return (a.dataset.groupName || "").localeCompare(b.dataset.groupName || "", "zh-Hans-CN");
          return Number(a.dataset.groupPriority || 9) - Number(b.dataset.groupPriority || 9);
        }};
        const orderedGroups = groups.slice().sort(compareGroups);
        orderedGroups.forEach((group) => list.appendChild(group));
        groups.forEach((group) => {{
          const body = group.querySelector("[data-server-group-body]");
          if (!body) return;
          Array.from(body.querySelectorAll("[data-server-row]")).sort(compareRows).forEach((row) => body.appendChild(row));
        }});
        const ordered = groups.length ? orderedGroups.flatMap((group) => Array.from(group.querySelectorAll("[data-server-row]"))) : rows.slice().sort(compareRows);
        if (!groups.length) {{
          ordered.forEach((row) => list.appendChild(row));
        }}

        let visible = 0;
        let firstVisible = null;
        ordered.forEach((row) => {{
          const matchesText = !q || (row.dataset.search || "").includes(q);
          const matchesState = state === "all" || row.dataset.filterState === state;
          const show = matchesText && matchesState;
          row.hidden = !show;
          if (show) {{
            visible += 1;
            firstVisible ||= row;
          }}
        }});
        groups.forEach((group) => {{
          const groupRows = Array.from(group.querySelectorAll("[data-server-row]"));
          const groupVisible = groupRows.filter((row) => !row.hidden).length;
          group.hidden = groupVisible === 0;
          const groupCount = group.querySelector("[data-group-visible-count]");
          if (groupCount) groupCount.textContent = groupVisible;
        }});
        if (count) count.textContent = visible;
        if (empty) empty.hidden = visible !== 0;

        const active = rows.find((row) => row.classList.contains("active") && !row.hidden);
        if (!active && firstVisible) selectServer(firstVisible.dataset.serverId);
      }}

      rows.forEach((row) => {{
        row.addEventListener("click", () => selectServer(row.dataset.serverId));
        row.addEventListener("keydown", (event) => {{
          if (event.key === "Enter" || event.key === " ") {{
            event.preventDefault();
            selectServer(row.dataset.serverId);
          }}
        }});
      }});
      [search, filter, sort].forEach((input) => input && input.addEventListener("input", applyFilters));
      applyFilters();
    }}
    function initSaveForms() {{
      document.querySelectorAll("[data-save-form]").forEach((form) => {{
        form.addEventListener("submit", (event) => {{
          if (form.dataset.submitting === "1") {{
            event.preventDefault();
            return;
          }}
          if (!form.checkValidity()) return;
          form.dataset.submitting = "1";
          form.classList.add("is-submitting");
          const button = form.querySelector("[data-submit-button]");
          if (button) {{
            button.disabled = true;
            button.dataset.originalText = button.textContent;
            button.textContent = button.dataset.loadingText || "正在保存...";
          }}
        }});
      }});
    }}
    function initRunCheckForms() {{
      document.querySelectorAll("[data-run-check-form]").forEach((form) => {{
        form.addEventListener("submit", (event) => {{
          if (form.dataset.submitting === "1") {{
            event.preventDefault();
            return;
          }}
          form.dataset.submitting = "1";
          form.classList.add("is-submitting");
          const button = form.querySelector("[data-run-check-button]");
          if (button) {{
            button.disabled = true;
            button.textContent = button.dataset.loadingText || "正在检查...";
          }}
        }});
      }});
    }}
    const trafficChart = {{
      serverId: "",
      poolKey: "",
      serverName: "",
      days: 1,
      points: []
    }};
    function gbText(value) {{
      const number = Number(value || 0);
      return number.toFixed(2) + " GB";
    }}
    function axisGbText(value, span) {{
      const number = Number(value || 0);
      const digits = span < 0.1 ? 3 : 2;
      return number.toFixed(digits) + " GB";
    }}
    function timeText(value) {{
      if (!value) return "暂无";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString("zh-CN", {{ hour12: false }});
    }}
    function axisTimeText(value, days) {{
      if (!value) return "";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      const options = days <= 1
        ? {{ hour: "2-digit", minute: "2-digit", hour12: false }}
        : {{ month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }};
      return date.toLocaleString("zh-CN", options);
    }}
    function setModalOpen(open) {{
      const modal = document.querySelector("[data-traffic-modal]");
      if (!modal) return;
      modal.classList.toggle("is-open", open);
      modal.setAttribute("aria-hidden", open ? "false" : "true");
      document.body.style.overflow = open ? "hidden" : "";
    }}
    async function loadTrafficChart() {{
      const svg = document.querySelector("[data-chart-svg]");
      const empty = document.querySelector("[data-chart-empty]");
      const table = document.querySelector("[data-chart-table]");
      if (svg) svg.innerHTML = "";
      if (empty) {{
        empty.textContent = "正在加载流量历史...";
        empty.classList.add("show");
      }}
      if (table) table.innerHTML = '<tr><td colspan="4" class="text-secondary">正在加载...</td></tr>';
      const data = await requestJson(`/api/traffic?server=${{encodeURIComponent(trafficChart.serverId)}}&pool=${{encodeURIComponent(trafficChart.poolKey)}}&days=${{trafficChart.days}}`);
      trafficChart.points = data.points || [];
      renderTrafficChart(data);
    }}
    function requestJson(url) {{
      return new Promise((resolve, reject) => {{
        const xhr = new XMLHttpRequest();
        xhr.open("GET", url, true);
        xhr.setRequestHeader("Cache-Control", "no-store");
        xhr.onreadystatechange = () => {{
          if (xhr.readyState !== 4) return;
          if (xhr.status < 200 || xhr.status >= 300) {{
            reject(new Error("HTTP " + xhr.status));
            return;
          }}
          try {{
            resolve(JSON.parse(xhr.responseText));
          }} catch (error) {{
            reject(error);
          }}
        }};
        xhr.onerror = () => reject(new Error("Network error"));
        xhr.send();
      }});
    }}
    function renderTrafficChart(data) {{
      const points = data.points || [];
      const svg = document.querySelector("[data-chart-svg]");
      const empty = document.querySelector("[data-chart-empty]");
      const table = document.querySelector("[data-chart-table]");
      const total = document.querySelector("[data-chart-total]");
      const last = document.querySelector("[data-chart-last]");
      const count = document.querySelector("[data-chart-count]");
      const range = document.querySelector("[data-chart-range]");
      if (total) total.textContent = gbText(data.total_delta_gb);
      if (last) last.textContent = data.last_traffic_gb == null ? "--" : gbText(data.last_traffic_gb);
      if (count) count.textContent = String(data.point_count || 0);
      if (range) range.textContent = data.days === 30 ? "1 个月" : data.days + " 天";
      if (!svg) return;
      svg.innerHTML = "";
      if (!points.length) {{
        if (empty) {{
          empty.textContent = "这个时间范围内暂无历史记录。";
          empty.classList.add("show");
        }}
        if (table) table.innerHTML = '<tr><td colspan="4" class="text-secondary">暂无数据</td></tr>';
        return;
      }}
      if (empty) empty.classList.remove("show");

      const width = 760;
      const height = 320;
      const pad = {{ left: 72, right: 26, top: 42, bottom: 58 }};
      const values = points.map((point) => Number(point.traffic_gb || 0));
      const deltas = points.map((point) => Number(point.delta_gb || 0));
      let minValue = Math.min(...values);
      let maxValue = Math.max(...values);
      const maxDelta = Math.max(...deltas, 0.001);
      let span = maxValue - minValue;
      if (span < 0.01) {{
        const center = (maxValue + minValue) / 2;
        span = Math.max(0.01, center * 0.002);
        minValue = Math.max(0, center - span / 2);
        maxValue = center + span / 2;
      }} else {{
        const padding = span * 0.12;
        minValue = Math.max(0, minValue - padding);
        maxValue = maxValue + padding;
        span = maxValue - minValue;
      }}
      const plotW = width - pad.left - pad.right;
      const plotH = height - pad.top - pad.bottom;
      const xAt = (index) => pad.left + (points.length === 1 ? plotW : index * plotW / (points.length - 1));
      const yAt = (value) => pad.top + plotH - ((value - minValue) / span * plotH);
      const barY = pad.top + plotH;
      const barW = Math.max(1, plotW / Math.max(points.length, 1) * .72);
      const ns = "http://www.w3.org/2000/svg";
      const add = (name, attrs) => {{
        const node = document.createElementNS(ns, name);
        Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
        svg.appendChild(node);
        return node;
      }};

      for (let i = 0; i <= 4; i += 1) {{
        const y = pad.top + i * plotH / 4;
        add("line", {{ x1: pad.left, y1: y, x2: width - pad.right, y2: y, stroke: "#e5e7eb", "stroke-width": "1" }});
        const value = maxValue - i * span / 4;
        add("text", {{ x: pad.left - 10, y: y + 4, fill: "#64748b", "font-size": "11", "text-anchor": "end" }}).textContent = axisGbText(value, span);
      }}
      add("line", {{ x1: pad.left, y1: pad.top, x2: pad.left, y2: barY, stroke: "#cbd5e1", "stroke-width": "1" }});
      add("line", {{ x1: pad.left, y1: barY, x2: width - pad.right, y2: barY, stroke: "#cbd5e1", "stroke-width": "1" }});
      add("text", {{ x: pad.left, y: 18, fill: "#475569", "font-size": "12", "font-weight": "700" }}).textContent = "纵轴：累计流量 GB";
      add("text", {{ x: width - pad.right, y: height - 8, fill: "#475569", "font-size": "12", "font-weight": "700", "text-anchor": "end" }}).textContent = "横轴：时间点";

      const tickCount = Math.min(5, points.length);
      for (let i = 0; i < tickCount; i += 1) {{
        const index = tickCount === 1 ? 0 : Math.round(i * (points.length - 1) / (tickCount - 1));
        const x = xAt(index);
        add("line", {{ x1: x, y1: barY, x2: x, y2: barY + 5, stroke: "#94a3b8", "stroke-width": "1" }});
        add("text", {{ x, y: barY + 20, fill: "#64748b", "font-size": "11", "text-anchor": i === 0 ? "start" : (i === tickCount - 1 ? "end" : "middle") }}).textContent = axisTimeText(points[index].at, data.days);
      }}
      points.forEach((point, index) => {{
        const delta = Number(point.delta_gb || 0);
        if (delta <= 0) return;
        const h = Math.max(2, delta / maxDelta * Math.min(72, plotH * 0.32));
        add("rect", {{ x: xAt(index) - barW / 2, y: barY - h, width: barW, height: h, rx: "2", fill: "rgba(245, 159, 0, .38)" }});
      }});
      const line = values.map((value, index) => `${{xAt(index).toFixed(1)}},${{yAt(value).toFixed(1)}}`).join(" ");
      add("polyline", {{ points: line, fill: "none", stroke: "#1763d1", "stroke-width": "3", "stroke-linecap": "round", "stroke-linejoin": "round" }});

      const tooltip = document.querySelector("[data-chart-tooltip]");
      const markerStep = Math.max(1, Math.ceil(points.length / 180));
      points.forEach((point, index) => {{
        if (index % markerStep !== 0 && index !== points.length - 1) return;
        const cx = xAt(index);
        const cy = yAt(Number(point.traffic_gb || 0));
        const guide = add("line", {{ x1: cx, y1: pad.top, x2: cx, y2: barY, stroke: "rgba(23,99,209,.22)", "stroke-width": "1", "stroke-dasharray": "4 4", opacity: "0" }});
        const dot = add("circle", {{ cx, cy, r: "4", fill: "#fff", stroke: "#1763d1", "stroke-width": "2", opacity: "0" }});
        const circle = add("circle", {{ cx, cy, r: "10", fill: "transparent", stroke: "transparent" }});
        circle.addEventListener("pointermove", () => {{
          if (!tooltip) return;
          guide.setAttribute("opacity", "1");
          dot.setAttribute("opacity", "1");
          tooltip.innerHTML = `时间：${{timeText(point.at)}}<br>累计流量：${{gbText(point.traffic_gb)}}<br>本次新增：${{gbText(point.delta_gb)}}`;
          tooltip.style.display = "block";
          tooltip.style.left = (cx / width * 100) + "%";
          tooltip.style.top = (cy / height * 100) + "%";
        }});
        circle.addEventListener("pointerleave", () => {{
          guide.setAttribute("opacity", "0");
          dot.setAttribute("opacity", "0");
          if (tooltip) tooltip.style.display = "none";
        }});
      }});

      if (table) {{
        const rows = points.slice(-160).reverse().map((point) => `
          <tr>
            <td>${{timeText(point.at)}}</td>
            <td>${{gbText(point.traffic_gb)}}</td>
            <td>${{gbText(point.delta_gb)}}</td>
            <td>${{point.status || ""}}</td>
          </tr>
        `);
        table.innerHTML = rows.join("");
      }}
    }}
    function initTrafficChartModal() {{
      const modal = document.querySelector("[data-traffic-modal]");
      if (!modal) return;
      document.querySelectorAll("[data-chart-trigger]").forEach((button) => {{
        button.addEventListener("click", (event) => {{
          event.preventDefault();
          event.stopPropagation();
          trafficChart.serverId = button.dataset.serverId || "";
          trafficChart.poolKey = button.dataset.chartPool || "";
          trafficChart.serverName = button.dataset.serverName || trafficChart.serverId;
          trafficChart.days = 1;
          document.querySelector("[data-chart-server]").textContent = trafficChart.poolKey ? (trafficChart.serverName + " · 按流量池统计") : trafficChart.serverName;
          document.querySelectorAll("[data-days]").forEach((tab) => tab.classList.toggle("active", tab.dataset.days === "1"));
          setModalOpen(true);
          loadTrafficChart().catch(() => renderTrafficChart({{ points: [], point_count: 0, days: trafficChart.days, total_delta_gb: 0 }}));
        }});
      }});
      document.querySelector("[data-chart-close]")?.addEventListener("click", () => setModalOpen(false));
      modal.addEventListener("click", (event) => {{
        if (event.target === modal) setModalOpen(false);
      }});
      document.querySelectorAll("[data-days]").forEach((tab) => {{
        tab.addEventListener("click", () => {{
          trafficChart.days = Number(tab.dataset.days || 1);
          document.querySelectorAll("[data-days]").forEach((item) => item.classList.toggle("active", item === tab));
          loadTrafficChart().catch(() => renderTrafficChart({{ points: [], point_count: 0, days: trafficChart.days, total_delta_gb: 0 }}));
        }});
      }});
      document.addEventListener("keydown", (event) => {{
        if (event.key === "Escape") setModalOpen(false);
      }});
    }}
    document.addEventListener("DOMContentLoaded", initAssetBoard);
    document.addEventListener("DOMContentLoaded", initSaveForms);
    document.addEventListener("DOMContentLoaded", initRunCheckForms);
    document.addEventListener("DOMContentLoaded", initTrafficChartModal);
  </script>
</body>
</html>
"""
    return html_doc.encode("utf-8")


def render_check_action() -> str:
    return """
    <div class="btn-list">
      <form class="run-check-form" method="post" action="/balance/run" data-run-check-form>
        <button class="btn" type="submit" title="马上通过 BSS 账单 API 查询阿里云账户余额" data-run-check-button data-loading-text="正在查询...">查询账户余额</button>
      </form>
      <form class="run-check-form" method="post" action="/guard/run" data-run-check-form>
        <button class="btn btn-primary" type="submit" title="马上查询 CDT 流量和 ECS 状态，并按阈值执行一次保护判断" data-run-check-button data-loading-text="正在检查...">手动检查流量</button>
      </form>
    </div>
    """


def money_text(amount, currency: str | None) -> str:
    if amount in {None, ""}:
        return "未知"
    try:
        number = float(amount)
        return f"{number:.2f} {currency or ''}".strip()
    except (TypeError, ValueError):
        return f"{amount} {currency or ''}".strip()


def balance_amount_level(amount) -> str:
    try:
        number = float(amount)
    except (TypeError, ValueError):
        return "is-warning"
    if number <= 0:
        return "is-danger"
    if number < 10:
        return "is-warning"
    return ""


def render_server_account_balance(item: dict) -> str:
    account_key = str(item.get("account_fingerprint") or "").strip()
    balance = item.get("account_balance") or {}
    if not account_key and not balance:
        return ""

    account_label = f"阿里云账号 {account_key}" if account_key else "阿里云账号 未识别"
    source = balance.get("source")
    if source == "bss":
        amount = money_text(balance.get("available_amount"), balance.get("currency"))
        cash = money_text(balance.get("available_cash_amount"), balance.get("currency"))
        level = balance_amount_level(balance.get("available_amount"))
        pill_class = f"account-balance-pill {level}".strip()
        title = f"阿里云账户余额：{amount}；现金余额：{cash}；来源：{balance.get('source_label') or 'BSS 账单 API'}"
        return f"""
          <span class="account-balance-line" title="{esc(title)}">
            <span class="account-key text-truncate">{esc(account_label)}</span>
            <span class="{pill_class}">余额 {esc(amount)}</span>
          </span>
        """

    if source == "error":
        error = str(balance.get("error") or "请检查 AliyunBSSReadOnlyAccess 权限")
        return f"""
          <span class="account-balance-line" title="{esc(error)}">
            <span class="account-key text-truncate">{esc(account_label)}</span>
            <span class="account-balance-pill is-danger">余额查询失败</span>
          </span>
        """

    return f"""
      <span class="account-balance-line">
        <span class="account-key text-truncate">{esc(account_label)}</span>
        <span class="account-balance-pill is-warning">余额未查询</span>
      </span>
    """


def account_group_key(item: dict) -> str:
    return str(item.get("account_fingerprint") or item.get("traffic_pool_key") or item.get("region_id") or "unknown")


def account_group_title(group_key: str) -> str:
    if group_key == "unknown":
        return "未识别阿里云账号"
    return f"阿里云账号 {group_key}"


def group_balance_summary(items: list[dict]) -> tuple[str, str]:
    for item in items:
        balance = item.get("account_balance") or {}
        if balance.get("source") == "bss":
            amount = money_text(balance.get("available_amount"), balance.get("currency"))
            return amount, balance_amount_level(balance.get("available_amount"))
        if balance.get("source") == "error":
            return "余额查询失败", "is-danger"
    return "余额未查询", "is-warning"


def group_scope_summary(items: list[dict]) -> str:
    labels = []
    for item in items:
        label = str(item.get("traffic_scope_label") or traffic_scope_label(item.get("traffic_scope")))
        if label not in labels:
            labels.append(label)
    if not labels:
        return "统计池未知"
    if len(labels) == 1:
        return labels[0]
    return "多个统计池"


def render_server_group(group_key: str, items: list[dict], metadata: dict[str, dict], history: list[dict], active_id: str | None) -> str:
    priorities = [server_health(item)[2] for item in items]
    group_priority = min(priorities) if priorities else 9
    total_traffic = sum(as_float(item.get("traffic_gb"), 0) for item in items if item.get("traffic_gb") is not None)
    balance_text, balance_level = group_balance_summary(items)
    scope_text = group_scope_summary(items)
    regions = sorted({str(item.get("region_id") or "") for item in items if item.get("region_id")})
    region_text = "、".join(regions[:3]) + (" 等" if len(regions) > 3 else "")
    group_name = account_group_title(group_key)
    rows = "".join(
        render_server_row(item, metadata, history, active=str(item.get("id") or item.get("instance_id")) == active_id)
        for item in items
    )
    return f"""
      <section class="server-group" data-server-group data-group-priority="{group_priority}" data-group-used="{total_traffic:.4f}" data-group-name="{esc(group_name.lower())}">
        <div class="server-group-head">
          <div>
            <div class="server-group-title">{esc(group_name)}</div>
            <div class="server-group-sub">
              <span data-group-visible-count>{len(items)}</span> / {len(items)} 台 · {esc(scope_text)}{f' · {esc(region_text)}' if region_text else ''}
            </div>
          </div>
          <div class="server-group-metrics">
            <span class="server-group-pill">合计 {fmt_gb(total_traffic)}</span>
            <span class="server-group-pill {balance_level}">余额 {esc(balance_text)}</span>
          </div>
        </div>
        <div class="server-group-body" data-server-group-body>
          {rows}
        </div>
      </section>
    """


def render_summary_cards(summary: dict) -> str:
    warnings = int(summary.get("warnings", 0) or 0)
    errors = int(summary.get("errors", 0) or 0)
    stopped = int(summary.get("stopped", 0) or 0)
    pools = int(summary.get("pools", 0) or 0)
    warning_class = "is-warning" if warnings else "is-muted"
    error_class = "is-danger" if errors else "is-muted"
    stopped_class = "is-danger" if stopped else "is-muted"
    return f"""
    <div class="row row-deck row-cards mb-4">
      <div class="col-sm-6 col-xl"><div class="card stat-card"><div class="card-body"><div class="subheader">总机器</div><div class="h1 mb-0">{esc(summary.get('total', 0))}</div><div class="stat-line"><span style="width:100%"></span></div></div></div></div>
      <div class="col-sm-6 col-xl"><div class="card stat-card"><div class="card-body"><div class="subheader">启用保护</div><div class="h1 mb-0">{esc(summary.get('enabled', 0))}</div><div class="stat-line"><span style="width:70%"></span></div></div></div></div>
      <div class="col-sm-6 col-xl"><div class="card stat-card"><div class="card-body"><div class="subheader">流量池</div><div class="h1 mb-0">{esc(pools)}</div><div class="stat-line"><span style="width:{min(100, max(18, pools * 25))}%"></span></div></div></div></div>
      <div class="col-sm-6 col-xl"><div class="card stat-card {warning_class}"><div class="card-body"><div class="subheader">流量预警</div><div class="h1 mb-0 text-yellow">{esc(warnings)}</div><div class="stat-line"><span style="width:{100 if warnings else 18}%; background:#f59f00"></span></div></div></div></div>
      <div class="col-sm-6 col-xl"><div class="card stat-card {error_class}"><div class="card-body"><div class="subheader">检查错误</div><div class="h1 mb-0 text-red">{esc(errors)}</div><div class="stat-line"><span style="width:{100 if errors else 18}%; background:#d63939"></span></div></div></div></div>
      <div class="col-sm-6 col-xl"><div class="card stat-card {stopped_class}"><div class="card-body"><div class="subheader">已停止</div><div class="h1 mb-0">{esc(stopped)}</div><div class="stat-line"><span style="width:{100 if stopped else 18}%; background:#64748b"></span></div></div></div></div>
    </div>
    """


def progress_class(item: dict) -> str:
    if item.get("last_error") or item.get("action") in {"stop", "manual_stop", "manual_stopped", "keep_stopped"}:
        return "bg-red"
    if used_percent(item) >= 100:
        return "bg-red"
    if item.get("warning") or item.get("action") == "hold":
        return "bg-yellow"
    return "bg-green"


def used_percent(item: dict) -> float:
    value = item.get("used_pct")
    if value is None:
        return 0
    try:
        return max(0, min(float(value), 100))
    except (TypeError, ValueError):
        return 0


def server_health(item: dict) -> tuple[str, str, int]:
    status = item.get("instance_status")
    action = item.get("action")
    if item.get("last_error") or action == "stop" or item.get("manual_stop"):
        return "danger", "异常/停机", 0
    if status == "Stopped":
        return "danger", "已关机", 1
    if item.get("warning") or action == "hold":
        return "warning", "流量预警", 2
    if action == "disabled" or status == "Disabled":
        return "muted", "已禁用", 4
    if status == "Running":
        return "running", "正常运行", 5
    return "muted", "状态未知", 3


def server_identity(item: dict, metadata: dict[str, dict]) -> dict[str, str]:
    meta = metadata.get(str(item.get("id")), {})
    public_ips = item.get("public_ips") or []
    private_ips = item.get("private_ips") or []
    primary_ip = first_value(
        meta.get("server_ip"),
        meta.get("public_ip"),
        public_ips[0] if public_ips else None,
        default="未识别",
    )
    product_name = first_value(meta.get("product_name"), meta.get("product"), item.get("label"), default="未命名产品")
    asset_label = first_value(meta.get("label"), item.get("label"), default=item.get("instance_id"))
    provider = first_value(meta.get("provider"), default="阿里云")
    return {
        "id": str(item.get("id") or item.get("instance_id")),
        "meta": meta,
        "public_ips": public_ips,
        "private_ips": private_ips,
        "primary_ip": str(primary_ip),
        "product_name": str(product_name),
        "asset_label": str(asset_label),
        "provider": str(provider),
    }


def traffic_values(server_id: str, history: list[dict], current) -> list[float]:
    values: list[float] = []
    for event in history:
        if str(event.get("id")) != server_id:
            continue
        value = event.get("traffic_gb")
        if value is None:
            continue
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    if current is not None:
        try:
            values.append(float(current))
        except (TypeError, ValueError):
            pass
    return values[-18:]


def sparkline_svg(values: list[float]) -> str:
    if len(values) < 2:
        return '<div class="text-secondary small mt-2">暂无趋势</div>'
    width = 128
    height = 28
    low = min(values)
    high = max(values)
    span = high - low or 1
    points = []
    for index, value in enumerate(values):
        x = index * width / (len(values) - 1)
        y = height - ((value - low) / span * (height - 4)) - 2
        points.append((x, y))
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    area = f"0,{height} {line} {width},{height}"
    return f'<svg class="sparkline" viewBox="0 0 {width} {height}" aria-hidden="true"><polygon class="area" points="{area}"></polygon><path d="M {line}"></path></svg>'


def product_label(product: str) -> str:
    labels = {
        "eip": "弹性公网 IP",
        "publicip": "固定公网 IP",
        "cbwp": "共享带宽包",
        "nat": "NAT 网关",
        "slb": "负载均衡",
    }
    return labels.get(product, product or "未知产品")


def traffic_delta_badge(value) -> str:
    if value is None:
        return '<span class="traffic-delta flat">暂无上次对比</span>'
    try:
        number = float(value)
    except (TypeError, ValueError):
        return '<span class="traffic-delta flat">暂无上次对比</span>'
    if number > 0.005:
        return f'<span class="traffic-delta up">本次 +{number:.2f} GB</span>'
    if number < -0.005:
        return f'<span class="traffic-delta down">本次 {number:.2f} GB</span>'
    return '<span class="traffic-delta flat">本次无变化</span>'


def render_traffic_breakdown(item: dict) -> str:
    products = item.get("traffic_products") or []
    if not products:
        return '<div class="text-secondary small">暂无 CDT 产品明细。新版本首次检查后会显示。</div>'
    rows = []
    for product in products:
        code = str(product.get("product") or "unknown")
        rows.append(
            f"""
            <div class="breakdown-row">
              <div>
                <div class="fw-semibold">{esc(product_label(code))}</div>
                <div class="asset-sub"><span class="product-code">{esc(code)}</span></div>
              </div>
              <div class="fw-semibold">{fmt_gb(product.get('traffic_gb'))}</div>
            </div>
            """
        )
    return f'<div class="breakdown-list">{"".join(rows)}</div>'


def render_diagnostics(item: dict, identity: dict[str, Any], manual_note: str) -> str:
    plan = item.get("recovery_plan") or {}
    matched = item.get("traffic_matched_detail_count")
    total = item.get("traffic_detail_count")
    match_line = "未知"
    if matched is not None and total is not None:
        match_line = f"{matched} / {total} 条"
    return f"""
      <details class="detail-section detail-disclosure">
        <summary>更多诊断信息</summary>
        <div class="detail-grid mt-3">
          <div class="detail-item">
            <div class="info-label">当前判断</div>
            <div>{badge(item.get('action'))}</div>
            <div class="text-secondary small mt-2">{esc(item.get('reason'))}</div>
            {f'<div class="text-danger small mt-1">{esc(manual_note)}</div>' if manual_note else ''}
            {f'<div class="text-danger small mt-1">{esc(item.get("last_error"))}</div>' if item.get("last_error") else ''}
          </div>
          <div class="detail-item">
            <div class="info-label">统计范围</div>
            <div class="info-value">{esc(traffic_pool_text(item))}</div>
            <div class="text-secondary small">CDT 明细匹配 {esc(match_line)}</div>
          </div>
          <div class="detail-item">
            <div class="info-label">BSS 账期接口</div>
            <div class="info-value">{esc(plan.get('reset_source_label') or item.get('billing_cycle_source_label') or '未知')}</div>
            <div class="text-secondary small">账期 {esc(plan.get('billing_cycle') or item.get('billing_cycle') or '未知')}</div>
            <div class="text-secondary small">{esc(plan.get('billing_region_id') or item.get('billing_region_id') or '')} {esc(plan.get('billing_endpoint') or item.get('billing_endpoint') or '')}</div>
          </div>
          <div class="detail-item">
            <div class="info-label">API RequestId</div>
            <div class="text-secondary small text-break">CDT：{esc(item.get('traffic_request_id') or '暂无')}</div>
            <div class="text-secondary small text-break">BSS：{esc(plan.get('billing_request_id') or item.get('billing_request_id') or '暂无')}</div>
          </div>
          <div class="detail-item">
            <div class="info-label">服务器 IP</div>
            <div class="ip-main">{esc(identity['primary_ip'])}</div>
            {small_line("公网 ", ", ".join(identity["public_ips"]))}
            {small_line("内网 ", ", ".join(identity["private_ips"]))}
          </div>
          <div class="detail-item">
            <div class="info-label">实例与区域</div>
            <div class="text-secondary small text-break">{esc(item.get('instance_id'))}</div>
            <div class="text-secondary small">ECS {esc(item.get('region_id'))} · CDT {esc(item.get('traffic_region_id'))}</div>
            <div class="text-secondary small">最近检查 {esc(fmt_time(item.get('updated_at')))}</div>
          </div>
        </div>
      </details>
    """


def render_server_row(item: dict, metadata: dict[str, dict], history: list[dict], active: bool = False) -> str:
    identity = server_identity(item, metadata)
    state_class, state_label, state_sub = status_view(item.get("instance_status"))
    health_class, filter_label, priority = server_health(item)
    pct = used_percent(item)
    account_balance = item.get("account_balance") or {}
    search_text = " ".join(
        [
            identity["product_name"],
            identity["asset_label"],
            identity["provider"],
            identity["primary_ip"],
            str(item.get("instance_id") or ""),
            str(item.get("region_id") or ""),
            str(item.get("traffic_region_id") or ""),
            str(item.get("traffic_pool_id") or ""),
            str(item.get("traffic_scope_label") or traffic_scope_label(item.get("traffic_scope"))),
            str(item.get("instance_name") or ""),
            str(item.get("account_fingerprint") or ""),
            str(account_balance.get("available_amount") or ""),
            str(account_balance.get("currency") or ""),
        ]
    ).lower()
    row_classes = ["server-row", f"is-{health_class}"]
    if active:
        row_classes.append("active")
    return f"""
      <article class="{' '.join(row_classes)}" data-server-row data-server-id="{esc(identity['id'])}" role="button" tabindex="0"
        data-search="{esc(search_text)}" data-filter-state="{esc(health_class)}" data-priority="{priority}"
        data-used="{pct:.4f}" data-name="{esc(identity['product_name'].lower())}" aria-selected="{'true' if active else 'false'}">
        <span class="server-cell">
          <span class="server-state {state_class}">
            <span class="server-state-dot"></span>
            <span>
              <span class="server-state-main">{esc(state_label)}</span>
              <span class="server-state-sub">{esc(state_sub)}</span>
            </span>
          </span>
        </span>
        <span class="server-cell">
          <span class="server-name-stack">
            <span class="asset-name d-block text-truncate">{esc(identity['product_name'])}</span>
            <span class="asset-sub d-block text-truncate">{esc(identity['asset_label'])} · {esc(identity['provider'])}</span>
            {render_server_account_balance(item)}
          </span>
        </span>
        <span class="server-cell"><span class="ip-main text-truncate">{esc(identity['primary_ip'])}</span></span>
        <span class="server-cell"><span class="text-secondary small">{esc(item.get('region_id'))}</span></span>
        <span class="server-cell">
          <span class="traffic-compact">
            <span class="traffic-meta">
              <span class="traffic-amount">{fmt_gb(item.get('traffic_gb'))}</span>
              <span class="text-secondary small">{pct:.0f}%</span>
            </span>
            <span class="progress"><span class="progress-bar {progress_class(item)}" style="width:{pct:.2f}%"></span></span>
            <span class="asset-sub d-block mt-1">{traffic_pool_badge(item)}</span>
            <span class="asset-sub d-block mt-1">{esc(fmt_delta(item.get('traffic_delta_gb')))}</span>
            <span class="asset-sub d-block mt-1">{esc(recovery_status_badge(item))}</span>
            {sparkline_svg(traffic_values(identity['id'], history, item.get('traffic_gb')))}
            <button class="chart-trigger" type="button" data-chart-trigger data-server-id="{esc(identity['id'])}" data-chart-pool="{esc(item.get('traffic_pool_key') or '')}" data-server-name="{esc(identity['product_name'])}">查看曲线</button>
          </span>
        </span>
        <span class="server-cell">
          <span>
            {badge(item.get('action'))}
            <span class="asset-sub d-block mt-1">{esc(filter_label)}</span>
          </span>
        </span>
      </article>
    """


def render_server_detail(item: dict, metadata: dict[str, dict], active: bool = False) -> str:
    identity = server_identity(item, metadata)
    meta = identity["meta"]
    pct = used_percent(item)
    state_class, state_label, state_sub = status_view(item.get("instance_status"))
    panel_username = first_value(meta.get("panel_username"), meta.get("login_username"), meta.get("username"))
    panel_password = first_value(meta.get("panel_password"), meta.get("login_password"), meta.get("password"))
    ssh_password = first_value(meta.get("ssh_password"))
    ssh_text = ""
    if meta.get("ssh_user") or meta.get("ssh_port"):
        ssh_text = f"{meta.get('ssh_user', 'root')}@{identity['primary_ip']}:{meta.get('ssh_port', 22)}"
    note_text = first_value(meta.get("notes"), meta.get("remark"), meta.get("account_note"))
    manual_note = "手动关机保持中，自动启动已暂停。" if item.get("manual_stop") else ""
    return f"""
      <section class="server-detail {'active' if active else ''}" data-server-detail data-server-id="{esc(identity['id'])}">
        <div class="detail-section">
          <div class="d-flex align-items-start justify-content-between gap-3">
            <div class="text-truncate">
              <div class="asset-name text-truncate">{esc(identity['product_name'])}</div>
              <div class="asset-sub text-truncate">{esc(identity['asset_label'])} · {esc(item.get('instance_name') or '未识别 ECS 名')}</div>
            </div>
            <span class="server-state-detail {state_class}">
              <span class="server-state-dot"></span>
              <span>
                <span class="server-state-main">{esc(state_label)}</span>
                <span class="server-state-sub">{esc(state_sub)}</span>
              </span>
            </span>
          </div>
        </div>
        <div class="detail-section">
          <div class="traffic-row">
            <div>
              <div class="info-label">CDT 用量</div>
              <div class="traffic-value">{fmt_gb(item.get('traffic_gb'))}</div>
            </div>
            <div class="text-secondary small">停机 {fmt_gb(item.get('stop_threshold_gb'))}</div>
          </div>
          <div class="progress mt-3">
            <div class="progress-bar {progress_class(item)}" style="width:{pct:.2f}%"></div>
          </div>
          <div class="d-flex justify-content-between mt-2 text-secondary small">
            <span>剩余 {fmt_gb(item.get('remaining_gb'))}</span>
            <span>{pct:.0f}% 已用</span>
          </div>
          <div class="pool-chip mt-2">{esc(traffic_pool_badge(item))}</div>
          <div class="mt-2">{traffic_delta_badge(item.get('traffic_delta_gb'))}</div>
          <button class="chart-trigger" type="button" data-chart-trigger data-server-id="{esc(identity['id'])}" data-chart-pool="{esc(item.get('traffic_pool_key') or '')}" data-server-name="{esc(identity['product_name'])}">查看 1天/3天/7天/1个月曲线</button>
        </div>
        <div class="detail-section">
          {render_recovery_plan(item)}
        </div>
        <div class="detail-section">
          <div class="info-label">CDT 计费明细</div>
          {render_traffic_breakdown(item)}
        </div>
        <details class="detail-section detail-disclosure">
          <summary>操作与电源控制</summary>
          <div class="mt-3">
            {power_controls(identity['id'], item.get('instance_status'))}
          </div>
        </details>
        {render_diagnostics(item, identity, manual_note)}
        <details class="detail-section detail-disclosure">
          <summary>登录、账号与备注</summary>
          <div class="detail-grid mt-3">
            <div class="detail-item">
              <div class="info-label">登录网站</div>
              <div>{link_or_text(meta.get('panel_url') or meta.get('login_url') or meta.get('website'))}</div>
              {small_line("账号 ", panel_username)}
              {secret_button(panel_password, "显示面板密码")}
            </div>
            <div class="detail-item">
              <div class="info-label">SSH 备注</div>
              {small_line("SSH ", ssh_text)}
              {secret_button(ssh_password, "显示 SSH 密码") if ssh_password else '<div class="text-secondary small">SSH 密码未填写</div>'}
            </div>
            <div class="detail-item">
              <div class="info-label">备注</div>
              <div class="note-cell">{esc(note_text) if note_text else '<span class="text-secondary">未填写</span>'}</div>
            </div>
          </div>
        </details>
        <div class="detail-section detail-actions">
          <a class="btn btn-primary btn-sm" href="/servers/edit?id={esc(identity['id'])}">编辑这台服务器</a>
          <form class="delete-form" method="post" action="/servers/delete" onsubmit="return confirm('确认删除这台服务器？删除后会立即从面板移除，并执行一次检查。')">
            <input type="hidden" name="id" value="{esc(identity['id'])}">
            <button class="btn btn-sm btn-outline-danger" type="submit">删除服务器</button>
          </form>
        </div>
      </section>
    """


def render_assets_card(instances: list[dict], metadata: dict[str, dict], history: list[dict]) -> str:
    sorted_instances = sorted(instances, key=lambda item: (server_health(item)[2], -used_percent(item), str(item.get("label") or "")))
    groups: dict[str, list[dict]] = {}
    details = []
    active_id = None
    for index, item in enumerate(sorted_instances):
        identity = server_identity(item, metadata)
        if index == 0:
            active_id = identity["id"]
        groups.setdefault(account_group_key(item), []).append(item)
        details.append(render_server_detail(item, metadata, active=index == 0))
    group_html = "".join(
        render_server_group(group_key, group_items, metadata, history, active_id)
        for group_key, group_items in sorted(
            groups.items(),
            key=lambda pair: (
                min(server_health(item)[2] for item in pair[1]),
                -sum(as_float(item.get("traffic_gb"), 0) for item in pair[1] if item.get("traffic_gb") is not None),
                account_group_title(pair[0]),
            ),
        )
    )
    return f"""
    <div class="card" id="servers" data-asset-board>
      <div class="card-header">
        <div class="asset-toolbar w-100">
          <h3 class="card-title">服务器资产</h3>
          <div class="btn-list">
            <a href="/api/status" class="btn btn-sm">状态 JSON</a>
            <a href="/api/history" class="btn btn-sm">历史 JSON</a>
          </div>
        </div>
      </div>
      <div class="asset-workspace">
        <div class="asset-list-panel">
          <div class="asset-filter-bar">
            <input class="form-control" type="search" placeholder="搜索名称、IP、实例 ID、区域" data-asset-search>
            <select class="form-select" data-asset-filter>
              <option value="all">全部状态</option>
              <option value="danger">异常/停机</option>
              <option value="warning">流量预警</option>
              <option value="running">运行中</option>
              <option value="muted">未知/禁用</option>
            </select>
            <select class="form-select" data-asset-sort>
              <option value="health">异常优先</option>
              <option value="traffic">流量最高</option>
              <option value="name">名称排序</option>
            </select>
          </div>
          <div class="asset-count-line">当前显示 <span data-visible-count>{len(sorted_instances)}</span> / {len(sorted_instances)} 台</div>
          <div class="server-list-head">
            <div>状态</div><div>服务器</div><div>IP</div><div>区域</div><div>CDT 用量</div><div>动作</div>
          </div>
          <div class="server-list" data-server-list>
            {group_html}
          </div>
          <div class="empty-state" data-empty-state hidden>没有符合条件的服务器</div>
          {'' if group_html else '<div class="empty-state">暂无服务器，请到“新增/编辑”添加第一台。</div>'}
        </div>
        <aside class="server-detail-panel">
          {''.join(details) if details else '<div class="empty-state">选择一台服务器查看详情。</div>'}
        </aside>
      </div>
    </div>
    """


def render_dashboard(query: dict[str, list[str]] | None = None) -> bytes:
    query = query or {}
    status = read_json(STATUS_FILE, {"summary": {}, "instances": [], "generated_at": "暂无"})
    config = read_config()
    summary = status.get("summary", {})
    instances = status.get("instances", [])
    metadata = config_by_id(config)
    history = read_history(1000)
    flash = query.get("flash", [""])[0]
    body = render_summary_cards(summary) + render_assets_card(instances, metadata, history)
    return page_shell(
        "overview",
        "CDT 流量保护与服务器资产面板",
        f"状态更新时间：{status.get('generated_at')}",
        body,
        actions=render_check_action(),
        flash=flash,
    )


def render_server_form_page(query: dict[str, list[str]] | None = None) -> bytes:
    query = query or {}
    config = read_config()
    status = read_json(STATUS_FILE, {"instances": []})
    edit_id = query.get("id", [""])[0]
    editing = selected_instance(config, edit_id)
    pool_options = collect_traffic_pool_options(config, status)
    body = f"""
    <div class="form-layout">
      <div>{render_form(editing, pool_options)}</div>
      {render_form_guide()}
    </div>
    """
    return page_shell(
        "servers",
        "新增/编辑服务器",
        "填写阿里云凭证、实例、阈值和资产备注",
        body,
        actions='<a href="/" class="btn">返回总览</a>',
        auto_refresh=False,
    )


def render_logs_page(query: dict[str, list[str]] | None = None) -> bytes:
    query = query or {}
    config = read_config()
    status = read_json(STATUS_FILE, {"instances": [], "generated_at": "暂无"})
    history = read_history(1000)
    configured = config.get("instances", [])
    status_by_id = {str(item.get("id")): item for item in status.get("instances", [])}
    selected_id = query.get("server", [""])[0]
    if not selected_id and configured:
        selected_id = str(configured[0].get("id") or configured[0].get("instance_id"))
    view = query.get("view", ["important"])[0]
    if view not in {"important", "normal", "all"}:
        view = "important"

    def is_important_log(event: dict) -> bool:
        action = str(event.get("action") or "")
        if event.get("error"):
            return True
        if event.get("warning"):
            return True
        if action in {"stop", "start", "manual_stop", "manual_start", "manual_stopped", "keep_stopped", "hold", "error", "disabled"}:
            return True
        if str(event.get("status") or "") in {"Stopped", "Stopping"}:
            return True
        try:
            traffic_gb = float(event.get("traffic_gb"))
        except (TypeError, ValueError):
            traffic_gb = None
        if traffic_gb is not None and action != "keep_running" and action:
            return True
        return False

    def log_view_url(server_id: str, target_view: str) -> str:
        return f"/logs?server={esc(server_id)}&view={esc(target_view)}"

    server_links = []
    for server in configured:
        server_id = str(server.get("id") or server.get("instance_id"))
        stat = status_by_id.get(server_id, {})
        active = "active" if server_id == selected_id else ""
        server_history = [event for event in history if str(event.get("id")) == server_id]
        important_count = sum(1 for event in server_history if is_important_log(event))
        normal_count = len(server_history) - important_count
        name = first_value(server.get("product_name"), server.get("label"), stat.get("label"), default=server_id)
        server_links.append(
            f"""
            <a href="{log_view_url(server_id, view)}" class="list-group-item list-group-item-action {active}">
              <div class="d-flex align-items-center">
                <div class="flex-fill">
                  <div class="fw-semibold">{esc(name)}</div>
                  <div class="text-secondary small">{esc(server.get('instance_id'))}</div>
                  <div class="text-secondary small">正常记录 {esc(normal_count)} 条</div>
                </div>
                <span class="badge {'bg-red-lt' if important_count else 'bg-secondary-lt'}">{important_count}</span>
              </div>
            </a>
            """
        )

    all_selected_logs = [
        event for event in reversed(history)
        if not selected_id or str(event.get("id")) == selected_id
    ]
    important_logs = [event for event in all_selected_logs if is_important_log(event)]
    normal_logs = [event for event in all_selected_logs if not is_important_log(event)]
    if view == "important":
        selected_logs = important_logs[:200]
    elif view == "normal":
        selected_logs = normal_logs[:200]
    else:
        selected_logs = all_selected_logs[:200]
    current_name = selected_id
    for server in configured:
        server_id = str(server.get("id") or server.get("instance_id"))
        if server_id == selected_id:
            current_name = first_value(server.get("product_name"), server.get("label"), default=server_id)
            break
    filter_tabs = f"""
      <div class="log-filter-tabs">
        <a class="log-filter-tab {'active' if view == 'important' else ''}" href="{log_view_url(selected_id, 'important')}">重要事件 {len(important_logs)}</a>
        <a class="log-filter-tab {'active' if view == 'normal' else ''}" href="{log_view_url(selected_id, 'normal')}">正常记录 {len(normal_logs)}</a>
        <a class="log-filter-tab {'active' if view == 'all' else ''}" href="{log_view_url(selected_id, 'all')}">全部 {len(all_selected_logs)}</a>
      </div>
    """
    note_map = {
        "important": "默认只展示异常、开机、关机、停机保持、流量预警和回差保持。正常 keep_running 巡检会收进“正常记录”。",
        "normal": "这里是普通巡检记录，主要用于排查历史趋势；日常不需要一直盯着看。",
        "all": "全部记录包含正常巡检流水，数量会比较多。",
    }
    log_items = []
    for event in selected_logs:
        important = is_important_log(event)
        danger = bool(event.get("error")) or str(event.get("action") or "") in {"stop", "keep_stopped", "manual_stopped", "error"}
        warning = str(event.get("action") or "") == "hold"
        log_items.append(
            f"""
            <details class="list-group-item log-item">
              <summary>
                <div class="row align-items-center">
                  <div class="col-auto"><span class="status-dot {'bg-red' if danger else ('bg-yellow' if warning else ('bg-blue' if important else 'bg-green'))} d-block"></span></div>
                  <div class="col text-truncate">
                    <div class="fw-semibold">{esc(event.get('label'))} · {esc(event.get('action'))}</div>
                    <div class="text-secondary text-truncate">{esc(event.get('reason'))}</div>
                  </div>
                  <div class="col-auto text-secondary small">{esc(event.get('at'))}</div>
                </div>
              </summary>
              <div class="mt-3 log-meta">
                <div><span class="text-secondary">流量</span><div>{fmt_gb(event.get('traffic_gb'))}</div></div>
                <div><span class="text-secondary">ECS 状态</span><div>{esc(event.get('status'))}</div></div>
                <div><span class="text-secondary">动作</span><div>{esc(event.get('action'))}</div></div>
                <div><span class="text-secondary">时间</span><div>{esc(event.get('at'))}</div></div>
                <div class="grid-full"><span class="text-secondary">原因</span><div>{esc(event.get('reason'))}</div></div>
                {f'<div class="grid-full text-red"><span>错误</span><div>{esc(event.get("error"))}</div></div>' if danger else ''}
              </div>
            </details>
            """
        )

    body = f"""
    <div class="log-layout">
      <div class="card">
        <div class="card-header"><h3 class="card-title">服务器</h3></div>
        <div class="list-group list-group-flush">{''.join(server_links) if server_links else '<div class="list-group-item text-secondary">暂无服务器</div>'}</div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="asset-toolbar w-100">
            <div>
              <h3 class="card-title">日志详情</h3>
              <div class="text-secondary small">{esc(current_name)}</div>
            </div>
            {filter_tabs}
            <a class="btn btn-sm" href="/api/history">历史 JSON</a>
          </div>
        </div>
        <div class="log-note">{esc(note_map.get(view, note_map['important']))}</div>
        <div class="list-group list-group-flush">{''.join(log_items) if log_items else '<div class="list-group-item text-secondary">暂无符合条件的日志</div>'}</div>
      </div>
    </div>
    """
    return page_shell(
        "logs",
        "服务器日志",
        "默认聚焦异常、启停、预警和需要处理的事件",
        body,
        actions=render_check_action(),
    )


def yes_no(value: bool) -> str:
    return "已启用" if value else "未启用"


def mask_middle(value: str, keep: int = 4) -> str:
    value = str(value or "")
    if len(value) <= keep * 2:
        return value
    return f"{value[:keep]}...{value[-keep:]}"


def render_saved_notification_channels(config: dict, state: dict) -> str:
    cards = []
    telegram = config.get("telegram", {})
    telegram_status = notifications.telegram_status(config)
    for index, chat_id in enumerate(telegram_status.get("chat_ids") or [], start=1):
        subtitle = "Telegram 私聊/群组/频道"
        cards.append(
            f"""
            <div class="saved-channel-card">
              <div class="saved-channel-head">
                <div class="saved-channel-icon">TG</div>
                <div>
                  <div class="saved-channel-title">Telegram #{index}</div>
                  <div class="saved-channel-subtitle">{esc(subtitle)}</div>
                </div>
              </div>
              <div class="saved-channel-meta">
                <div>Chat ID：{esc(mask_middle(chat_id))}</div>
                <div>Bot Token：{esc(telegram_status.get("token_masked") or "未保存")}</div>
                <div>主动查询：{esc("可用" if telegram_status.get("command_ready") and not str(chat_id).startswith("@") else "未就绪")}</div>
              </div>
              <div class="saved-channel-actions">
                <span class="saved-channel-badge {'is-on' if config.get('enabled') and telegram.get('enabled') else ''}">{esc('发送中' if config.get('enabled') and telegram.get('enabled') else '未启用')}</span>
                <button class="btn btn-sm" type="submit" name="chat_id" value="{esc(chat_id)}" form="telegram-remove-chat-form">移除</button>
              </div>
            </div>
            """
        )

    webhook = config.get("webhook", {})
    if webhook.get("url"):
        cards.append(
            f"""
            <div class="saved-channel-card">
              <div class="saved-channel-head">
                <div class="saved-channel-icon">WH</div>
                <div>
                  <div class="saved-channel-title">Webhook</div>
                  <div class="saved-channel-subtitle">{esc(mask_middle(webhook.get("url", ""), 14))}</div>
                </div>
              </div>
              <div class="saved-channel-meta">
                <div>用途：Bark、Server酱、飞书/企业微信中转</div>
                <div>格式：POST JSON</div>
              </div>
              <span class="saved-channel-badge {'is-on' if config.get('enabled') and webhook.get('enabled') else ''}">{esc('发送中' if config.get('enabled') and webhook.get('enabled') else '未启用')}</span>
            </div>
            """
        )

    smtp = config.get("smtp", {})
    if smtp.get("host") or smtp.get("recipients"):
        cards.append(
            f"""
            <div class="saved-channel-card">
              <div class="saved-channel-head">
                <div class="saved-channel-icon">MAIL</div>
                <div>
                  <div class="saved-channel-title">SMTP 邮件</div>
                  <div class="saved-channel-subtitle">{esc(smtp.get("host") or "未填写 SMTP 主机")}</div>
                </div>
              </div>
              <div class="saved-channel-meta">
                <div>收件人：{esc(smtp.get("recipients") or "未填写")}</div>
                <div>端口：{esc(smtp.get("port") or 587)}</div>
              </div>
              <span class="saved-channel-badge {'is-on' if config.get('enabled') and smtp.get('enabled') else ''}">{esc('发送中' if config.get('enabled') and smtp.get('enabled') else '未启用')}</span>
            </div>
            """
        )

    if not cards:
        cards.append(
            """
            <div class="saved-channel-card">
              <div class="saved-channel-head">
                <div class="saved-channel-icon">+</div>
                <div>
                  <div class="saved-channel-title">暂无已保存渠道</div>
                  <div class="saved-channel-subtitle">在下面添加 Telegram、Webhook 或 SMTP 邮件后，会出现在这里。</div>
                </div>
              </div>
            </div>
            """
        )

    last_test = state.get("last_test_result") or {}
    last_test_text = ""
    if last_test:
        last_test_text = f'<div class="text-secondary small mt-2">上次测试：{esc("成功" if last_test.get("ok") else "失败，请查看配置")}</div>'
    return f"""
      <section class="form-section">
        <h3 class="form-section-title">已保存推送渠道</h3>
        <div class="saved-channel-grid">{"".join(cards)}</div>
        {last_test_text}
      </section>
    """


def render_telegram_status(config: dict, state: dict) -> str:
    status = notifications.telegram_status(config)
    last_error = state.get("telegram_last_error", "")
    command_error = state.get("telegram_command_error", "")
    last_command = state.get("telegram_last_command") or {}
    chat_ids = [str(item) for item in status.get("chat_ids") or []]
    chat_warning = ""
    if any(chat_id.startswith("@") for chat_id in chat_ids):
        chat_warning = "有 Chat ID 看起来像用户名。私聊通知通常需要纯数字 Chat ID，请给机器人发消息后点击“获取 Chat ID”。"
    command_text = "暂无命令"
    if last_command:
        command_text = f"{last_command.get('command') or '未知命令'}，{'已回复' if last_command.get('ok') else '未回复'}"
    command_cards = "".join(
        f"""
        <div class="telegram-command">
          <code>{esc(command)}</code>
          <span>{esc(description)}</span>
        </div>
        """
        for command, description in [
            ("/status", "查看面板总览、机器数量、预警和错误。"),
            ("/traffic", "查看每台机器当前 CDT 用量、本次新增和重置时间。"),
            ("/pools", "查看共享 CDT 流量池用量和成员机器。"),
            ("/server 关键词", "按产品名、实例 ID 或公网 IP 查询单台服务器。"),
            ("/report", "立即生成一次完整流量报告。"),
            ("/help", "查看 Telegram 命令帮助。"),
        ]
    )
    return f"""
      {f'<div class="alert alert-danger mb-3">{esc(last_error)}</div>' if last_error else ''}
      {f'<div class="alert alert-danger mb-3">{esc(command_error)}</div>' if command_error else ''}
      {f'<div class="alert alert-warning mb-3">{esc(chat_warning)}</div>' if chat_warning else ''}
      <div class="text-secondary small mb-3">最近 Telegram 命令：{esc(command_text)}</div>
      <div class="setup-box">
        <strong>主动查询：</strong>保存 Telegram 配置后，在 Telegram 里直接发送下面任意命令即可获取面板数据。主动查询只做状态查看，不提供远程开关机。
        <div class="telegram-command-grid">{command_cards}</div>
      </div>
    """


def render_chat_candidates(state: dict) -> str:
    candidates = state.get("telegram_chat_candidates") or []
    if not candidates:
        return '<div class="text-secondary small mt-2">暂无候选 Chat ID。保存 Bot Token 后，先给机器人发一条消息，再点击“获取 Chat ID”。</div>'
    rows = []
    for item in candidates:
        chat_id = str(item.get("chat_id") or "")
        title = item.get("title") or chat_id
        username = item.get("username") or ""
        chat_type = item.get("type") or "unknown"
        rows.append(
            f"""
            <div class="chat-candidate">
              <div>
                <div class="fw-semibold">{esc(title)}</div>
                <div class="text-secondary small">类型：{esc(chat_type)} {f'@{esc(username)}' if username else ''}</div>
                <div class="chat-id-code">{esc(chat_id)}</div>
              </div>
              <button class="btn btn-sm btn-primary" type="submit" name="chat_id" value="{esc(chat_id)}" form="telegram-use-chat-form">追加这个 Chat ID</button>
            </div>
            """
        )
    return f'<div class="chat-candidates">{"".join(rows)}</div>'


def render_notifications_page(query: dict[str, list[str]] | None = None) -> bytes:
    query = query or {}
    config = notifications.load_config()
    state = notifications.load_state()
    rules = config.get("rules", {})
    telegram = config.get("telegram", {})
    webhook = config.get("webhook", {})
    smtp = config.get("smtp", {})
    flash = query.get("flash", [""])[0]
    body = f"""
    <form class="card save-form" method="post" action="/notifications/save" data-save-form>
      <div class="card-header">
        <div class="asset-toolbar w-100">
          <h3 class="card-title">通知设置</h3>
          <button class="btn btn-primary btn-sm" type="submit" data-submit-button data-loading-text="正在保存...">保存通知设置</button>
        </div>
      </div>
      <div class="card-body notification-layout">
        {render_saved_notification_channels(config, state)}

        <section class="form-section">
          <h3 class="form-section-title">通知规则</h3>
          {checkbox_field("enabled", "启用通知系统", bool(config.get("enabled")), "关闭后不会发送 Telegram、Webhook 或邮件。")}
          <div class="credential-grid">
            {checkbox_field("notify_actions", "启停动作通知", bool(rules.get("notify_actions", True)), "自动停机、自动启动时发送。")}
            {checkbox_field("notify_warnings", "流量预警通知", bool(rules.get("notify_warnings", True)), "首次进入预警状态时发送，避免每分钟刷屏。")}
          </div>
          <div class="credential-grid">
            {checkbox_field("notify_errors", "检查错误通知", bool(rules.get("notify_errors", True)), "阿里云 API 失败、实例查询失败等错误变化时发送。")}
            {checkbox_field("daily_report", "每日报告", bool(rules.get("daily_report", False)), "每天按指定时间发送一次服务器和流量池汇总。")}
          </div>
          <div class="credential-grid">
            {input_field("daily_report_time", "每日报告时间", rules.get("daily_report_time", "09:00"), placeholder="09:00", hint="按下面的时区判断，格式 HH:MM。")}
            {input_field("timezone", "报告时区", rules.get("timezone", "Asia/Shanghai"), placeholder="Asia/Shanghai")}
          </div>
        </section>

        <section class="form-section">
          <h3 class="form-section-title">添加 Telegram</h3>
          {render_telegram_status(config, state)}
          <div class="setup-box">
            <strong>获取 Chat ID：</strong>先填写 Bot Token 并保存；然后在 Telegram 给机器人发送任意一条消息；最后点击下面的“获取 Chat ID”。如果机器人在群组里，请先把机器人拉进群并在群里发一条消息。点击候选 Chat ID 会追加到已保存渠道，不会覆盖已有收件人。
          </div>
          {checkbox_field("telegram_enabled", "启用 Telegram Bot 通知", bool(telegram.get("enabled")), "从 BotFather 创建机器人，填 Bot Token；Chat ID 可以是个人、群组或频道。")}
          <div class="credential-grid">
            {input_field("telegram_bot_token", "Bot Token", "", "password", placeholder="123456:ABC-DEF...", hint="留空则保留原 Token；重新粘贴新的 Token 会覆盖原 Token。")}
            {input_field("telegram_chat_id", "新增 Chat ID", "", placeholder="例如：123456789 或 -100xxxxxxxxxx", hint="已保存的 Chat ID 会显示在顶部；这里留空会保留原有收件人，填写后会追加一个新收件人。")}
          </div>
          {checkbox_field("telegram_disable_preview", "禁用链接预览", bool(telegram.get("disable_web_page_preview", True)))}
          <div class="btn-list mt-2">
            <button class="btn" type="submit" data-submit-button data-loading-text="正在保存...">保存 Telegram 设置</button>
          </div>
          <div class="mt-3">
            <button class="btn btn-outline-primary" type="submit" form="telegram-discover-form">获取 Chat ID</button>
            {render_chat_candidates(state)}
          </div>
        </section>

        <section class="form-section">
          <h3 class="form-section-title">通用 Webhook</h3>
          {checkbox_field("webhook_enabled", "启用 Webhook", bool(webhook.get("enabled")), "会 POST JSON 到你填写的 URL，适合接 Bark、Server酱、企业微信/飞书中转。")}
          {input_field("webhook_url", "Webhook URL", webhook.get("url", ""), placeholder="https://example.com/notify")}
        </section>

        <section class="form-section">
          <h3 class="form-section-title">SMTP 邮件</h3>
          {checkbox_field("smtp_enabled", "启用邮件通知", bool(smtp.get("enabled")), "适合发到 iCloud、QQ、Gmail 或自建邮箱。")}
          <div class="credential-grid">
            {input_field("smtp_host", "SMTP 主机", smtp.get("host", ""), placeholder="smtp.example.com")}
            {input_field("smtp_port", "SMTP 端口", smtp.get("port", 587), "number")}
          </div>
          <div class="credential-grid">
            {input_field("smtp_username", "SMTP 用户名", smtp.get("username", ""))}
            {input_field("smtp_password", "SMTP 密码/授权码", "", "password", hint="留空则保留原密码。")}
          </div>
          <div class="credential-grid">
            {input_field("smtp_sender", "发件人", smtp.get("sender", ""), placeholder="alert@example.com")}
            {input_field("smtp_recipients", "收件人", smtp.get("recipients", ""), placeholder="a@example.com,b@example.com")}
          </div>
          {checkbox_field("smtp_use_tls", "使用 STARTTLS", bool(smtp.get("use_tls", True)), "大多数 587 端口邮箱使用 STARTTLS；465 端口通常关闭这个开关。")}
        </section>
      </div>
      <div class="card-footer d-flex align-items-center gap-2">
        <div class="submit-feedback"><span class="spinner-dot"></span><span>正在保存通知配置...</span></div>
        <button class="btn btn-primary btn-submit ms-auto" type="submit" data-submit-button data-loading-text="正在保存...">保存通知设置</button>
      </div>
    </form>
    <form id="telegram-discover-form" method="post" action="/notifications/telegram/discover"></form>
    <form id="telegram-use-chat-form" method="post" action="/notifications/telegram/use-chat"></form>
    <form id="telegram-remove-chat-form" method="post" action="/notifications/telegram/remove-chat"></form>
    <div class="card mt-3">
      <div class="card-header"><h3 class="card-title">测试通知</h3></div>
      <div class="card-body">
        <p class="text-secondary mb-3">保存设置后，可以发送一条测试消息确认 Telegram、Webhook 或邮件是否能收到；测试消息会附带 Telegram 主动查询命令，方便新用户直接照着使用。</p>
        <form method="post" action="/notifications/test">
          <button class="btn" type="submit">发送测试通知</button>
        </form>
      </div>
    </div>
    """
    return page_shell(
        "notifications",
        "通知设置",
        "Telegram、Webhook、邮件和每日流量报告",
        body,
        actions='<a href="/" class="btn">返回总览</a>',
        flash=flash,
        auto_refresh=False,
    )


def checked(fields: dict[str, list[str]], name: str) -> bool:
    return form_value(fields, name) == "1"


def default_domain_proxy_config() -> dict:
    env = load_env(WEB_ENV_FILE)
    return {
        "domain": "",
        "origin_ip": "",
        "origin_port": env.get("CDT_GUARD_PORT", "8787"),
        "proxy_type": "caddy",
        "cloudflare_proxy": True,
    }


def read_domain_proxy_config() -> dict:
    config = default_domain_proxy_config()
    saved = read_json(DOMAIN_PROXY_FILE, {})
    if isinstance(saved, dict):
        config.update({key: value for key, value in saved.items() if value is not None})
    return config


def save_domain_proxy(fields: dict[str, list[str]]) -> None:
    config = {
        "domain": form_value(fields, "domain").strip().lower(),
        "origin_ip": form_value(fields, "origin_ip").strip(),
        "origin_port": form_value(fields, "origin_port", "8787").strip() or "8787",
        "proxy_type": form_value(fields, "proxy_type", "caddy") or "caddy",
        "cloudflare_proxy": checked(fields, "cloudflare_proxy"),
    }
    write_json(DOMAIN_PROXY_FILE, config)


def render_code_block(text: str) -> str:
    return f'<pre class="config-block"><code>{esc(text.strip())}</code></pre>'


def render_domain_page(query: dict[str, list[str]] | None = None) -> bytes:
    query = query or {}
    config = read_domain_proxy_config()
    domain = str(config.get("domain") or "cdt.example.com")
    origin_ip = str(config.get("origin_ip") or "你的服务器公网 IP")
    origin_port = str(config.get("origin_port") or "8787")
    proxy_type = str(config.get("proxy_type") or "caddy")
    dns_name = domain.split(".", 1)[0] if "." in domain else domain
    caddy_config = f"""
{domain} {{
  reverse_proxy 127.0.0.1:{origin_port}
}}
"""
    nginx_config = f"""
server {{
  listen 80;
  server_name {domain};

  location / {{
    proxy_pass http://127.0.0.1:{origin_port};
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }}
}}
"""
    env_config = "WEB_COOKIE_SECURE=true"
    body = f"""
    <div class="proxy-grid">
      <form class="card save-form" method="post" action="/domain/save" data-save-form>
        <div class="card-header">
          <h3 class="card-title">绑定域名 / 反代向导</h3>
        </div>
        <div class="card-body">
          <div class="setup-box">
            保存域名信息后，下面会自动生成 Cloudflare DNS、Caddy、Nginx 和 web.env 配置。这里不会自动修改 Cloudflare，避免误动你的 DNS。
          </div>
          <div class="credential-grid">
            {input_field("domain", "面板域名", config.get("domain", ""), placeholder="例如：cdt.example.com", hint="在 Cloudflare DNS 里添加这个子域名。")}
            {input_field("origin_ip", "源站公网 IP", config.get("origin_ip", ""), placeholder="例如：154.83.98.194", hint="A 记录指向这台安装面板的服务器 IP。")}
          </div>
          <div class="credential-grid">
            {input_field("origin_port", "面板源站端口", config.get("origin_port", "8787"), "number", hint="默认 8787；如果安装时改过 WEB_PORT，就填实际端口。")}
            {select_field("proxy_type", "推荐反代方式", proxy_type, [("caddy", "Caddy（推荐，自动 HTTPS）"), ("nginx", "Nginx（手动配置证书）")])}
          </div>
          {checkbox_field("cloudflare_proxy", "Cloudflare 开启代理（橙色云）", bool(config.get("cloudflare_proxy", True)), "开启后浏览器访问域名会走 Cloudflare；SSL/TLS 建议使用 Full 或 Full strict。")}
        </div>
        <div class="card-footer d-flex align-items-center gap-2">
          <div class="submit-feedback"><span class="spinner-dot"></span><span>正在保存域名配置...</span></div>
          <button class="btn btn-primary btn-submit ms-auto" type="submit" data-submit-button data-loading-text="正在保存...">保存域名配置</button>
        </div>
      </form>

      <aside class="card guide-panel">
        <div class="card-header"><h3 class="card-title">操作步骤</h3></div>
        <div class="card-body">
          <div class="guide-step">
            <strong>1. Cloudflare 添加 DNS</strong>
            <span>类型选 A，名称填子域名前缀，例如 cdt；IPv4 地址填源站公网 IP；代理状态建议开启。</span>
          </div>
          <div class="guide-step">
            <strong>2. 服务器安装反代</strong>
            <span>推荐 Caddy。它会自动申请 HTTPS 证书，并把域名流量转发到 127.0.0.1:{esc(origin_port)}。</span>
          </div>
          <div class="guide-step">
            <strong>3. 修改 Cookie 安全项</strong>
            <span>确认域名 HTTPS 可访问后，在 web.env 里开启 WEB_COOKIE_SECURE=true 并重启面板。</span>
          </div>
          <div class="guide-step">
            <strong>4. 收紧源站端口</strong>
            <span>域名确认可用后，可以用防火墙限制 8787 只允许本机/反代访问。</span>
          </div>
        </div>
      </aside>
    </div>

    <div class="card mt-3">
      <div class="card-header"><h3 class="card-title">生成配置</h3></div>
      <div class="card-body">
        <div class="proxy-step-grid">
          <div class="proxy-step-card">
            <strong>Cloudflare DNS</strong>
            <span>类型：A<br>名称：{esc(dns_name)}<br>IPv4：{esc(origin_ip)}<br>代理：{"开启（橙色云）" if config.get("cloudflare_proxy", True) else "关闭（灰色云）"}</span>
          </div>
          <div class="proxy-step-card">
            <strong>Cloudflare SSL/TLS</strong>
            <span>建议选择 Full 或 Full strict。不要使用 Flexible，否则容易出现跳转或 Cookie 问题。</span>
          </div>
          <div class="proxy-step-card">
            <strong>面板访问地址</strong>
            <span>配置完成后访问：https://{esc(domain)}</span>
          </div>
        </div>

        <h3 class="form-section-title mt-4">Caddyfile（推荐）</h3>
        {render_code_block(caddy_config)}

        <h3 class="form-section-title mt-4">Nginx 反代示例</h3>
        {render_code_block(nginx_config)}

        <h3 class="form-section-title mt-4">web.env 建议</h3>
        {render_code_block(env_config)}

        <div class="status-note mt-3">
          这一页先做配置向导，不自动改 DNS。以后如果你愿意提供 Cloudflare API Token，可以再加“一键创建 DNS 记录”。
        </div>
      </div>
    </div>
    """
    return page_shell(
        "domain",
        "域名反代",
        "用 Cloudflare + Caddy/Nginx 把 IP:端口 变成 HTTPS 域名",
        body,
        actions='<a href="/" class="btn">返回总览</a>',
        flash=query.get("flash", [""])[0],
        auto_refresh=False,
    )


def save_notifications(fields: dict[str, list[str]]) -> None:
    existing = notifications.load_config()
    telegram_token = form_value(fields, "telegram_bot_token")
    telegram_chat_id = form_value(fields, "telegram_chat_id")
    existing_telegram = existing.get("telegram", {})
    smtp_password = form_value(fields, "smtp_password")
    config = {
        "enabled": checked(fields, "enabled"),
        "rules": {
            "notify_actions": checked(fields, "notify_actions"),
            "notify_warnings": checked(fields, "notify_warnings"),
            "notify_errors": checked(fields, "notify_errors"),
            "daily_report": checked(fields, "daily_report"),
            "daily_report_time": form_value(fields, "daily_report_time", "09:00"),
            "timezone": form_value(fields, "timezone", "Asia/Shanghai"),
        },
        "telegram": {
            "enabled": checked(fields, "telegram_enabled"),
            "bot_token": telegram_token or existing_telegram.get("bot_token", ""),
            "chat_id": notifications.add_chat_id(existing_telegram.get("chat_id", ""), telegram_chat_id) if telegram_chat_id else existing_telegram.get("chat_id", ""),
            "disable_web_page_preview": checked(fields, "telegram_disable_preview"),
        },
        "webhook": {
            "enabled": checked(fields, "webhook_enabled"),
            "url": form_value(fields, "webhook_url"),
        },
        "smtp": {
            "enabled": checked(fields, "smtp_enabled"),
            "host": form_value(fields, "smtp_host"),
            "port": int(as_float(form_value(fields, "smtp_port"), 587)),
            "username": form_value(fields, "smtp_username"),
            "password": smtp_password or existing.get("smtp", {}).get("password", ""),
            "sender": form_value(fields, "smtp_sender"),
            "recipients": form_value(fields, "smtp_recipients"),
            "use_tls": checked(fields, "smtp_use_tls"),
        },
    }
    notifications.save_config(config)
    state = notifications.load_state()
    state.pop("telegram_last_error", None)
    notifications.save_state(state)


def discover_telegram_chats() -> bool:
    state = notifications.load_state()
    result = notifications.discover_telegram_chats()
    if result.get("ok"):
        candidates = result.get("candidates") or []
        state["telegram_chat_candidates"] = candidates
        state.pop("telegram_last_error", None)
        config = notifications.load_config()
        if len(candidates) == 1 and not config.get("telegram", {}).get("chat_id"):
            config.setdefault("telegram", {})["chat_id"] = candidates[0].get("chat_id", "")
            notifications.save_config(config)
        notifications.save_state(state)
        return True
    state["telegram_last_error"] = str(result.get("error") or "Telegram getUpdates 失败")
    notifications.save_state(state)
    return False


def use_telegram_chat(chat_id: str) -> None:
    config = notifications.load_config()
    telegram = config.setdefault("telegram", {})
    telegram["chat_id"] = notifications.add_chat_id(telegram.get("chat_id", ""), chat_id)
    notifications.save_config(config)


def remove_telegram_chat(chat_id: str) -> None:
    config = notifications.load_config()
    telegram = config.setdefault("telegram", {})
    remaining = [item for item in notifications.split_chat_ids(telegram.get("chat_id", "")) if item != chat_id]
    telegram["chat_id"] = notifications.join_chat_ids(remaining)
    notifications.save_config(config)


def input_field(name: str, label: str, value="", field_type: str = "text", placeholder: str = "", hint: str = "", required: bool = False) -> str:
    required_attr = " required" if required else ""
    hint_html = f'<div class="form-hint">{esc(hint)}</div>' if hint else ""
    return (
        '<div class="mb-3">'
        f'<label class="form-label">{esc(label)}</label>'
        f'<input class="form-control" type="{esc(field_type)}" name="{esc(name)}" value="{esc(value)}" placeholder="{esc(placeholder)}"{required_attr}>'
        f'{hint_html}'
        '</div>'
    )


def region_field(name: str, label: str, value="", placeholder: str = "", hint: str = "", required: bool = False) -> str:
    required_attr = " required" if required else ""
    list_id = f"{name}-options"
    hint_html = f'<div class="form-hint">{esc(hint)}</div>' if hint else ""
    options = "".join(
        f'<option value="{esc(region_id)}" label="{esc(region_name)}">{esc(region_name)} · {esc(region_id)}</option>'
        for region_id, region_name in ALIYUN_REGION_OPTIONS
    )
    return f"""
      <div class="mb-3">
        <div class="form-label-row">
          <label class="form-label mb-0">{esc(label)}</label>
          <a class="form-doc-link" href="{esc(ALIYUN_REGION_DOC_URL)}" target="_blank" rel="noopener">查看官方地域 ID</a>
        </div>
        <input class="form-control mt-2" type="text" name="{esc(name)}" value="{esc(value)}" placeholder="{esc(placeholder)}" list="{esc(list_id)}"{required_attr}>
        <datalist id="{esc(list_id)}">{options}</datalist>
        {hint_html}
      </div>
    """


def select_field(name: str, label: str, value: str, options: list[tuple[str, str]], hint: str = "") -> str:
    hint_html = f'<div class="form-hint">{esc(hint)}</div>' if hint else ""
    option_html = "".join(
        f'<option value="{esc(option_value)}" {"selected" if option_value == value else ""}>{esc(option_label)}</option>'
        for option_value, option_label in options
    )
    return (
        '<div class="mb-3">'
        f'<label class="form-label">{esc(label)}</label>'
        f'<select class="form-select" name="{esc(name)}">{option_html}</select>'
        f'{hint_html}'
        '</div>'
    )


def collect_traffic_pool_options(config: dict, status: dict) -> list[tuple[str, str]]:
    status_by_id = {str(item.get("id") or ""): item for item in status.get("instances", [])}
    pools: dict[str, dict[str, Any]] = {}
    account_scopes = {TRAFFIC_SCOPE_ACCOUNT_NON_CHINA, TRAFFIC_SCOPE_ACCOUNT_ALL}

    def add_pool(pool_id: str, scope: str | None, name: str, source: str, member_key: str) -> None:
        pool_id = str(pool_id or "").strip()
        scope = normalize_traffic_scope(scope)
        if not pool_id or (source == "auto" and scope not in account_scopes):
            return
        pool = pools.setdefault(pool_id, {"members": set(), "scopes": set(), "names": [], "sources": set()})
        member_key = member_key or f"{pool_id}:{name}"
        if member_key in pool["members"]:
            return
        pool["members"].add(member_key)
        pool["scopes"].add(traffic_scope_label(scope))
        pool["sources"].add(source)
        if name:
            pool["names"].append(name)

    for item in config.get("instances", []):
        server_id = str(item.get("id") or "")
        status_item = status_by_id.get(server_id, {})
        pool_id = str(item.get("traffic_pool_id") or "").strip()
        name = first_value(item.get("product_name"), item.get("label"), item.get("instance_id"), server_id)
        if pool_id:
            add_pool(pool_id, item.get("traffic_scope") or status_item.get("traffic_scope"), name, "custom", server_id)

    for item in status.get("instances", []):
        server_id = str(item.get("id") or "")
        pool_id = str(item.get("traffic_pool_id") or "").strip()
        name = first_value(item.get("product_name"), item.get("label"), item.get("instance_name"), item.get("id"))
        source = "custom" if item.get("traffic_pool_custom") else "auto"
        add_pool(pool_id, item.get("traffic_scope"), name, source, server_id)

    options = []
    for pool_id, info in pools.items():
        scope_text = "、".join(sorted(info["scopes"]))
        name_preview = "、".join([name for name in info["names"] if name][:2])
        source_text = "手动分组" if "custom" in info["sources"] else "自动共享池"
        label = f"{pool_id} · {source_text} · 已有 {len(info['members'])} 台"
        if scope_text:
            label += f" · {scope_text}"
        if name_preview:
            label += f" · {name_preview}"
        options.append((pool_id, label))
    return sorted(options, key=lambda item: item[0].lower())


def traffic_pool_field(name: str, value: str, pool_options: list[tuple[str, str]]) -> str:
    list_id = f"{name}-options"
    option_html = "".join(
        f'<option value="{esc(pool_id)}" label="{esc(label)}">{esc(label)}</option>'
        for pool_id, label in pool_options
    )
    chips = "".join(
        f'<span class="pool-option-chip">{esc(pool_id)}</span>'
        for pool_id, _ in pool_options[:8]
    )
    if chips:
        chips = f'<div class="pool-option-list">{chips}</div>'
    advice = """
      <div class="pool-auto-advice">
        <strong>推荐：同一个阿里云账号的机器，这里直接留空</strong>
        新增日本、香港、新加坡等非中国内地机器时，决定归属的是你填写的 AccessKey：填哪个阿里云账号的 AccessKey，就归到哪个账号池；上方选择“账号非中国内地共享池”，这里留空即可。
      </div>
    """
    hint = "只有多个 RAM AccessKey 需要强制合并统计时，才手动选择已有分组或填写同一个新分组名。不同阿里云账号不要共用同一个手动分组。"
    if not pool_options:
        hint += " 当前没有手动分组可选，这不是错误；多数情况下保持留空即可。"
    return f"""
      <div class="mb-3">
        <label class="form-label">流量池分组（通常不用填）</label>
        {advice}
        <input class="form-control" type="text" name="{esc(name)}" value="{esc(value)}" placeholder="推荐留空：按阿里云账号自动归组" list="{esc(list_id)}">
        <datalist id="{esc(list_id)}">{option_html}</datalist>
        <div class="form-hint">{esc(hint)}</div>
        {chips}
      </div>
    """


def checkbox_field(name: str, label: str, checked: bool, hint: str = "") -> str:
    hint_html = f'<div class="form-hint">{esc(hint)}</div>' if hint else ""
    return f"""
      <div class="mb-3">
        <label class="form-check">
          <input class="form-check-input" type="checkbox" name="{esc(name)}" value="1" {"checked" if checked else ""}>
          <span class="form-check-label">{esc(label)}</span>
        </label>
        {hint_html}
      </div>
    """


def render_form_guide() -> str:
    return """
    <aside class="card guide-panel">
      <div class="card-header"><h3 class="card-title">填写说明</h3></div>
      <div class="card-body">
        <div class="guide-step">
          <strong>1. 新增只填核心信息</strong>
          <span>产品名、Instance ID、区域和 AccessKey 是必须的；服务器 IP 建议填写，方便识别是哪台机器。</span>
        </div>
        <div class="guide-step">
          <strong>2. 其他信息后期补</strong>
          <span>别名、服务商、登录网站、SSH、备注都可以保存后再编辑，不影响第一次巡检。</span>
        </div>
        <div class="guide-step">
          <strong>3. 填 AccessKey</strong>
          <span>这里不会自动带入任何密钥。请填写这台服务器所属阿里云账号或 RAM 用户的 AccessKey ID 和 Secret。</span>
        </div>
        <div class="guide-step">
          <strong>4. 区域 ID 要填准</strong>
          <span>控制台常显示地域名称，官方“地域和可用区”文档会列出地域 ID；例如中国香港是 cn-hongkong，日本东京是 ap-northeast-1。</span>
        </div>
        <div class="guide-step">
          <strong>5. 阈值可先用默认</strong>
          <span>默认预警 160GB、停机 180GB、恢复 175GB；以后可以按自己的账号额度再微调。</span>
        </div>
        <div class="guide-step">
          <strong>6. 共享池不用去阿里云找 ID</strong>
          <span>新增日本等非中国内地机器时，统计方式选“账号非中国内地共享池”，流量池分组通常留空；面板会按 AccessKey 自动归到同一账号池。</span>
        </div>
        <div class="guide-step">
          <strong>7. 账期优先走 BSS</strong>
          <span>已授权 BSS 后，面板会用账单 API 判断真实账期；每月重置日只是备用推算。</span>
        </div>
        <div class="guide-step">
          <strong>8. 保存后的反应</strong>
          <span>点击保存后会立即写入配置并做一次检查，按钮会进入等待状态，完成后回到总览页。</span>
        </div>
      </div>
    </aside>
    """


def render_form(item: dict, pool_options: list[tuple[str, str]] | None = None) -> str:
    pool_options = pool_options or []
    is_edit = bool(item)
    title = "编辑服务器" if is_edit else "新增服务器"
    id_value = item.get("id", "")
    access_key_id = item.get("access_key_id", "")
    access_key_hint = "编辑时留空则保留原 AccessKey ID 或继续使用全局配置。" if is_edit else "新增时不会自动填入已有密钥。"
    secret_hint = "编辑时留空则保留原 Secret 或继续使用全局配置。" if is_edit else ""
    panel_password_hint = "编辑时留空则保留原密码" if is_edit else ""
    current_scope = item.get("traffic_scope", TRAFFIC_SCOPE_REGION)
    advanced_open = " open" if is_edit else ""
    return f"""
    <form class="card save-form" method="post" action="/servers/save" data-save-form>
      <div class="card-header"><h3 class="card-title">{title}</h3></div>
      <div class="card-body">
        <input type="hidden" name="original_id" value="{esc(id_value)}">
        <section class="form-section">
          <h3 class="form-section-title">必填信息</h3>
          <div class="setup-box">
            新增服务器只需要先填能完成巡检的核心信息：产品名、实例 ID、区域和阿里云 AccessKey。别名、登录备注、SSH 等可以保存后再编辑补充。
          </div>
          {input_field("product_name", "产品自定义名字", item.get("product_name", ""), placeholder="例如：阿里云香港 1号机", required=True)}
          <div class="credential-grid">
            {input_field("server_ip", "服务器 IP", first_value(item.get("server_ip"), item.get("public_ip")), placeholder="例如：154.83.98.194")}
            {input_field("instance_id", "ECS Instance ID", item.get("instance_id", ""), placeholder="例如：i-j6ceg1880o7i5vxdpeq4", required=True)}
          </div>
          <div class="credential-grid">
            {region_field("region_id", "区域 ID", item.get("region_id", "cn-hongkong"), placeholder="输入或选择，例如：cn-hongkong", hint="必须和 ECS 实例所在地域一致；填错会导致实例查询和开关机失败。", required=True)}
            {input_field("access_key_id", "阿里云 AccessKey ID", access_key_id, placeholder="粘贴 AccessKey ID", hint=access_key_hint, required=not is_edit)}
          </div>
          {input_field("access_key_secret", "阿里云 AccessKey Secret", "", "password", placeholder="粘贴 AccessKey Secret", hint=secret_hint or "只在保存时写入配置文件，页面不会回显。", required=not is_edit)}
        </section>
        <section class="form-section">
          <h3 class="form-section-title">推荐保护设置</h3>
          <div class="credential-grid">
            {input_field("warning_threshold_gb", "预警阈值 GB", item.get("warning_threshold_gb", 160), "number")}
            {input_field("stop_threshold_gb", "停机阈值 GB", item.get("stop_threshold_gb", 180), "number")}
          </div>
          <div class="credential-grid">
            {input_field("start_threshold_gb", "恢复启动阈值 GB", item.get("start_threshold_gb", 175), "number")}
            <div class="mb-3">
              <label class="form-label">自动保护</label>
              <label class="form-check form-switch mt-2">
                <input class="form-check-input" type="checkbox" name="enabled" value="1" {"checked" if item.get("enabled", True) else ""}>
                <span class="form-check-label">启用自动巡检和启停</span>
              </label>
              <div class="form-hint">默认开启。达到停机阈值会自动关机，低于恢复阈值才会再次启动。</div>
            </div>
          </div>
        </section>
        <details class="form-section detail-disclosure"{advanced_open}>
          <summary>高级设置</summary>
          <div class="credential-grid mt-3">
            {input_field("label", "服务器别名", item.get("label", ""), placeholder="例如：HK-01", hint="可选；留空会使用产品自定义名字。")}
            {input_field("provider", "服务商", item.get("provider", "阿里云"))}
          </div>
          <div class="credential-grid">
            {region_field("traffic_region_id", "CDT 流量区域", item.get("traffic_region_id", "") if is_edit else "", placeholder="留空默认跟随区域 ID，例如 cn-hongkong", hint="留空会自动跟随区域 ID；共享池模式下只用于备注和兼容旧配置。")}
            {input_field("traffic_reset_day", "CDT 每月重置日", item.get("traffic_reset_day", 1), "number", hint="BSS 账单 API 不可用时才作为备用推算。通常填 1。")}
          </div>
          <div class="credential-grid">
            {select_field("traffic_scope", "CDT 统计方式", current_scope, [
                (TRAFFIC_SCOPE_REGION, "按当前 CDT 区域统计"),
                (TRAFFIC_SCOPE_ACCOUNT_NON_CHINA, "账号非中国内地共享池"),
                (TRAFFIC_SCOPE_ACCOUNT_ALL, "账号全部 CDT 流量"),
            ], "香港、日本、新加坡等机器共享同一账号额度时，建议选“账号非中国内地共享池”。")}
            {traffic_pool_field("traffic_pool_id", item.get("traffic_pool_id", ""), pool_options)}
          </div>
        </details>
        <details class="form-section detail-disclosure"{advanced_open}>
          <summary>登录备注</summary>
          <div class="setup-box mt-3">
            这些只是给你自己看的资产备注，不影响阿里云巡检和自动启停，可以保存服务器后再补。
          </div>
          <div class="credential-grid">
            {input_field("panel_url", "服务器登录网站", item.get("panel_url", ""), placeholder="https://example.com/clientarea")}
            {input_field("panel_username", "登录网站账号", item.get("panel_username", ""))}
          </div>
          <div class="credential-grid">
            {input_field("panel_password", "登录网站密码", "", "password", hint=panel_password_hint)}
            {input_field("ssh_user", "SSH 用户", item.get("ssh_user", "root"))}
          </div>
          <div class="credential-grid">
            {input_field("ssh_port", "SSH 端口", item.get("ssh_port", 22), "number")}
            {input_field("ssh_password", "SSH 密码备注", "", "password", hint=panel_password_hint)}
          </div>
          <div class="mb-3">
            <label class="form-label">备注</label>
            <textarea class="form-control" name="notes" rows="4" placeholder="用途、购买平台、套餐、到期时间、注意事项">{esc(item.get("notes", ""))}</textarea>
          </div>
        </details>
      </div>
      <div class="card-footer d-flex align-items-center gap-2">
        <div class="submit-feedback"><span class="spinner-dot"></span><span>正在保存配置并立即检查，请稍等...</span></div>
        {f'<a href="/" class="btn me-2">取消编辑</a>' if is_edit else ""}
        <button class="btn btn-primary btn-submit ms-auto" type="submit" data-submit-button data-loading-text="正在保存...">保存服务器</button>
      </div>
    </form>
    """


def save_server(fields: dict[str, list[str]]) -> str:
    config = read_config()
    original_id = form_value(fields, "original_id")
    product_name = form_value(fields, "product_name")
    instance_id = form_value(fields, "instance_id")
    server_id = original_id or slug(first_value(product_name, instance_id))
    existing = selected_instance(config, original_id) if original_id else {}

    access_key_id = form_value(fields, "access_key_id") or existing.get("access_key_id", "")
    access_secret = form_value(fields, "access_key_secret")
    panel_password = form_value(fields, "panel_password")
    ssh_password = form_value(fields, "ssh_password")
    item = {
        "id": server_id,
        "product_name": product_name,
        "label": form_value(fields, "label") or product_name,
        "provider": form_value(fields, "provider", "阿里云"),
        "server_ip": form_value(fields, "server_ip"),
        "region_id": form_value(fields, "region_id", "cn-hongkong"),
        "traffic_region_id": form_value(fields, "traffic_region_id") or form_value(fields, "region_id", "cn-hongkong"),
        "traffic_scope": form_value(fields, "traffic_scope", existing.get("traffic_scope", TRAFFIC_SCOPE_REGION)) or TRAFFIC_SCOPE_REGION,
        "traffic_pool_id": form_value(fields, "traffic_pool_id") or existing.get("traffic_pool_id", ""),
        "instance_id": instance_id,
        "access_key_id": access_key_id,
        "access_key_secret": access_secret or existing.get("access_key_secret", ""),
        "warning_threshold_gb": as_float(form_value(fields, "warning_threshold_gb"), 160),
        "stop_threshold_gb": as_float(form_value(fields, "stop_threshold_gb"), 180),
        "start_threshold_gb": as_float(form_value(fields, "start_threshold_gb"), 175),
        "traffic_reset_day": int(max(1, min(as_float(form_value(fields, "traffic_reset_day"), 1), 28))),
        "panel_url": form_value(fields, "panel_url"),
        "panel_username": form_value(fields, "panel_username"),
        "panel_password": panel_password or existing.get("panel_password", ""),
        "ssh_user": form_value(fields, "ssh_user", "root"),
        "ssh_port": int(as_float(form_value(fields, "ssh_port"), 22)),
        "ssh_password": ssh_password or existing.get("ssh_password", ""),
        "notes": form_value(fields, "notes"),
        "enabled": form_value(fields, "enabled") == "1",
        "manual_stop": bool(existing.get("manual_stop", False)),
    }

    instances = [server for server in config.get("instances", []) if str(server.get("id")) != server_id]
    instances.append(item)
    config["instances"] = instances
    config.setdefault("version", 1)
    config.setdefault("defaults", {})
    write_json(CONFIG_FILE, config)
    return server_id


def delete_server(server_id: str) -> None:
    config = read_config()
    config["instances"] = [
        server for server in config.get("instances", [])
        if str(server.get("id")) != server_id
    ]
    write_json(CONFIG_FILE, config)


def run_guard_now() -> None:
    subprocess.run(
        [str(BASE_DIR / "venv/bin/python"), str(BASE_DIR / "guard.py"), "run"],
        cwd=str(BASE_DIR),
        timeout=60,
        check=False,
    )


def run_power_action(server_id: str, power_action: str) -> bool:
    result = subprocess.run(
        [str(BASE_DIR / "venv/bin/python"), str(BASE_DIR / "guard.py"), "power", server_id, power_action],
        cwd=str(BASE_DIR),
        timeout=90,
        check=False,
    )
    return result.returncode == 0


class Handler(BaseHTTPRequestHandler):
    server_version = "AliyunCDTGuard/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/healthz":
            self.send_json({"ok": True})
            return
        if parsed.path == "/logout":
            self.handle_logout()
            return
        if parsed.path == "/login":
            if self.is_authorized():
                self.redirect("/")
            else:
                self.send_bytes(render_login_page(query), "text/html; charset=utf-8")
            return
        if not self.is_authorized():
            self.send_login_required()
            return
        if parsed.path == "/":
            self.send_bytes(render_dashboard(query), "text/html; charset=utf-8")
            return
        if parsed.path == "/servers/new":
            self.send_bytes(render_server_form_page(query), "text/html; charset=utf-8")
            return
        if parsed.path == "/servers/edit":
            self.send_bytes(render_server_form_page(query), "text/html; charset=utf-8")
            return
        if parsed.path == "/logs":
            self.send_bytes(render_logs_page(query), "text/html; charset=utf-8")
            return
        if parsed.path == "/notifications":
            self.send_bytes(render_notifications_page(query), "text/html; charset=utf-8")
            return
        if parsed.path == "/domain":
            self.send_bytes(render_domain_page(query), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/status":
            self.send_json(read_json(STATUS_FILE, {"error": "status not found"}))
            return
        if parsed.path == "/api/history":
            limit = int(query.get("limit", ["200"])[0])
            self.send_json(read_history(max(1, min(limit, 1000))))
            return
        if parsed.path == "/api/traffic":
            server_id = query.get("server", [""])[0]
            pool_key = query.get("pool", [""])[0]
            days = int(query.get("days", ["1"])[0])
            self.send_json(read_traffic_series(server_id, days, pool_key))
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        if parsed.path == "/login":
            self.handle_login(fields)
            return
        if parsed.path == "/logout":
            self.handle_logout()
            return
        if not self.is_authorized():
            self.send_login_required()
            return
        if parsed.path == "/servers/save":
            save_server(fields)
            run_guard_now()
            self.redirect("/?flash=saved")
            return
        if parsed.path == "/servers/delete":
            delete_server(form_value(fields, "id"))
            run_guard_now()
            self.redirect("/?flash=deleted")
            return
        if parsed.path == "/servers/power":
            server_id = form_value(fields, "id")
            power_action = form_value(fields, "action")
            if power_action not in {"start", "stop"}:
                self.redirect("/?flash=power_failed")
                return
            ok = run_power_action(server_id, power_action)
            if ok and power_action == "start":
                self.redirect("/?flash=started")
            elif ok and power_action == "stop":
                self.redirect("/?flash=stopped")
            else:
                self.redirect("/?flash=power_failed")
            return
        if parsed.path == "/guard/run":
            run_guard_now()
            self.redirect("/?flash=checked")
            return
        if parsed.path == "/balance/run":
            run_guard_now()
            self.redirect("/?flash=balance_checked")
            return
        if parsed.path == "/notifications/save":
            save_notifications(fields)
            self.redirect("/notifications?flash=notify_saved")
            return
        if parsed.path == "/domain/save":
            save_domain_proxy(fields)
            self.redirect("/domain?flash=domain_saved")
            return
        if parsed.path == "/notifications/test":
            result = notifications.send_test_message()
            state = notifications.load_state()
            state["last_test_result"] = result
            if not result.get("ok"):
                state["telegram_last_error"] = str(result.get("error") or result.get("channels", {}).get("telegram", {}).get("error") or "测试通知发送失败")
            else:
                state.pop("telegram_last_error", None)
            notifications.save_state(state)
            self.redirect("/notifications?flash=notify_test_sent" if result.get("ok") else "/notifications?flash=notify_test_failed")
            return
        if parsed.path == "/notifications/telegram/discover":
            ok = discover_telegram_chats()
            self.redirect("/notifications?flash=telegram_discovered" if ok else "/notifications?flash=telegram_discover_failed")
            return
        if parsed.path == "/notifications/telegram/use-chat":
            use_telegram_chat(form_value(fields, "chat_id"))
            self.redirect("/notifications?flash=telegram_chat_saved")
            return
        if parsed.path == "/notifications/telegram/remove-chat":
            remove_telegram_chat(form_value(fields, "chat_id"))
            self.redirect("/notifications?flash=telegram_chat_removed")
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def is_authorized(self) -> bool:
        username, password, env = web_credentials()
        if not password:
            return False
        if self.is_session_authorized(username, password, env):
            return True
        if cookie_parts(self.headers.get("Cookie", "")).get("cdt_guard_logged_out") == "1":
            return False
        return self.is_basic_authorized(username, password)

    def is_basic_authorized(self, username: str, password: str) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        except Exception:
            return False
        supplied_user, _, supplied_password = decoded.partition(":")
        return hmac.compare_digest(supplied_user, username) and hmac.compare_digest(supplied_password, password)

    def is_session_authorized(self, username: str, password: str, env: dict[str, str]) -> bool:
        cookie = cookie_parts(self.headers.get("Cookie", "")).get("cdt_guard_session", "")
        parts = cookie.split("|")
        if len(parts) != 4:
            return False
        supplied_user, expires, nonce, signature = parts
        if supplied_user != username:
            return False
        try:
            if int(expires) < int(time.time()):
                return False
        except ValueError:
            return False
        expected = sign_session(supplied_user, expires, nonce, session_secret(env, password))
        return hmac.compare_digest(signature, expected)

    def handle_login(self, fields: dict[str, list[str]]) -> None:
        username, password, env = web_credentials()
        supplied_user = form_value(fields, "username")
        supplied_password = form_value(fields, "password")
        if password and hmac.compare_digest(supplied_user, username) and hmac.compare_digest(supplied_password, password):
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", build_session_cookie(username, env, password))
            self.send_header("Set-Cookie", clear_logout_marker_cookie())
            self.end_headers()
            return
        self.redirect("/login?flash=login_failed")

    def handle_logout(self) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/login?flash=logged_out")
        self.send_header("Set-Cookie", clear_session_cookie())
        self.send_header("Set-Cookie", logout_marker_cookie())
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def send_login_required(self):
        self.redirect("/login?flash=login_required")

    def redirect(self, location: str):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def send_json(self, data):
        body = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        self.send_bytes(body, "application/json; charset=utf-8")

    def send_bytes(self, body: bytes, content_type: str):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


def main() -> int:
    env = load_env(WEB_ENV_FILE)
    host = os.environ.get("CDT_GUARD_HOST", env.get("CDT_GUARD_HOST", "0.0.0.0"))
    port = int(os.environ.get("CDT_GUARD_PORT", env.get("CDT_GUARD_PORT", "8787")))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Aliyun CDT Guard web listening on http://{host}:{port}")
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
from urllib.parse import parse_qs, urlparse

import notifications

BASE_DIR = Path(os.environ.get("CDT_GUARD_HOME", "/opt/aliyun-cdt-guard"))
WEB_ENV_FILE = BASE_DIR / "web.env"
CONFIG_FILE = BASE_DIR / "instances.json"
STATUS_FILE = BASE_DIR / "status.json"
HISTORY_FILE = BASE_DIR / "history.jsonl"
TRAFFIC_SCOPE_REGION = "region"
TRAFFIC_SCOPE_ACCOUNT_NON_CHINA = "account_non_china"
TRAFFIC_SCOPE_ACCOUNT_ALL = "account_all"
TRAFFIC_SCOPE_LABELS = {
    TRAFFIC_SCOPE_REGION: "按当前 CDT 区域统计",
    TRAFFIC_SCOPE_ACCOUNT_NON_CHINA: "账号非中国内地共享池",
    TRAFFIC_SCOPE_ACCOUNT_ALL: "账号全部 CDT 流量",
}


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
    days = plan.get("days_until_reset")
    will_auto_start = bool(plan.get("will_auto_start_after_reset"))
    paused = bool(plan.get("auto_start_paused"))
    status_text = "会自动开机" if will_auto_start else ("手动关机保持中" if paused else "未处于自动恢复队列")
    status_class = "recovery-ok" if will_auto_start else ("recovery-paused" if paused else "recovery-neutral")
    return f"""
      <div class="recovery-panel {status_class}">
        <div>
          <div class="recovery-title">{esc(status_text)}</div>
          <div class="recovery-copy">{esc(plan.get('recovery_note') or '')}</div>
        </div>
        <div class="recovery-count">
          <div class="recovery-days">{esc(days)}</div>
          <div class="recovery-unit">天后重置</div>
        </div>
      </div>
      <div class="detail-grid mt-3">
        <div class="detail-item">
          <div class="info-label">预计重置日期</div>
          <div class="info-value">{esc(fmt_date(plan.get('next_reset_at')))}</div>
          <div class="text-secondary small">每月 {esc(plan.get('traffic_reset_day') or 1)} 日 00:00 UTC</div>
        </div>
        <div class="detail-item">
          <div class="info-label">恢复判断</div>
          <div class="info-value">{esc('自动巡检会开机' if will_auto_start else '暂不自动开机')}</div>
          <div class="text-secondary small">恢复阈值 {fmt_gb(item.get('start_threshold_gb'))}</div>
        </div>
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
        "saved": "服务器已保存并完成一次检查",
        "deleted": "服务器已删除",
        "started": "已提交开机指令，并恢复自动保护",
        "stopped": "已提交关机指令，自动启动已暂停",
        "power_failed": "电源操作失败，请查看服务器日志",
        "notify_saved": "通知设置已保存",
        "notify_test_sent": "已发送测试通知，请检查接收端",
        "notify_test_failed": "测试通知发送失败，请检查配置",
        "login_required": "请先登录",
        "login_failed": "用户名或密码不正确",
        "logged_out": "已退出登录",
    }
    return messages.get(code, code)


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
    ]
    nav_html = "".join(
        f'<li class="nav-item {"active" if key == active else ""}"><a class="nav-link" href="{href}"><span class="nav-link-title">{label}</span></a></li>'
        for href, key, label in nav
    )
    flash_html = f'<div class="alert alert-success">{esc(flash_message(flash))}</div>' if flash else ""
    refresh_meta = '<meta http-equiv="refresh" content="60">' if auto_refresh else ""
    header_actions = f"""
      {actions}
      <form class="ms-2" method="post" action="/logout">
        <button class="btn btn-sm" type="submit">退出登录</button>
      </form>
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
    .log-layout {{ display: grid; grid-template-columns: 300px minmax(0, 1fr); gap: 18px; }}
    .log-item summary {{ cursor: pointer; list-style: none; }}
    .log-item summary::-webkit-details-marker {{ display: none; }}
    .log-meta {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 18px; }}
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
          <div class="navbar-nav flex-row order-md-last ms-auto">{header_actions}</div>
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
        const ordered = rows.slice().sort((a, b) => {{
          const mode = sort?.value || "health";
          if (mode === "traffic") return Number(b.dataset.used || 0) - Number(a.dataset.used || 0);
          if (mode === "name") return (a.dataset.name || "").localeCompare(b.dataset.name || "", "zh-Hans-CN");
          return Number(a.dataset.priority || 9) - Number(b.dataset.priority || 9);
        }});
        ordered.forEach((row) => list.appendChild(row));

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
    function timeText(value) {{
      if (!value) return "暂无";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString("zh-CN", {{ hour12: false }});
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
      const pad = {{ left: 54, right: 24, top: 24, bottom: 42 }};
      const values = points.map((point) => Number(point.traffic_gb || 0));
      const deltas = points.map((point) => Number(point.delta_gb || 0));
      const minValue = Math.min(...values);
      const maxValue = Math.max(...values);
      const maxDelta = Math.max(...deltas, 0.001);
      const span = maxValue - minValue || 1;
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
      }}
      points.forEach((point, index) => {{
        const delta = Number(point.delta_gb || 0);
        if (delta <= 0) return;
        const h = Math.max(2, delta / maxDelta * 58);
        add("rect", {{ x: xAt(index) - barW / 2, y: barY - h, width: barW, height: h, rx: "2", fill: "rgba(245, 159, 0, .36)" }});
      }});
      const line = values.map((value, index) => `${{xAt(index).toFixed(1)}},${{yAt(value).toFixed(1)}}`).join(" ");
      add("polyline", {{ points: line, fill: "none", stroke: "#1763d1", "stroke-width": "3", "stroke-linecap": "round", "stroke-linejoin": "round" }});
      add("text", {{ x: pad.left, y: height - 12, fill: "#64748b", "font-size": "12" }}).textContent = timeText(points[0].at);
      add("text", {{ x: width - pad.right, y: height - 12, fill: "#64748b", "font-size": "12", "text-anchor": "end" }}).textContent = timeText(points[points.length - 1].at);
      add("text", {{ x: 10, y: pad.top + 4, fill: "#64748b", "font-size": "12" }}).textContent = gbText(maxValue);
      add("text", {{ x: 10, y: pad.top + plotH, fill: "#64748b", "font-size": "12" }}).textContent = gbText(minValue);

      const tooltip = document.querySelector("[data-chart-tooltip]");
      const markerStep = Math.max(1, Math.ceil(points.length / 180));
      points.forEach((point, index) => {{
        if (index % markerStep !== 0 && index !== points.length - 1) return;
        const cx = xAt(index);
        const cy = yAt(Number(point.traffic_gb || 0));
        const circle = add("circle", {{ cx, cy, r: "7", fill: "transparent", stroke: "transparent" }});
        circle.addEventListener("pointermove", () => {{
          if (!tooltip) return;
          tooltip.innerHTML = `${{timeText(point.at)}}<br>累计：${{gbText(point.traffic_gb)}}<br>新增：${{gbText(point.delta_gb)}}`;
          tooltip.style.display = "block";
          tooltip.style.left = (cx / width * 100) + "%";
          tooltip.style.top = (cy / height * 100) + "%";
        }});
        circle.addEventListener("pointerleave", () => {{
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
    <div>
      <form class="run-check-form" method="post" action="/guard/run" data-run-check-form>
        <button class="btn btn-primary" type="submit" title="马上查询 CDT 流量和 ECS 状态，并按阈值执行一次保护判断" data-run-check-button data-loading-text="正在检查...">手动检查流量</button>
      </form>
    </div>
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
    request_id = item.get("traffic_request_id")
    request_line = f'<div class="text-secondary small mt-2">CDT API RequestId：{esc(request_id)}</div>' if request_id else ""
    matched = item.get("traffic_matched_detail_count")
    total = item.get("traffic_detail_count")
    count_line = ""
    if matched is not None and total is not None:
        count_line = f'<div class="text-secondary small mt-2">CDT 明细匹配 {esc(matched)} / {esc(total)} 条</div>'
    scope_line = f'<div class="text-secondary small mt-2">统计范围：{esc(traffic_pool_text(item))}</div>'
    return f'<div class="breakdown-list">{"".join(rows)}</div>{scope_line}{count_line}{request_line}'


def render_server_row(item: dict, metadata: dict[str, dict], history: list[dict], active: bool = False) -> str:
    identity = server_identity(item, metadata)
    state_class, state_label, state_sub = status_view(item.get("instance_status"))
    health_class, filter_label, priority = server_health(item)
    pct = used_percent(item)
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
          <span class="text-truncate">
            <span class="asset-name d-block text-truncate">{esc(identity['product_name'])}</span>
            <span class="asset-sub d-block text-truncate">{esc(identity['asset_label'])} · {esc(identity['provider'])}</span>
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
          <div class="info-label">预计恢复开机</div>
          {render_recovery_plan(item)}
        </div>
        <div class="detail-section">
          <div class="info-label">CDT 计费明细</div>
          {render_traffic_breakdown(item)}
        </div>
        <div class="detail-section">
          <div class="info-label">当前判断</div>
          <div>{badge(item.get('action'))}</div>
          <div class="text-secondary small mt-2">{esc(item.get('reason'))}</div>
          {f'<div class="text-danger small mt-1">{esc(manual_note)}</div>' if manual_note else ''}
          {f'<div class="text-danger small mt-1">{esc(item.get("last_error"))}</div>' if item.get("last_error") else ''}
        </div>
        <div class="detail-section">
          <div class="info-label">电源控制</div>
          {power_controls(identity['id'], item.get('instance_status'))}
        </div>
        <div class="detail-section">
          <div class="detail-grid">
            <div class="detail-item">
              <div class="info-label">服务器 IP</div>
              <div class="ip-main">{esc(identity['primary_ip'])}</div>
              {small_line("公网 ", ", ".join(identity["public_ips"]))}
              {small_line("内网 ", ", ".join(identity["private_ips"]))}
            </div>
            <div class="detail-item">
              <div class="info-label">区域</div>
              <div class="info-value">{esc(item.get('region_id'))}</div>
              <div class="text-secondary small">CDT {esc(item.get('traffic_region_id'))}</div>
            </div>
            <div class="detail-item">
              <div class="info-label">CDT 流量池</div>
              <div class="info-value">{esc(item.get('traffic_pool_id') or '默认池')}</div>
              <div class="text-secondary small">{esc(item.get('traffic_scope_label') or traffic_scope_label(item.get('traffic_scope')))}</div>
              <div class="text-secondary small">池内启用机器 {esc(item.get('traffic_pool_member_count') or 0)} 台</div>
            </div>
            <div class="detail-item">
              <div class="info-label">保护阈值</div>
              <div class="info-value">预警 {fmt_gb(item.get('warning_threshold_gb'))}</div>
              <div class="text-secondary small">恢复启动 {fmt_gb(item.get('start_threshold_gb'))}</div>
            </div>
            <div class="detail-item">
              <div class="info-label">最近检查</div>
              <div class="info-value">{esc(fmt_time(item.get('updated_at')))}</div>
            </div>
          </div>
        </div>
        <details class="detail-section">
          <summary class="info-label">登录、实例 ID 与备注</summary>
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
              <div class="info-label">实例 ID</div>
              <div class="text-secondary small text-break">{esc(item.get('instance_id'))}</div>
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
    rows = []
    details = []
    for index, item in enumerate(sorted_instances):
        rows.append(render_server_row(item, metadata, history, active=index == 0))
        details.append(render_server_detail(item, metadata, active=index == 0))
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
            {''.join(rows)}
          </div>
          <div class="empty-state" data-empty-state hidden>没有符合条件的服务器</div>
          {'' if rows else '<div class="empty-state">暂无服务器，请到“新增/编辑”添加第一台。</div>'}
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
    edit_id = query.get("id", [""])[0]
    editing = selected_instance(config, edit_id)
    body = f"""
    <div class="form-layout">
      <div>{render_form(editing)}</div>
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

    server_links = []
    for server in configured:
        server_id = str(server.get("id") or server.get("instance_id"))
        stat = status_by_id.get(server_id, {})
        active = "active" if server_id == selected_id else ""
        count = sum(1 for event in history if str(event.get("id")) == server_id)
        name = first_value(server.get("product_name"), server.get("label"), stat.get("label"), default=server_id)
        server_links.append(
            f"""
            <a href="/logs?server={esc(server_id)}" class="list-group-item list-group-item-action {active}">
              <div class="d-flex align-items-center">
                <div class="flex-fill">
                  <div class="fw-semibold">{esc(name)}</div>
                  <div class="text-secondary small">{esc(server.get('instance_id'))}</div>
                </div>
                <span class="badge bg-secondary-lt">{count}</span>
              </div>
            </a>
            """
        )

    selected_logs = [
        event for event in reversed(history)
        if not selected_id or str(event.get("id")) == selected_id
    ]
    log_items = []
    for event in selected_logs:
        danger = bool(event.get("error"))
        log_items.append(
            f"""
            <details class="list-group-item log-item">
              <summary>
                <div class="row align-items-center">
                  <div class="col-auto"><span class="status-dot {'bg-red' if danger else 'bg-green'} d-block"></span></div>
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
            <h3 class="card-title">日志详情</h3>
            <a class="btn btn-sm" href="/api/history">历史 JSON</a>
          </div>
        </div>
        <div class="list-group list-group-flush">{''.join(log_items) if log_items else '<div class="list-group-item text-secondary">暂无日志</div>'}</div>
      </div>
    </div>
    """
    return page_shell(
        "logs",
        "服务器日志",
        "按服务器查看最近巡检、启停和错误记录",
        body,
        actions=render_check_action(),
    )


def render_notifications_page(query: dict[str, list[str]] | None = None) -> bytes:
    query = query or {}
    config = notifications.load_config()
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
        <section class="form-section">
          <h3 class="form-section-title">通知总开关</h3>
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
          <h3 class="form-section-title">Telegram</h3>
          {checkbox_field("telegram_enabled", "启用 Telegram Bot 通知", bool(telegram.get("enabled")), "从 BotFather 创建机器人，填 Bot Token；Chat ID 可以是个人、群组或频道。")}
          <div class="credential-grid">
            {input_field("telegram_bot_token", "Bot Token", "", "password", placeholder="123456:ABC-DEF...", hint="留空则保留原 Token。")}
            {input_field("telegram_chat_id", "Chat ID", telegram.get("chat_id", ""), placeholder="例如：123456789 或 -100xxxxxxxxxx")}
          </div>
          {checkbox_field("telegram_disable_preview", "禁用链接预览", bool(telegram.get("disable_web_page_preview", True)))}
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
    <div class="card mt-3">
      <div class="card-header"><h3 class="card-title">测试通知</h3></div>
      <div class="card-body">
        <p class="text-secondary mb-3">保存设置后，可以发送一条测试消息确认 Telegram、Webhook 或邮件是否能收到。</p>
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


def save_notifications(fields: dict[str, list[str]]) -> None:
    existing = notifications.load_config()
    telegram_token = form_value(fields, "telegram_bot_token")
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
            "bot_token": telegram_token or existing.get("telegram", {}).get("bot_token", ""),
            "chat_id": form_value(fields, "telegram_chat_id"),
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
          <strong>1. 先填识别信息</strong>
          <span>产品名和服务器 IP 是给你自己看的，建议写成能一眼认出来的名字。</span>
        </div>
        <div class="guide-step">
          <strong>2. 填 ECS 实例信息</strong>
          <span>Instance ID 和区域 ID 必须和阿里云 ECS 控制台里显示的一致，例如 cn-hongkong。</span>
        </div>
        <div class="guide-step">
          <strong>3. 填 AccessKey</strong>
          <span>这里不会自动带入任何密钥。请填写这台服务器所属阿里云账号或 RAM 用户的 AccessKey ID 和 Secret。</span>
        </div>
        <div class="guide-step">
          <strong>4. 选择 CDT 流量池</strong>
          <span>如果一个阿里云账号下多台非中国内地服务器共享 200G/220G CDT，把它们设成同一个“账号非中国内地共享池”。</span>
        </div>
        <div class="guide-step">
          <strong>5. 设置阈值</strong>
          <span>达到停机阈值会自动关机；低于恢复启动阈值时才会再次启动，用来避免临界值反复开关。</span>
        </div>
        <div class="guide-step">
          <strong>6. 设置恢复时间</strong>
          <span>CDT 通常按自然月重置，默认每月 1 日。面板会据此显示预计多少天后可恢复开机。</span>
        </div>
        <div class="guide-step">
          <strong>7. 保存后的反应</strong>
          <span>点击保存后会立即写入配置并做一次检查，按钮会进入等待状态，完成后回到总览页。</span>
        </div>
      </div>
    </aside>
    """


def render_form(item: dict) -> str:
    is_edit = bool(item)
    title = "编辑服务器" if is_edit else "新增服务器"
    id_value = item.get("id", "")
    access_key_id = item.get("access_key_id", "")
    access_key_hint = "编辑时留空则保留原 AccessKey ID 或继续使用全局配置。" if is_edit else "新增时不会自动填入已有密钥。"
    secret_hint = "编辑时留空则保留原 Secret 或继续使用全局配置。" if is_edit else ""
    panel_password_hint = "编辑时留空则保留原密码" if is_edit else ""
    current_scope = item.get("traffic_scope", TRAFFIC_SCOPE_REGION)
    return f"""
    <form class="card save-form" method="post" action="/servers/save" data-save-form>
      <div class="card-header"><h3 class="card-title">{title}</h3></div>
      <div class="card-body">
        <input type="hidden" name="original_id" value="{esc(id_value)}">
        <section class="form-section">
          <h3 class="form-section-title">基础识别</h3>
          {input_field("product_name", "产品自定义名字", item.get("product_name", ""), placeholder="例如：阿里云香港 1号机", required=True)}
          <div class="credential-grid">
            {input_field("label", "服务器别名", item.get("label", ""), placeholder="例如：HK-01")}
            {input_field("provider", "服务商", item.get("provider", "阿里云"))}
          </div>
          <div class="credential-grid">
            {input_field("server_ip", "服务器 IP", first_value(item.get("server_ip"), item.get("public_ip")), placeholder="例如：154.83.98.194")}
            {input_field("instance_id", "ECS Instance ID", item.get("instance_id", ""), placeholder="例如：i-j6ceg1880o7i5vxdpeq4", required=True)}
          </div>
        </section>
        <section class="form-section">
          <h3 class="form-section-title">阿里云凭证与区域</h3>
          <div class="credential-grid">
            {input_field("region_id", "区域 ID", item.get("region_id", "cn-hongkong"), placeholder="例如：cn-hongkong", required=True)}
            {input_field("traffic_region_id", "CDT 流量区域", item.get("traffic_region_id", item.get("region_id", "cn-hongkong")), placeholder="例如：cn-hongkong", hint="选择“按当前 CDT 区域统计”时使用；共享池模式下用于备注和兼容旧配置。")}
          </div>
          <div class="credential-grid">
            {input_field("access_key_id", "阿里云 AccessKey ID", access_key_id, placeholder="粘贴 AccessKey ID", hint=access_key_hint, required=not is_edit)}
            {input_field("access_key_secret", "阿里云 AccessKey Secret", "", "password", placeholder="粘贴 AccessKey Secret", hint=secret_hint or "只在保存时写入配置文件，页面不会回显。", required=not is_edit)}
          </div>
          <div class="credential-grid">
            {select_field("traffic_scope", "CDT 统计方式", current_scope, [
                (TRAFFIC_SCOPE_REGION, "按当前 CDT 区域统计"),
                (TRAFFIC_SCOPE_ACCOUNT_NON_CHINA, "账号非中国内地共享池"),
                (TRAFFIC_SCOPE_ACCOUNT_ALL, "账号全部 CDT 流量"),
            ], "香港、日本、新加坡等机器共享同一账号额度时，建议选“账号非中国内地共享池”。")}
            {input_field("traffic_pool_id", "流量池 ID", item.get("traffic_pool_id", ""), placeholder="例如：global-200g 或 hk-account-pool", hint="同一账号共享额度的机器填同一个 ID；留空会自动生成默认池。")}
          </div>
        </section>
        <section class="form-section">
          <h3 class="form-section-title">流量保护阈值</h3>
          <div class="credential-grid">
            {input_field("warning_threshold_gb", "预警阈值 GB", item.get("warning_threshold_gb", 160), "number")}
            {input_field("stop_threshold_gb", "停机阈值 GB", item.get("stop_threshold_gb", 180), "number")}
          </div>
          <div class="credential-grid">
            {input_field("start_threshold_gb", "恢复启动阈值 GB", item.get("start_threshold_gb", 175), "number")}
            {input_field("traffic_reset_day", "CDT 每月重置日", item.get("traffic_reset_day", 1), "number", hint="用于计算预计恢复开机时间。通常填 1，表示每月 1 日重置。")}
          </div>
          <div class="credential-grid">
            <div class="mb-3">
              <label class="form-label">自动保护</label>
              <label class="form-check form-switch mt-2">
                <input class="form-check-input" type="checkbox" name="enabled" value="1" {"checked" if item.get("enabled", True) else ""}>
                <span class="form-check-label">启用自动巡检和启停</span>
              </label>
            </div>
            <div></div>
          </div>
        </section>
        <section class="form-section">
          <h3 class="form-section-title">登录备注</h3>
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
        </section>
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
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/login?flash=logged_out")
            self.send_header("Set-Cookie", clear_session_cookie())
            self.end_headers()
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
        if parsed.path == "/notifications/save":
            save_notifications(fields)
            self.redirect("/notifications?flash=notify_saved")
            return
        if parsed.path == "/notifications/test":
            result = notifications.send_test_message()
            self.redirect("/notifications?flash=notify_test_sent" if result.get("ok") else "/notifications?flash=notify_test_failed")
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def is_authorized(self) -> bool:
        username, password, env = web_credentials()
        if not password:
            return False
        if self.is_session_authorized(username, password, env):
            return True
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
            self.end_headers()
            return
        self.redirect("/login?flash=login_failed")

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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import html
import json
import os
import secrets
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(os.environ.get("CDT_GUARD_HOME", "/opt/aliyun-cdt-guard"))
WEB_ENV_FILE = BASE_DIR / "web.env"
CONFIG_FILE = BASE_DIR / "instances.json"
STATUS_FILE = BASE_DIR / "status.json"
HISTORY_FILE = BASE_DIR / "history.jsonl"


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
        return f"{float(value):.4f} GB"
    except (TypeError, ValueError):
        return "未知"


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
        "manual_stopped": ("secondary", "手动保持停止"),
        "keep_running": ("success", "保持运行"),
        "keep_stopped": ("secondary", "保持停止"),
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
    }
    return messages.get(code, code)


def page_shell(active: str, title: str, subtitle: str, body: str, actions: str = "", flash: str = "") -> bytes:
    nav = [
        ("/", "overview", "总览"),
        ("/servers/new", "servers", "新增/编辑"),
        ("/logs", "logs", "服务器日志"),
    ]
    nav_html = "".join(
        f'<li class="nav-item {"active" if key == active else ""}"><a class="nav-link" href="{href}"><span class="nav-link-title">{label}</span></a></li>'
        for href, key, label in nav
    )
    flash_html = f'<div class="alert alert-success">{esc(flash_message(flash))}</div>' if flash else ""
    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="60">
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
    .server-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(520px, 1fr));
      gap: 18px;
      padding: 18px;
    }}
    .server-card {{
      overflow: hidden;
    }}
    .server-card-head {{
      align-items: flex-start;
      border-bottom: 1px solid var(--line);
      display: flex;
      gap: 18px;
      justify-content: space-between;
      padding: 20px 22px;
    }}
    .server-state {{
      align-items: center;
      border-radius: 999px;
      display: inline-flex;
      gap: 8px;
      padding: 7px 12px;
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
    .server-card-body {{
      display: grid;
      gap: 14px;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      padding: 18px 22px 22px;
    }}
    .info-block {{
      background: #fbfcfe;
      border: 1px solid var(--line);
      border-radius: 8px;
      min-height: 92px;
      padding: 14px 15px;
    }}
    .info-block.span-3 {{ grid-column: span 3; }}
    .info-block.span-4 {{ grid-column: span 4; }}
    .info-block.span-5 {{ grid-column: span 5; }}
    .info-block.span-6 {{ grid-column: span 6; }}
    .info-block.span-7 {{ grid-column: span 7; }}
    .info-block.span-12 {{ grid-column: 1 / -1; }}
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
    .credential-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }}
    .log-layout {{ display: grid; grid-template-columns: 300px minmax(0, 1fr); gap: 18px; }}
    .log-item summary {{ cursor: pointer; list-style: none; }}
    .log-item summary::-webkit-details-marker {{ display: none; }}
    .log-meta {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 18px; }}
    .grid-full {{ grid-column: 1 / -1; }}
    .asset-toolbar {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; }}
    @media (max-width: 992px) {{
      .navbar-vertical {{ width: 100%; }}
      .container-xl {{ padding-left: 16px; padding-right: 16px; }}
      .credential-grid, .log-layout, .log-meta, .server-grid {{ grid-template-columns: 1fr; }}
      .server-card-body {{ grid-template-columns: 1fr; }}
      .info-block.span-3, .info-block.span-4, .info-block.span-5, .info-block.span-6, .info-block.span-7 {{ grid-column: 1 / -1; }}
      .server-card-head, .power-panel {{ align-items: flex-start; flex-direction: column; }}
      .table-responsive {{ min-height: 0; }}
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
          <div class="navbar-nav flex-row order-md-last ms-auto">{actions}</div>
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
  </script>
</body>
</html>
"""
    return html_doc.encode("utf-8")


def render_check_action() -> str:
    return """
    <div>
      <form method="post" action="/guard/run">
        <button class="btn btn-primary" type="submit" title="马上查询 CDT 流量和 ECS 状态，并按阈值执行一次保护判断">手动检查流量</button>
      </form>
    </div>
    """


def render_summary_cards(summary: dict) -> str:
    return f"""
    <div class="row row-deck row-cards mb-4">
      <div class="col-sm-6 col-xl"><div class="card stat-card"><div class="card-body"><div class="subheader">总机器</div><div class="h1 mb-0">{esc(summary.get('total', 0))}</div><div class="stat-line"><span style="width:100%"></span></div></div></div></div>
      <div class="col-sm-6 col-xl"><div class="card stat-card"><div class="card-body"><div class="subheader">启用保护</div><div class="h1 mb-0">{esc(summary.get('enabled', 0))}</div><div class="stat-line"><span style="width:70%"></span></div></div></div></div>
      <div class="col-sm-6 col-xl"><div class="card stat-card"><div class="card-body"><div class="subheader">流量预警</div><div class="h1 mb-0 text-yellow">{esc(summary.get('warnings', 0))}</div><div class="stat-line"><span style="width:28%; background:#f59f00"></span></div></div></div></div>
      <div class="col-sm-6 col-xl"><div class="card stat-card"><div class="card-body"><div class="subheader">检查错误</div><div class="h1 mb-0 text-red">{esc(summary.get('errors', 0))}</div><div class="stat-line"><span style="width:28%; background:#d63939"></span></div></div></div></div>
      <div class="col-sm-6 col-xl"><div class="card stat-card"><div class="card-body"><div class="subheader">已停止</div><div class="h1 mb-0">{esc(summary.get('stopped', 0))}</div><div class="stat-line"><span style="width:28%; background:#64748b"></span></div></div></div></div>
    </div>
    """


def render_asset_cards(instances: list[dict], metadata: dict[str, dict]) -> str:
    cards = []
    for item in instances:
        meta = metadata.get(str(item.get("id")), {})
        used_pct = item.get("used_pct")
        pct = 0 if used_pct is None else max(0, min(float(used_pct), 100))
        progress = "bg-green"
        if item.get("last_error") or item.get("action") == "stop":
            progress = "bg-red"
        elif item.get("warning") or item.get("action") == "hold":
            progress = "bg-yellow"

        public_ips = item.get("public_ips") or []
        private_ips = item.get("private_ips") or []
        primary_ip = first_value(meta.get("server_ip"), meta.get("public_ip"), public_ips[0] if public_ips else None, default="未识别")
        product_name = first_value(meta.get("product_name"), meta.get("product"), item.get("label"), default="未命名产品")
        asset_label = first_value(meta.get("label"), item.get("label"), default=item.get("instance_id"))
        provider = first_value(meta.get("provider"), default="阿里云")
        panel_username = first_value(meta.get("panel_username"), meta.get("login_username"), meta.get("username"))
        panel_password = first_value(meta.get("panel_password"), meta.get("login_password"), meta.get("password"))
        ssh_password = first_value(meta.get("ssh_password"))
        ssh_text = ""
        if meta.get("ssh_user") or meta.get("ssh_port"):
            ssh_text = f"{meta.get('ssh_user', 'root')}@{primary_ip}:{meta.get('ssh_port', 22)}"
        note_text = first_value(meta.get("notes"), meta.get("remark"), meta.get("account_note"))
        state_class, state_label, state_sub = status_view(item.get("instance_status"))
        manual_note = "手动关机保持中" if item.get("manual_stop") else ""
        cards.append(
            f"""
            <article class="card server-card">
              <div class="server-card-head">
                <div>
                  <div class="asset-name">{esc(product_name)}</div>
                  <div class="asset-sub">{esc(asset_label)}</div>
                  <div class="asset-sub">{esc(provider)} · {esc(item.get('instance_name') or '未识别 ECS 名')}</div>
                </div>
                <div class="server-state {state_class}">
                  <span class="server-state-dot"></span>
                  <div>
                    <div class="server-state-main">{esc(state_label)}</div>
                    <div class="server-state-sub">{esc(state_sub)}</div>
                  </div>
                </div>
              </div>
              <div class="server-card-body">
                <section class="info-block span-4">
                  <div class="info-label">服务器 IP</div>
                  <div class="ip-main">{esc(primary_ip)}</div>
                  {small_line("公网 ", ", ".join(public_ips))}
                  {small_line("内网 ", ", ".join(private_ips))}
                </section>
                <section class="info-block span-4">
                  <div class="info-label">阿里云信息</div>
                  <div class="info-value">{esc(item.get('region_id'))}</div>
                  <div class="text-secondary small">CDT {esc(item.get('traffic_region_id'))}</div>
                  <div class="text-secondary small">{esc(item.get('instance_id'))}</div>
                </section>
                <section class="info-block span-4">
                  <div class="info-label">当前判断</div>
                  {badge(item.get('action'))}
                  <div class="text-secondary small mt-2">{esc(item.get('reason'))}</div>
                  {f'<div class="text-danger small mt-1">{esc(manual_note)}</div>' if manual_note else ''}
                </section>
                <section class="info-block span-6">
                  <div class="traffic-row">
                    <div>
                      <div class="info-label">CDT 用量</div>
                      <div class="traffic-value">{fmt_gb(item.get('traffic_gb'))}</div>
                    </div>
                    <div class="text-secondary small">上限 {fmt_gb(item.get('stop_threshold_gb'))}</div>
                  </div>
                  <div class="progress mt-3">
                    <div class="progress-bar {progress}" style="width:{pct:.2f}%"></div>
                  </div>
                </section>
                <section class="info-block span-6">
                  <div class="info-label">保护阈值</div>
                  <div class="info-value">剩余 {fmt_gb(item.get('remaining_gb'))}</div>
                  <div class="text-secondary small">预警 {fmt_gb(item.get('warning_threshold_gb'))}</div>
                  <div class="text-secondary small">恢复启动 {fmt_gb(item.get('start_threshold_gb'))}</div>
                </section>
                <section class="info-block span-6">
                  <div class="info-label">登录信息</div>
                  <div>{link_or_text(meta.get('panel_url') or meta.get('login_url') or meta.get('website'))}</div>
                  {small_line("账号 ", panel_username)}
                  {secret_button(panel_password, "显示面板密码")}
                  {small_line("SSH ", ssh_text)}
                  {secret_button(ssh_password, "显示 SSH 密码") if ssh_password else ""}
                </section>
                <section class="info-block span-6">
                  <div class="info-label">备注</div>
                  <div class="note-cell">{esc(note_text) if note_text else '<span class="text-secondary">未填写</span>'}</div>
                </section>
                <section class="info-block span-12">
                  <div class="info-label">电源控制</div>
                  {power_controls(str(item.get('id')), item.get('instance_status'))}
                </section>
                <section class="info-block span-12">
                  <div class="asset-toolbar">
                    <div>
                      <div class="info-label">最近检查</div>
                      <div class="info-value">{esc(item.get('updated_at'))}</div>
                    </div>
                    <div class="btn-list">
                      <a class="btn btn-sm" href="/servers/edit?id={esc(item.get('id'))}">编辑</a>
                      <form method="post" action="/servers/delete" onsubmit="return confirm('确认删除这台服务器？')">
                        <input type="hidden" name="id" value="{esc(item.get('id'))}">
                        <button class="btn btn-sm btn-outline-danger" type="submit">删除</button>
                      </form>
                    </div>
                  </div>
                </section>
              </div>
            </article>
            """
        )
    return "".join(cards)


def render_assets_card(instances: list[dict], metadata: dict[str, dict]) -> str:
    cards = render_asset_cards(instances, metadata)
    return f"""
    <div class="card" id="servers">
      <div class="card-header">
        <div class="asset-toolbar w-100">
          <h3 class="card-title">服务器资产</h3>
          <div class="btn-list">
            <a href="/servers/new" class="btn btn-primary btn-sm">新增服务器</a>
            <a href="/api/status" class="btn btn-sm">状态 JSON</a>
            <a href="/api/history" class="btn btn-sm">历史 JSON</a>
          </div>
        </div>
      </div>
      <div class="server-grid">
        {cards if cards else '<div class="text-secondary">暂无服务器，请先新增。</div>'}
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
    flash = query.get("flash", [""])[0]
    body = render_summary_cards(summary) + render_assets_card(instances, metadata)
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
    body = f'<div class="row justify-content-center"><div class="col-xl-8 col-lg-10">{render_form(editing)}</div></div>'
    return page_shell(
        "servers",
        "新增/编辑服务器",
        "填写阿里云凭证、实例、阈值和资产备注",
        body,
        actions=render_check_action(),
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


def render_form(item: dict) -> str:
    is_edit = bool(item)
    title = "编辑服务器" if is_edit else "新增服务器"
    id_value = item.get("id", "")
    global_env = load_env(BASE_DIR / "guard.env")
    access_key_id = first_value(item.get("access_key_id"), global_env.get("ALIYUN_ACCESS_KEY_ID"))
    secret_hint = "编辑时留空则保留原 Secret" if is_edit else ""
    panel_password_hint = "编辑时留空则保留原密码" if is_edit else ""
    return f"""
    <form class="card" method="post" action="/servers/save">
      <div class="card-header"><h3 class="card-title">{title}</h3></div>
      <div class="card-body">
        <input type="hidden" name="original_id" value="{esc(id_value)}">
        {input_field("product_name", "产品自定义名字", item.get("product_name", ""), placeholder="例如：阿里云香港 1号机", required=True)}
        <div class="credential-grid">
          {input_field("label", "服务器别名", item.get("label", ""), placeholder="例如：HK-01")}
          {input_field("provider", "服务商", item.get("provider", "阿里云"))}
        </div>
        <div class="credential-grid">
          {input_field("server_ip", "服务器 IP", first_value(item.get("server_ip"), item.get("public_ip")), placeholder="可留空，系统会从 ECS 读取")}
          {input_field("instance_id", "ECS Instance ID", item.get("instance_id", ""), placeholder="i-xxxxxxxx", required=True)}
        </div>
        <div class="credential-grid">
          {input_field("region_id", "区域 ID", item.get("region_id", "cn-hongkong"), placeholder="cn-hongkong", required=True)}
          {input_field("traffic_region_id", "CDT 流量区域", item.get("traffic_region_id", item.get("region_id", "cn-hongkong")), placeholder="cn-hongkong")}
        </div>
        <div class="credential-grid">
          {input_field("access_key_id", "阿里云 AccessKey ID", access_key_id, required=True)}
          {input_field("access_key_secret", "阿里云 AccessKey Secret", "", "password", hint=secret_hint, required=not is_edit)}
        </div>
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
          </div>
        </div>
        <hr>
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
      </div>
      <div class="card-footer text-end">
        {f'<a href="/" class="btn me-2">取消编辑</a>' if is_edit else ""}
        <button class="btn btn-primary" type="submit">保存服务器</button>
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
        "instance_id": instance_id,
        "access_key_id": form_value(fields, "access_key_id"),
        "access_key_secret": access_secret or existing.get("access_key_secret", ""),
        "warning_threshold_gb": as_float(form_value(fields, "warning_threshold_gb"), 160),
        "stop_threshold_gb": as_float(form_value(fields, "stop_threshold_gb"), 180),
        "start_threshold_gb": as_float(form_value(fields, "start_threshold_gb"), 175),
        "panel_url": form_value(fields, "panel_url"),
        "panel_username": form_value(fields, "panel_username"),
        "panel_password": panel_password or existing.get("panel_password", ""),
        "ssh_user": form_value(fields, "ssh_user", "root"),
        "ssh_port": int(as_float(form_value(fields, "ssh_port"), 22)),
        "ssh_password": ssh_password or existing.get("ssh_password", ""),
        "notes": form_value(fields, "notes"),
        "enabled": form_value(fields, "enabled") == "1",
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
        if not self.is_authorized():
            self.send_auth_required()
            return

        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
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
        if parsed.path == "/api/status":
            self.send_json(read_json(STATUS_FILE, {"error": "status not found"}))
            return
        if parsed.path == "/api/history":
            limit = int(query.get("limit", ["200"])[0])
            self.send_json(read_history(max(1, min(limit, 1000))))
            return
        if parsed.path == "/healthz":
            self.send_json({"ok": True})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self):
        if not self.is_authorized():
            self.send_auth_required()
            return

        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
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

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def is_authorized(self) -> bool:
        env = load_env(WEB_ENV_FILE)
        username = env.get("WEB_USERNAME", "admin")
        password = env.get("WEB_PASSWORD", "")
        if not password:
            return False

        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        except Exception:
            return False
        supplied_user, _, supplied_password = decoded.partition(":")
        return supplied_user == username and supplied_password == password

    def send_auth_required(self):
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="Aliyun CDT Guard"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("Authentication required\n".encode("utf-8"))

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

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


def render_dashboard(query: dict[str, list[str]] | None = None) -> bytes:
    query = query or {}
    status = read_json(STATUS_FILE, {"summary": {}, "instances": [], "generated_at": "暂无"})
    config = read_config()
    history = read_history(80)
    summary = status.get("summary", {})
    instances = status.get("instances", [])
    metadata = config_by_id(config)
    edit_id = query.get("edit", [""])[0]
    editing = selected_instance(config, edit_id)
    flash = query.get("flash", [""])[0]

    rows = []
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
        rows.append(
            f"""
            <tr>
              <td>
                <div class="fw-bold">{esc(product_name)}</div>
                <div class="text-secondary small">{esc(asset_label)}</div>
                <div class="text-secondary small">{esc(provider)} · {esc(item.get('instance_name') or '未识别 ECS 名')}</div>
              </td>
              <td>
                <div class="font-monospace">{esc(primary_ip)}</div>
                {small_line("公网 ", ", ".join(public_ips))}
                {small_line("内网 ", ", ".join(private_ips))}
              </td>
              <td>
                <div>{esc(item.get('region_id'))}</div>
                <div class="text-secondary small">{esc(item.get('traffic_region_id'))}</div>
                <div class="text-secondary small">{esc(item.get('instance_id'))}</div>
              </td>
              <td>{badge(item.get('action'))}<div class="mt-1">{esc(item.get('instance_status'))}</div></td>
              <td>
                <div class="progress progress-sm">
                  <div class="progress-bar {progress}" style="width:{pct:.2f}%"></div>
                </div>
                <div class="text-secondary small mt-1">{fmt_gb(item.get('traffic_gb'))} / {fmt_gb(item.get('stop_threshold_gb'))}</div>
              </td>
              <td>
                <div>{fmt_gb(item.get('remaining_gb'))}</div>
                <div class="text-secondary small">预警 {fmt_gb(item.get('warning_threshold_gb'))}</div>
                <div class="text-secondary small">启动 {fmt_gb(item.get('start_threshold_gb'))}</div>
              </td>
              <td>
                <div>{link_or_text(meta.get('panel_url') or meta.get('login_url') or meta.get('website'))}</div>
                {small_line("账号 ", panel_username)}
                {secret_button(panel_password, "显示面板密码")}
                {small_line("SSH ", ssh_text)}
                {secret_button(ssh_password, "显示 SSH 密码") if ssh_password else ""}
              </td>
              <td class="note-cell">{esc(note_text) if note_text else '<span class="text-secondary">未填写</span>'}</td>
              <td>
                <div>{esc(item.get('reason'))}</div>
                <div class="text-secondary small">{esc(item.get('updated_at'))}</div>
                <div class="btn-list mt-2">
                  <a class="btn btn-sm" href="/?edit={esc(item.get('id'))}">编辑</a>
                  <form method="post" action="/servers/delete" onsubmit="return confirm('确认删除这台服务器？')">
                    <input type="hidden" name="id" value="{esc(item.get('id'))}">
                    <button class="btn btn-sm btn-outline-danger" type="submit">删除</button>
                  </form>
                </div>
              </td>
            </tr>
            """
        )

    form = render_form(editing)
    events = []
    for event in reversed(history):
        level = "text-red" if event.get("error") else "text-secondary"
        events.append(
            f"""
            <div class="list-group-item">
              <div class="row align-items-center">
                <div class="col-auto"><span class="status-dot status-dot-animated {'bg-red' if event.get('error') else 'bg-green'} d-block"></span></div>
                <div class="col text-truncate">
                  <div class="text-body d-block">{esc(event.get('label'))} · {esc(event.get('action'))}</div>
                  <div class="{level} text-truncate mt-n1">{esc(event.get('reason'))} · {fmt_gb(event.get('traffic_gb'))} · {esc(event.get('status'))}</div>
                </div>
                <div class="col-auto text-secondary small">{esc(event.get('at'))}</div>
              </div>
            </div>
            """
        )

    flash_html = f'<div class="alert alert-success">{esc(flash)}</div>' if flash else ""
    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="60">
  <title>Aliyun CDT Guard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0-beta20/dist/css/tabler.min.css">
  <style>
    body {{ background: #f4f6fa; }}
    .navbar-brand {{ letter-spacing: 0; }}
    .page-wrapper {{ min-height: 100vh; }}
    .table td {{ vertical-align: middle; }}
    .note-cell {{ min-width: 220px; white-space: pre-wrap; }}
    .btn-list form {{ display: inline-block; margin: 0; }}
    .form-hint {{ margin-top: 4px; }}
    .credential-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
    @media (max-width: 992px) {{
      .credential-grid {{ grid-template-columns: 1fr; }}
      .table-responsive {{ min-height: 0; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <aside class="navbar navbar-vertical navbar-expand-lg" data-bs-theme="dark">
      <div class="container-fluid">
        <h1 class="navbar-brand navbar-brand-autodark">Aliyun CDT Guard</h1>
        <div class="navbar-nav flex-row d-lg-none"></div>
        <div class="collapse navbar-collapse show">
          <ul class="navbar-nav pt-lg-3">
            <li class="nav-item active"><a class="nav-link" href="/"><span class="nav-link-title">总览</span></a></li>
            <li class="nav-item"><a class="nav-link" href="#servers"><span class="nav-link-title">服务器资产</span></a></li>
            <li class="nav-item"><a class="nav-link" href="#add"><span class="nav-link-title">新增/编辑</span></a></li>
            <li class="nav-item"><a class="nav-link" href="#history"><span class="nav-link-title">历史记录</span></a></li>
          </ul>
        </div>
      </div>
    </aside>
    <div class="page-wrapper">
      <header class="navbar navbar-expand-md d-print-none">
        <div class="container-xl">
          <div>
            <h2 class="page-title">CDT 流量保护与服务器资产面板</h2>
            <div class="text-secondary small">状态更新时间：{esc(status.get('generated_at'))}</div>
          </div>
          <div class="navbar-nav flex-row order-md-last ms-auto">
            <form method="post" action="/guard/run">
              <button class="btn btn-primary" type="submit">立即巡检</button>
            </form>
          </div>
        </div>
      </header>
      <div class="page-body">
        <div class="container-xl">
          {flash_html}
          <div class="row row-deck row-cards mb-3">
            <div class="col-sm-6 col-lg"><div class="card"><div class="card-body"><div class="subheader">总机器</div><div class="h1 mb-0">{esc(summary.get('total', 0))}</div></div></div></div>
            <div class="col-sm-6 col-lg"><div class="card"><div class="card-body"><div class="subheader">启用</div><div class="h1 mb-0">{esc(summary.get('enabled', 0))}</div></div></div></div>
            <div class="col-sm-6 col-lg"><div class="card"><div class="card-body"><div class="subheader">预警</div><div class="h1 mb-0 text-yellow">{esc(summary.get('warnings', 0))}</div></div></div></div>
            <div class="col-sm-6 col-lg"><div class="card"><div class="card-body"><div class="subheader">错误</div><div class="h1 mb-0 text-red">{esc(summary.get('errors', 0))}</div></div></div></div>
            <div class="col-sm-6 col-lg"><div class="card"><div class="card-body"><div class="subheader">已停止</div><div class="h1 mb-0">{esc(summary.get('stopped', 0))}</div></div></div></div>
          </div>
          <div class="card mb-3" id="servers">
            <div class="card-header"><h3 class="card-title">服务器资产</h3><div class="card-actions"><a href="/api/status" class="btn btn-sm">状态 JSON</a><a href="/api/history" class="btn btn-sm">历史 JSON</a></div></div>
            <div class="table-responsive">
              <table class="table table-vcenter card-table">
                <thead>
                  <tr>
                    <th>产品/机器</th><th>服务器 IP</th><th>阿里云信息</th><th>状态</th><th>CDT 用量</th><th>额度</th><th>登录信息</th><th>备注</th><th>操作</th>
                  </tr>
                </thead>
                <tbody>{''.join(rows) if rows else '<tr><td colspan="9" class="text-secondary">暂无服务器，请先在下面添加。</td></tr>'}</tbody>
              </table>
            </div>
          </div>
          <div class="row row-cards">
            <div class="col-lg-5" id="add">{form}</div>
            <div class="col-lg-7" id="history">
              <div class="card">
                <div class="card-header"><h3 class="card-title">最近记录</h3></div>
                <div class="list-group list-group-flush">{''.join(events) if events else '<div class="list-group-item text-secondary">暂无记录</div>'}</div>
              </div>
            </div>
          </div>
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
            self.redirect("/?flash=服务器已保存并完成一次巡检")
            return
        if parsed.path == "/servers/delete":
            delete_server(form_value(fields, "id"))
            run_guard_now()
            self.redirect("/?flash=服务器已删除")
            return
        if parsed.path == "/guard/run":
            run_guard_now()
            self.redirect("/?flash=已完成一次手动巡检")
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

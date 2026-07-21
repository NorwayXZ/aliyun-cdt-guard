#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import fcntl
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkecs.request.v20140526 import (
    DescribeInstancesRequest,
    StartInstancesRequest,
    StopInstancesRequest,
)

import notifications

BASE_DIR = Path("/opt/aliyun-cdt-guard")
ENV_FILE = BASE_DIR / "guard.env"
CONFIG_FILE = BASE_DIR / "instances.json"
STATUS_FILE = BASE_DIR / "status.json"
HISTORY_FILE = BASE_DIR / "history.jsonl"
LOCK_FILE = BASE_DIR / "guard.lock"
MAX_HISTORY_DAYS = int(os.environ.get("CDT_GUARD_HISTORY_DAYS", "31"))
MAX_HISTORY_LINES = int(os.environ.get("CDT_GUARD_MAX_HISTORY_LINES", "200000"))
TRAFFIC_SCOPE_REGION = "region"
TRAFFIC_SCOPE_ACCOUNT_NON_CHINA = "account_non_china"
TRAFFIC_SCOPE_ACCOUNT_ALL = "account_all"
TRAFFIC_SCOPES = {
    TRAFFIC_SCOPE_REGION,
    TRAFFIC_SCOPE_ACCOUNT_NON_CHINA,
    TRAFFIC_SCOPE_ACCOUNT_ALL,
}
BILLING_TIMEZONE = timezone(timedelta(hours=8))
BSS_ENDPOINTS = [
    ("cn-hongkong", "business.aliyuncs.com"),
    ("cn-hangzhou", "business.aliyuncs.com"),
    ("ap-southeast-1", "business.ap-southeast-1.aliyuncs.com"),
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)
logging.getLogger("aliyunsdkcore").setLevel(logging.CRITICAL)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def month_days(year: int, month: int) -> int:
    if month == 12:
        next_month = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        next_month = datetime(year, month + 1, 1, tzinfo=timezone.utc)
    this_month = datetime(year, month, 1, tzinfo=timezone.utc)
    return (next_month - this_month).days


def add_month(year: int, month: int) -> tuple[int, int]:
    if month == 12:
        return year + 1, 1
    return year, month + 1


def normalize_reset_day(value: Any) -> int:
    try:
        day = int(value)
    except (TypeError, ValueError):
        day = 1
    return max(1, min(day, 28))


def next_reset_at(reset_day: int, now: datetime | None = None) -> datetime:
    now = now or utc_now()
    reset_day = normalize_reset_day(reset_day)
    day = min(reset_day, month_days(now.year, now.month))
    candidate = datetime(now.year, now.month, day, tzinfo=timezone.utc)
    if now >= candidate:
        year, month = add_month(now.year, now.month)
        day = min(reset_day, month_days(year, month))
        candidate = datetime(year, month, day, tzinfo=timezone.utc)
    return candidate


def billing_cycle_now(now: datetime | None = None) -> str:
    return (now or utc_now()).astimezone(BILLING_TIMEZONE).strftime("%Y-%m")


def next_billing_cycle_start(billing_cycle: str) -> datetime:
    year_text, _, month_text = str(billing_cycle).partition("-")
    year = int(year_text)
    month = int(month_text)
    next_year, next_month = add_month(year, month)
    return datetime(next_year, next_month, 1, tzinfo=BILLING_TIMEZONE)


def query_billing_cycle_info(item: dict[str, Any]) -> dict[str, Any]:
    billing_cycle = billing_cycle_now()
    last_error = ""
    for region_id, domain in BSS_ENDPOINTS:
        try:
            client = AcsClient(item["access_key_id"], item["access_key_secret"], region_id)
            request = CommonRequest()
            request.set_domain(domain)
            request.set_version("2017-12-14")
            request.set_action_name("QueryBillOverview")
            request.set_method("POST")
            request.set_accept_format("json")
            request.add_query_param("BillingCycle", billing_cycle)
            request.add_query_param("ProductCode", "cdt")
            response = client.do_action_with_exception(request)
            response_json = json.loads(response.decode("utf-8"))
            rows = ((response_json.get("Data") or {}).get("Items") or {}).get("Item") or []
            first_row = rows[0] if rows else {}
            reset_at = next_billing_cycle_start(billing_cycle)
            return {
                "source": "bss",
                "source_label": "BSS 账单 API",
                "billing_cycle": billing_cycle,
                "billing_product_code": first_row.get("ProductCode") or "cdt",
                "billing_product_name": first_row.get("ProductName") or "云数据传输",
                "billing_endpoint": domain,
                "billing_region_id": region_id,
                "billing_request_id": response_json.get("RequestId"),
                "billing_row_count": len(rows),
                "next_reset_at": reset_at.isoformat(timespec="seconds"),
            }
        except Exception as exc:
            last_error = str(exc)[:500]
    return {
        "source": "config",
        "source_label": "配置推算",
        "billing_cycle": billing_cycle,
        "billing_error": last_error,
    }


def recovery_plan(
    item: dict[str, Any],
    traffic_gb: float | None,
    ecs_status: str | None,
    action: str | None,
    billing_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reset_day = normalize_reset_day(item.get("traffic_reset_day", 1))
    billing_info = billing_info or {}
    if billing_info.get("source") == "bss" and billing_info.get("next_reset_at"):
        reset_at = datetime.fromisoformat(str(billing_info["next_reset_at"]))
        reset_source = "bss"
        reset_source_label = "BSS 账单 API"
    else:
        reset_at = next_reset_at(reset_day)
        reset_source = "config"
        reset_source_label = "配置推算"
    seconds = max(0, int((reset_at - utc_now()).total_seconds()))
    days = (seconds + 86399) // 86400
    auto_start_paused = bool(item.get("manual_stop"))
    over_stop = traffic_gb is not None and traffic_gb >= float(item.get("stop_threshold_gb", 0))
    stopped_by_threshold = action in {"stop", "keep_stopped"} or (ecs_status == "Stopped" and over_stop)
    will_auto_start = stopped_by_threshold and not auto_start_paused
    if auto_start_paused:
        note = "手动关机保持中，月初重置后也不会自动开机，需手动开机恢复自动保护。"
    elif stopped_by_threshold:
        note = "预计 CDT 月度流量重置后，下一次巡检会低于恢复阈值并自动开机。"
    else:
        note = "当前未因流量阈值停机；这里显示下一次 CDT 账期重置时间。"
    return {
        "traffic_reset_day": reset_day,
        "next_reset_at": reset_at.isoformat(timespec="seconds"),
        "days_until_reset": days,
        "seconds_until_reset": seconds,
        "reset_source": reset_source,
        "reset_source_label": reset_source_label,
        "billing_cycle": billing_info.get("billing_cycle"),
        "billing_product_code": billing_info.get("billing_product_code"),
        "billing_product_name": billing_info.get("billing_product_name"),
        "billing_endpoint": billing_info.get("billing_endpoint"),
        "billing_region_id": billing_info.get("billing_region_id"),
        "billing_request_id": billing_info.get("billing_request_id"),
        "billing_error": billing_info.get("billing_error"),
        "stopped_by_threshold": stopped_by_threshold,
        "will_auto_start_after_reset": will_auto_start,
        "auto_start_paused": auto_start_paused,
        "recovery_note": note,
    }


def load_env(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"missing config file: {path}")

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required config: {name}")
    return value


def load_config() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        legacy_instance_id = require_env("ECS_INSTANCE_ID")
        legacy_region_id = os.environ.get("ALIYUN_REGION_ID", "cn-hongkong")
        legacy_traffic_region = os.environ.get("TRAFFIC_REGION_ID", legacy_region_id)
        legacy_stop = float(os.environ.get("TRAFFIC_THRESHOLD_GB", "180"))
        config = {
            "version": 1,
            "defaults": {
                "enabled": True,
                "warning_threshold_gb": max(legacy_stop - 20, 0),
                "stop_threshold_gb": legacy_stop,
                "start_threshold_gb": max(legacy_stop - 5, 0),
                "traffic_region_id": legacy_traffic_region,
                "traffic_scope": TRAFFIC_SCOPE_REGION,
                "traffic_reset_day": 1,
            },
            "instances": [
                {
                    "id": "hk-launch-advisor",
                    "label": "香港 launch-advisor",
                    "region_id": legacy_region_id,
                    "traffic_region_id": legacy_traffic_region,
                    "traffic_scope": TRAFFIC_SCOPE_REGION,
                    "instance_id": legacy_instance_id,
                    "enabled": True,
                }
            ],
        }
        atomic_write_json(CONFIG_FILE, config, mode=0o600)
        return config

    return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))


def atomic_write_json(path: Path, data: dict[str, Any], mode: int = 0o600) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(tmp_path, mode)
    tmp_path.replace(path)


def append_history(event: dict[str, Any]) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


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


def prune_history() -> None:
    try:
        lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return

    cutoff = utc_now() - timedelta(days=MAX_HISTORY_DAYS)
    kept: list[str] = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        event_time = parse_event_time(event.get("at"))
        if event_time is None or event_time >= cutoff:
            kept.append(line)

    if len(kept) > MAX_HISTORY_LINES:
        kept = kept[-MAX_HISTORY_LINES:]
    if len(kept) != len(lines):
        HISTORY_FILE.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        os.chmod(HISTORY_FILE, 0o600)


def get_client(region_id: str, access_key_id: str | None = None, access_key_secret: str | None = None) -> AcsClient:
    return AcsClient(
        access_key_id or require_env("ALIYUN_ACCESS_KEY_ID"),
        access_key_secret or require_env("ALIYUN_ACCESS_KEY_SECRET"),
        region_id,
    )


def bytes_to_gb(value: int | str | None) -> float:
    return int(value or 0) / (1024 ** 3)


def normalize_traffic_scope(value: str | None) -> str:
    value = (value or TRAFFIC_SCOPE_REGION).strip()
    return value if value in TRAFFIC_SCOPES else TRAFFIC_SCOPE_REGION


def traffic_scope_label(scope: str) -> str:
    labels = {
        TRAFFIC_SCOPE_REGION: "按当前 CDT 区域统计",
        TRAFFIC_SCOPE_ACCOUNT_NON_CHINA: "账号非中国内地共享池",
        TRAFFIC_SCOPE_ACCOUNT_ALL: "账号全部 CDT 流量",
    }
    return labels.get(scope, labels[TRAFFIC_SCOPE_REGION])


def is_china_mainland_region(region_id: str | None) -> bool:
    region_id = str(region_id or "").strip().lower()
    return region_id.startswith("cn-") and region_id != "cn-hongkong"


def credential_fingerprint(access_key_id: str | None) -> str:
    digest = hashlib.sha1(str(access_key_id or "").encode("utf-8")).hexdigest()
    return digest[:10]


def default_traffic_pool_id(scope: str, traffic_region_id: str | None) -> str:
    if scope == TRAFFIC_SCOPE_ACCOUNT_NON_CHINA:
        return "cdt-account-non-china"
    if scope == TRAFFIC_SCOPE_ACCOUNT_ALL:
        return "cdt-account-all"
    return f"cdt-region-{traffic_region_id or 'all'}"


def traffic_pool_id(item: dict[str, Any]) -> str:
    scope = normalize_traffic_scope(item.get("traffic_scope"))
    return str(item.get("traffic_pool_id") or default_traffic_pool_id(scope, item.get("traffic_region_id")))


def has_custom_traffic_pool_id(item: dict[str, Any]) -> bool:
    return bool(str(item.get("traffic_pool_id") or "").strip())


def traffic_pool_key(item: dict[str, Any]) -> str:
    scope = normalize_traffic_scope(item.get("traffic_scope"))
    pool_id = traffic_pool_id(item)
    is_custom = item.get("traffic_pool_custom", has_custom_traffic_pool_id(item))
    if is_custom:
        return f"custom:{scope}:{pool_id}"
    return f"{credential_fingerprint(item.get('access_key_id'))}:{scope}:{pool_id}"


def traffic_cache_key(item: dict[str, Any]) -> tuple[str, str, str | None]:
    scope = normalize_traffic_scope(item.get("traffic_scope"))
    traffic_region_id = item.get("traffic_region_id") if scope == TRAFFIC_SCOPE_REGION else None
    credential_key = traffic_pool_key(item) if item.get("traffic_pool_custom") else credential_fingerprint(item.get("access_key_id"))
    return (credential_key, scope, traffic_region_id)


def traffic_pool_label(item: dict[str, Any]) -> str:
    return f"{traffic_scope_label(normalize_traffic_scope(item.get('traffic_scope')))} / {traffic_pool_id(item)}"


def include_traffic_detail(detail: dict[str, Any], scope: str, traffic_region_id: str | None) -> bool:
    business_region = detail.get("BusinessRegionId")
    if scope == TRAFFIC_SCOPE_ACCOUNT_ALL:
        return True
    if scope == TRAFFIC_SCOPE_ACCOUNT_NON_CHINA:
        return not is_china_mainland_region(business_region)
    if traffic_region_id:
        return business_region == traffic_region_id
    return True


def get_traffic_report(
    client: AcsClient,
    traffic_region_id: str | None = None,
    traffic_scope: str = TRAFFIC_SCOPE_REGION,
) -> dict[str, Any]:
    traffic_scope = normalize_traffic_scope(traffic_scope)
    request = CommonRequest()
    request.set_domain("cdt.aliyuncs.com")
    request.set_version("2021-08-13")
    request.set_action_name("ListCdtInternetTraffic")
    request.set_method("POST")
    request.set_accept_format("json")

    response = client.do_action_with_exception(request)
    response_json = json.loads(response.decode("utf-8"))
    all_details = response_json.get("TrafficDetails", [])
    traffic_details = [
        item for item in all_details
        if include_traffic_detail(item, traffic_scope, traffic_region_id)
    ]

    total_bytes = sum(int(item.get("Traffic", 0) or 0) for item in traffic_details)
    products: dict[str, int] = {}
    regions = []

    for detail in traffic_details:
        product_details = detail.get("ProductTrafficDetails") or []
        for product_detail in product_details:
            product = str(product_detail.get("Product") or "unknown")
            products[product] = products.get(product, 0) + int(product_detail.get("Traffic", 0) or 0)
        regions.append(
            {
                "region_id": detail.get("BusinessRegionId"),
                "isp_type": detail.get("ISPType"),
                "traffic_bytes": int(detail.get("Traffic", 0) or 0),
                "traffic_gb": bytes_to_gb(detail.get("Traffic")),
            }
        )

    product_rows = [
        {
            "product": product,
            "traffic_bytes": traffic_bytes,
            "traffic_gb": bytes_to_gb(traffic_bytes),
        }
        for product, traffic_bytes in sorted(products.items())
    ]

    return {
        "request_id": response_json.get("RequestId"),
        "traffic_scope": traffic_scope,
        "traffic_scope_label": traffic_scope_label(traffic_scope),
        "traffic_bytes": total_bytes,
        "traffic_gb": bytes_to_gb(total_bytes),
        "detail_count": len(all_details),
        "matched_detail_count": len(traffic_details),
        "products": product_rows,
        "regions": regions,
    }


def get_total_traffic_gb(client: AcsClient, traffic_region_id: str | None = None) -> float:
    return get_traffic_report(client, traffic_region_id)["traffic_gb"]


def describe_instance(client: AcsClient, instance_id: str) -> dict[str, Any] | None:
    request = DescribeInstancesRequest.DescribeInstancesRequest()
    request.set_accept_format("json")
    request.set_InstanceIds([instance_id])

    response = client.do_action_with_exception(request)
    response_json = json.loads(response.decode("utf-8"))
    instances = response_json.get("Instances", {}).get("Instance", [])
    return instances[0] if instances else None


def list_values(container: dict[str, Any] | None, key: str = "IpAddress") -> list[str]:
    if not container:
        return []
    values = container.get(key, [])
    return [str(value) for value in values if value]


def instance_public_ips(instance: dict[str, Any] | None) -> list[str]:
    if not instance:
        return []
    ips = []
    ips.extend(list_values(instance.get("PublicIpAddress")))
    eip = instance.get("EipAddress") or {}
    if eip.get("IpAddress"):
        ips.append(str(eip["IpAddress"]))
    return sorted(set(ips))


def instance_private_ips(instance: dict[str, Any] | None) -> list[str]:
    if not instance:
        return []
    ips = []
    ips.extend(list_values(instance.get("InnerIpAddress")))
    vpc = instance.get("VpcAttributes") or {}
    ips.extend(list_values(vpc.get("PrivateIpAddress")))
    return sorted(set(ips))


def ecs_start(client: AcsClient, instance_id: str) -> str:
    request = StartInstancesRequest.StartInstancesRequest()
    request.set_accept_format("json")
    request.set_InstanceIds([instance_id])
    response = client.do_action_with_exception(request)
    return response.decode("utf-8")


def ecs_stop(client: AcsClient, instance_id: str) -> str:
    request = StopInstancesRequest.StopInstancesRequest()
    request.set_accept_format("json")
    request.set_InstanceIds([instance_id])
    request.set_ForceStop(False)
    response = client.do_action_with_exception(request)
    return response.decode("utf-8")


def merged_instance(raw: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    item = dict(defaults)
    item.update(raw)
    item["warning_threshold_gb"] = float(item.get("warning_threshold_gb", 160))
    item["stop_threshold_gb"] = float(item.get("stop_threshold_gb", 180))
    item["start_threshold_gb"] = float(item.get("start_threshold_gb", item["stop_threshold_gb"] - 5))
    item["traffic_reset_day"] = normalize_reset_day(item.get("traffic_reset_day", 1))
    item["enabled"] = bool(item.get("enabled", True))
    item["manual_stop"] = bool(item.get("manual_stop", False))
    item["region_id"] = item.get("region_id") or require_env("ALIYUN_REGION_ID")
    item["traffic_region_id"] = item.get("traffic_region_id") or item["region_id"]
    item["traffic_scope"] = normalize_traffic_scope(item.get("traffic_scope"))
    item["traffic_pool_custom"] = has_custom_traffic_pool_id(item)
    item["traffic_pool_id"] = traffic_pool_id(item)
    item["label"] = item.get("label") or item.get("id") or item["instance_id"]
    item["id"] = item.get("id") or item["instance_id"]
    item["access_key_id"] = item.get("access_key_id") or os.environ.get("ALIYUN_ACCESS_KEY_ID", "")
    item["access_key_secret"] = item.get("access_key_secret") or os.environ.get("ALIYUN_ACCESS_KEY_SECRET", "")
    item["traffic_pool_key"] = traffic_pool_key(item)
    item["traffic_pool_label"] = traffic_pool_label(item)
    return item


def decide_action(item: dict[str, Any], traffic_gb: float, ecs_status: str | None) -> tuple[str, str]:
    if not item["enabled"]:
        return "disabled", "配置已禁用，跳过"
    if ecs_status is None:
        return "error", "查不到实例"
    if item.get("manual_stop"):
        if ecs_status in {"Stopped", "Stopping"}:
            return "manual_stopped", "手动关机保持中，自动启动已暂停"
        return "stop", "手动关机保持中，执行停止"

    stop_threshold = item["stop_threshold_gb"]
    start_threshold = item["start_threshold_gb"]

    if traffic_gb >= stop_threshold:
        if ecs_status in {"Stopped", "Stopping"}:
            return "keep_stopped", "已超过停机阈值，实例已停止或正在停止"
        return "stop", "超过停机阈值，执行停止"

    if traffic_gb <= start_threshold:
        if ecs_status == "Stopped":
            return "start", "低于启动阈值，执行启动"
        return "keep_running", "低于启动阈值，保持运行"

    return "hold", "处于回差区间，保持当前状态"


def run_guard() -> dict[str, Any]:
    load_env(ENV_FILE)
    config = load_config()
    defaults = config.get("defaults", {})
    raw_instances = config.get("instances", [])
    if not raw_instances:
        raise RuntimeError("instances.json has no instances")
    merged_instances = [merged_instance(raw, defaults) for raw in raw_instances]
    pool_member_counts: dict[str, int] = {}
    for item in merged_instances:
        if item.get("enabled"):
            pool_key = item["traffic_pool_key"]
            pool_member_counts[pool_key] = pool_member_counts.get(pool_key, 0) + 1

    previous_status = read_status() or {}
    previous_by_id = {
        str(item.get("id")): item
        for item in previous_status.get("instances", [])
    }
    previous_by_pool = {
        str(item.get("traffic_pool_key")): item
        for item in previous_status.get("instances", [])
        if item.get("traffic_pool_key") and item.get("traffic_gb") is not None
    }
    client_cache: dict[str, AcsClient] = {}
    traffic_cache: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    billing_cache: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []

    with LOCK_FILE.open("w") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logger.info("another guard run is still active; skipping")
            return read_status() or {"generated_at": iso_now(), "skipped": True, "instances": []}

        for item in merged_instances:
            region_id = item["region_id"]
            traffic_region_id = item["traffic_region_id"]
            traffic_scope = item["traffic_scope"]
            pool_key = item["traffic_pool_key"]
            key = traffic_cache_key(item)
            result = {
                "id": item["id"],
                "label": item["label"],
                "enabled": item["enabled"],
                "manual_stop": item["manual_stop"],
                "region_id": region_id,
                "traffic_region_id": traffic_region_id,
                "traffic_scope": traffic_scope,
                "traffic_scope_label": traffic_scope_label(traffic_scope),
                "traffic_pool_id": item["traffic_pool_id"],
                "traffic_pool_key": pool_key,
                "traffic_pool_label": item["traffic_pool_label"],
                "traffic_pool_member_count": pool_member_counts.get(pool_key, 0),
                "instance_id": item["instance_id"],
                "warning_threshold_gb": item["warning_threshold_gb"],
                "start_threshold_gb": item["start_threshold_gb"],
                "stop_threshold_gb": item["stop_threshold_gb"],
                "traffic_reset_day": item["traffic_reset_day"],
                "updated_at": iso_now(),
                "last_error": None,
            }

            try:
                if not item["enabled"]:
                    result.update(
                        {
                            "traffic_gb": None,
                            "remaining_gb": None,
                            "used_pct": None,
                            "warning": False,
                            "instance_name": None,
                            "instance_status": "Disabled",
                            "public_ips": [],
                            "private_ips": [],
                            "action": "disabled",
                            "reason": "配置已禁用，跳过",
                            "api_response": None,
                            "recovery_plan": recovery_plan(item, None, "Disabled", "disabled"),
                        }
                    )
                    logger.info("%s disabled; skipping API calls", item["id"])
                    results.append(result)
                    events.append(
                        {
                            "at": result["updated_at"],
                            "id": result["id"],
                            "label": result["label"],
                            "traffic_gb": None,
                            "traffic_scope": result.get("traffic_scope"),
                            "traffic_pool_id": result.get("traffic_pool_id"),
                            "traffic_pool_key": result.get("traffic_pool_key"),
                            "traffic_pool_label": result.get("traffic_pool_label"),
                            "status": result.get("instance_status"),
                            "action": result.get("action"),
                            "reason": result.get("reason"),
                            "error": None,
                        }
                    )
                    continue

                client = client_cache.setdefault(
                    f"{region_id}:{item['access_key_id']}",
                    get_client(region_id, item["access_key_id"], item["access_key_secret"]),
                )
                if key not in traffic_cache:
                    traffic_cache[key] = get_traffic_report(client, traffic_region_id, traffic_scope)
                traffic_report = traffic_cache[key]
                billing_key = credential_fingerprint(item.get("access_key_id"))
                if billing_key not in billing_cache:
                    billing_cache[billing_key] = query_billing_cycle_info(item)
                billing_info = billing_cache[billing_key]
                traffic_gb = float(traffic_report["traffic_gb"])
                previous_traffic = previous_by_pool.get(pool_key, previous_by_id.get(str(item["id"]), {})).get("traffic_gb")
                traffic_delta_gb = None
                if previous_traffic is not None:
                    traffic_delta_gb = traffic_gb - float(previous_traffic)

                instance = describe_instance(client, item["instance_id"])
                ecs_status = instance.get("Status") if instance else None
                public_ips = instance_public_ips(instance)
                private_ips = instance_private_ips(instance)
                action, reason = decide_action(item, traffic_gb, ecs_status)
                api_response = None

                if action == "stop":
                    api_response = ecs_stop(client, item["instance_id"])
                elif action == "start":
                    api_response = ecs_start(client, item["instance_id"])

                warning = traffic_gb >= item["warning_threshold_gb"]
                remaining_gb = max(item["stop_threshold_gb"] - traffic_gb, 0)
                used_pct = (traffic_gb / item["stop_threshold_gb"] * 100) if item["stop_threshold_gb"] else 0

                result.update(
                    {
                        "traffic_gb": traffic_gb,
                        "traffic_delta_gb": traffic_delta_gb,
                        "traffic_request_id": traffic_report.get("request_id"),
                        "traffic_scope": traffic_report.get("traffic_scope", traffic_scope),
                        "traffic_scope_label": traffic_report.get("traffic_scope_label", traffic_scope_label(traffic_scope)),
                        "traffic_detail_count": traffic_report.get("detail_count"),
                        "traffic_matched_detail_count": traffic_report.get("matched_detail_count"),
                        "traffic_products": traffic_report.get("products", []),
                        "traffic_regions": traffic_report.get("regions", []),
                        "remaining_gb": remaining_gb,
                        "used_pct": used_pct,
                        "warning": warning,
                        "instance_name": instance.get("InstanceName") if instance else None,
                        "instance_status": ecs_status,
                        "public_ips": public_ips,
                        "private_ips": private_ips,
                        "action": action,
                        "reason": reason,
                        "api_response": api_response,
                        "billing_cycle_source": billing_info.get("source"),
                        "billing_cycle_source_label": billing_info.get("source_label"),
                        "billing_cycle": billing_info.get("billing_cycle"),
                        "billing_product_code": billing_info.get("billing_product_code"),
                        "billing_product_name": billing_info.get("billing_product_name"),
                        "billing_endpoint": billing_info.get("billing_endpoint"),
                        "billing_region_id": billing_info.get("billing_region_id"),
                        "billing_request_id": billing_info.get("billing_request_id"),
                        "billing_error": billing_info.get("billing_error"),
                        "recovery_plan": recovery_plan(item, traffic_gb, ecs_status, action, billing_info),
                    }
                )
                logger.info("%s %s traffic=%.4fGB status=%s action=%s", item["id"], item["traffic_pool_label"], traffic_gb, ecs_status, action)
            except Exception as exc:
                result.update(
                    {
                        "traffic_gb": None,
                        "remaining_gb": None,
                        "used_pct": None,
                        "warning": False,
                        "instance_name": None,
                        "instance_status": None,
                        "action": "error",
                        "reason": "执行失败",
                        "last_error": str(exc),
                        "recovery_plan": recovery_plan(item, None, None, "error"),
                    }
                )
                logger.exception("guard failed for %s: %s", item["id"], exc)

            results.append(result)
            events.append(
                {
                    "at": result["updated_at"],
                    "id": result["id"],
                    "label": result["label"],
                    "traffic_gb": result.get("traffic_gb"),
                    "traffic_delta_gb": result.get("traffic_delta_gb"),
                    "traffic_scope": result.get("traffic_scope"),
                    "traffic_pool_id": result.get("traffic_pool_id"),
                    "traffic_pool_key": result.get("traffic_pool_key"),
                    "traffic_pool_label": result.get("traffic_pool_label"),
                    "traffic_products": result.get("traffic_products"),
                    "status": result.get("instance_status"),
                    "action": result.get("action"),
                    "reason": result.get("reason"),
                    "error": result.get("last_error"),
                }
            )

    status = {
        "generated_at": iso_now(),
        "version": config.get("version", 1),
        "summary": summarize(results),
        "instances": results,
    }
    atomic_write_json(STATUS_FILE, status)
    for event in events:
        append_history(event)
    prune_history()
    try:
        sent_notifications = notifications.handle_guard_notifications(status, previous_status)
        for item in sent_notifications:
            logger.info("notification sent: %s %s", item.get("id"), item.get("title"))
    except Exception as exc:
        logger.exception("notification handling failed: %s", exc)
    return status


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    enabled = [item for item in results if item.get("enabled")]
    errors = [item for item in results if item.get("last_error")]
    warnings = [item for item in results if item.get("warning")]
    stopped = [item for item in results if item.get("instance_status") == "Stopped"]
    actions = [item for item in results if item.get("action") in {"start", "stop"}]
    pools = {
        str(item.get("traffic_pool_key"))
        for item in enabled
        if item.get("traffic_pool_key")
    }
    return {
        "total": len(results),
        "enabled": len(enabled),
        "pools": len(pools),
        "warnings": len(warnings),
        "errors": len(errors),
        "stopped": len(stopped),
        "actions": len(actions),
    }


def read_status() -> dict[str, Any] | None:
    if not STATUS_FILE.exists():
        return None
    return json.loads(STATUS_FILE.read_text(encoding="utf-8"))


def find_raw_instance(config: dict[str, Any], server_id: str) -> dict[str, Any] | None:
    for raw in config.get("instances", []):
        if str(raw.get("id")) == server_id or str(raw.get("instance_id")) == server_id:
            return raw
    return None


def manual_power(server_id: str, power_action: str) -> dict[str, Any]:
    load_env(ENV_FILE)
    config = load_config()
    raw = find_raw_instance(config, server_id)
    if raw is None:
        raise RuntimeError(f"server not found: {server_id}")

    item = merged_instance(raw, config.get("defaults", {}))
    client = get_client(item["region_id"], item["access_key_id"], item["access_key_secret"])
    instance = describe_instance(client, item["instance_id"])
    if not instance:
        raise RuntimeError(f"ECS instance not found: {item['instance_id']}")

    status = instance.get("Status")
    api_response = None
    if power_action == "start":
        raw["manual_stop"] = False
        raw["enabled"] = True
        if status != "Running":
            api_response = ecs_start(client, item["instance_id"])
        action = "manual_start"
        reason = "手动开机并恢复自动保护"
    elif power_action == "stop":
        raw["manual_stop"] = True
        if status not in {"Stopped", "Stopping"}:
            api_response = ecs_stop(client, item["instance_id"])
        action = "manual_stop"
        reason = "手动关机，自动启动已暂停"
    else:
        raise RuntimeError(f"unsupported power action: {power_action}")

    atomic_write_json(CONFIG_FILE, config)
    event = {
        "at": iso_now(),
        "id": item["id"],
        "label": item["label"],
        "traffic_gb": None,
        "traffic_scope": item.get("traffic_scope"),
        "traffic_pool_id": item.get("traffic_pool_id"),
        "traffic_pool_key": item.get("traffic_pool_key"),
        "traffic_pool_label": item.get("traffic_pool_label"),
        "status": status,
        "action": action,
        "reason": reason,
        "error": None,
    }
    append_history(event)
    prune_history()
    try:
        notifications.send_message(
            f"Aliyun CDT Guard {notifications.action_label(action)}",
            notifications.instance_line(
                {
                    **item,
                    "status": status,
                    "action": action,
                    "reason": reason,
                    "traffic_gb": None,
                }
            ),
            {"event": event},
        )
    except Exception as exc:
        logger.exception("manual power notification failed: %s", exc)
    logger.info("%s %s status=%s response=%s", item["id"], action, status, api_response)
    return event


def print_status(as_json: bool = False) -> int:
    status = read_status()
    if not status:
        print("暂无状态，请先运行：cdt-guard run")
        return 1
    if as_json:
        print(json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    summary = status.get("summary", {})
    print(f"更新时间：{status.get('generated_at')}")
    print(f"机器：{summary.get('enabled', 0)}/{summary.get('total', 0)} 启用，流量池 {summary.get('pools', 0)}，预警 {summary.get('warnings', 0)}，错误 {summary.get('errors', 0)}")
    for item in status.get("instances", []):
        traffic = item.get("traffic_gb")
        traffic_text = "未知" if traffic is None else f"{traffic:.4f} GB"
        print(
            f"- {item.get('label')} | {item.get('instance_status')} | "
            f"{item.get('traffic_pool_label', item.get('traffic_region_id'))} | "
            f"{traffic_text}/{item.get('stop_threshold_gb')} GB | {item.get('action')} | {item.get('reason')}"
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Aliyun CDT guard")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("run")
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--json", action="store_true")
    power_parser = subparsers.add_parser("power")
    power_parser.add_argument("server_id")
    power_parser.add_argument("action", choices=["start", "stop"])
    args = parser.parse_args()

    if args.command in {None, "run"}:
        run_guard()
        return 0
    if args.command == "status":
        return print_status(as_json=args.json)
    if args.command == "power":
        manual_power(args.server_id, args.action)
        run_guard()
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        logger.exception("guard run failed: %s", exc)
        raise SystemExit(1)

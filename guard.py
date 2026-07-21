#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import fcntl
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkecs.request.v20140526 import (
    DescribeInstancesRequest,
    StartInstancesRequest,
    StopInstancesRequest,
)

BASE_DIR = Path("/opt/aliyun-cdt-guard")
ENV_FILE = BASE_DIR / "guard.env"
CONFIG_FILE = BASE_DIR / "instances.json"
STATUS_FILE = BASE_DIR / "status.json"
HISTORY_FILE = BASE_DIR / "history.jsonl"
LOCK_FILE = BASE_DIR / "guard.lock"
MAX_HISTORY_LINES = 5000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


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
            },
            "instances": [
                {
                    "id": "hk-launch-advisor",
                    "label": "香港 launch-advisor",
                    "region_id": legacy_region_id,
                    "traffic_region_id": legacy_traffic_region,
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

    try:
        lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return
    if len(lines) > MAX_HISTORY_LINES:
        HISTORY_FILE.write_text("\n".join(lines[-MAX_HISTORY_LINES:]) + "\n", encoding="utf-8")
        os.chmod(HISTORY_FILE, 0o600)


def get_client(region_id: str, access_key_id: str | None = None, access_key_secret: str | None = None) -> AcsClient:
    return AcsClient(
        access_key_id or require_env("ALIYUN_ACCESS_KEY_ID"),
        access_key_secret or require_env("ALIYUN_ACCESS_KEY_SECRET"),
        region_id,
    )


def get_total_traffic_gb(client: AcsClient, traffic_region_id: str | None = None) -> float:
    request = CommonRequest()
    request.set_domain("cdt.aliyuncs.com")
    request.set_version("2021-08-13")
    request.set_action_name("ListCdtInternetTraffic")
    request.set_method("POST")
    request.set_accept_format("json")

    response = client.do_action_with_exception(request)
    response_json = json.loads(response.decode("utf-8"))
    traffic_details = response_json.get("TrafficDetails", [])

    if traffic_region_id:
        traffic_details = [
            item for item in traffic_details
            if item.get("BusinessRegionId") == traffic_region_id
        ]

    total_bytes = sum(int(item.get("Traffic", 0) or 0) for item in traffic_details)
    return total_bytes / (1024 ** 3)


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
    item["enabled"] = bool(item.get("enabled", True))
    item["manual_stop"] = bool(item.get("manual_stop", False))
    item["region_id"] = item.get("region_id") or require_env("ALIYUN_REGION_ID")
    item["traffic_region_id"] = item.get("traffic_region_id") or item["region_id"]
    item["label"] = item.get("label") or item.get("id") or item["instance_id"]
    item["id"] = item.get("id") or item["instance_id"]
    item["access_key_id"] = item.get("access_key_id") or os.environ.get("ALIYUN_ACCESS_KEY_ID", "")
    item["access_key_secret"] = item.get("access_key_secret") or os.environ.get("ALIYUN_ACCESS_KEY_SECRET", "")
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

    client_cache: dict[str, AcsClient] = {}
    traffic_cache: dict[tuple[str, str], float] = {}
    results: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []

    with LOCK_FILE.open("w") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logger.info("another guard run is still active; skipping")
            return read_status() or {"generated_at": iso_now(), "skipped": True, "instances": []}

        for raw in raw_instances:
            item = merged_instance(raw, defaults)
            region_id = item["region_id"]
            traffic_region_id = item["traffic_region_id"]
            key = (region_id, traffic_region_id, item["access_key_id"])
            result = {
                "id": item["id"],
                "label": item["label"],
                "enabled": item["enabled"],
                "manual_stop": item["manual_stop"],
                "region_id": region_id,
                "traffic_region_id": traffic_region_id,
                "instance_id": item["instance_id"],
                "warning_threshold_gb": item["warning_threshold_gb"],
                "start_threshold_gb": item["start_threshold_gb"],
                "stop_threshold_gb": item["stop_threshold_gb"],
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
                    traffic_cache[key] = get_total_traffic_gb(client, traffic_region_id)
                traffic_gb = traffic_cache[key]

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
                    }
                )
                logger.info("%s %s traffic=%.4fGB status=%s action=%s", item["id"], traffic_region_id, traffic_gb, ecs_status, action)
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
    return status


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    enabled = [item for item in results if item.get("enabled")]
    errors = [item for item in results if item.get("last_error")]
    warnings = [item for item in results if item.get("warning")]
    stopped = [item for item in results if item.get("instance_status") == "Stopped"]
    actions = [item for item in results if item.get("action") in {"start", "stop"}]
    return {
        "total": len(results),
        "enabled": len(enabled),
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
        "status": status,
        "action": action,
        "reason": reason,
        "error": None,
    }
    append_history(event)
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
    print(f"机器：{summary.get('enabled', 0)}/{summary.get('total', 0)} 启用，预警 {summary.get('warnings', 0)}，错误 {summary.get('errors', 0)}")
    for item in status.get("instances", []):
        traffic = item.get("traffic_gb")
        traffic_text = "未知" if traffic is None else f"{traffic:.4f} GB"
        print(
            f"- {item.get('label')} | {item.get('instance_status')} | "
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

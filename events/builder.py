import json
import socket
import platform
import time
import uuid
from typing import Any, Dict, Optional

from .schema import (
    EVENT_VERSION,
    REQUIRED_TOP_LEVEL_KEYS,
    REQUIRED_PROCESS_KEYS,
    REQUIRED_HOST_KEYS,
)

def _now_ts_ns() -> int:
    return time.time_ns()

def _get_host_info() -> Dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "kernel_release": platform.release(),
    }

def validate_event(evt: Dict[str, Any]) -> None:
    missing_top = REQUIRED_TOP_LEVEL_KEYS - set(evt.keys())
    if missing_top:
        raise ValueError(f"Missing top-level keys: {sorted(missing_top)}")

    if not isinstance(evt["host"], dict):
        raise ValueError("Event 'host' must be dict")

    missing_host = REQUIRED_HOST_KEYS - set(evt["host"].keys())
    if missing_host:
        raise ValueError(f"Missing host keys: {sorted(missing_host)}")

    if not isinstance(evt["process"], dict):
        raise ValueError("Event 'process' must be dict")

    missing_proc = REQUIRED_PROCESS_KEYS - set(evt["process"].keys())
    if missing_proc:
        raise ValueError(f"Missing process keys: {sorted(missing_proc)}")

    if not isinstance(evt["ts_ns"], int):
        raise ValueError("ts_ns must be int")

    if not isinstance(evt["event_type"], str):
        raise ValueError("event_type must be str")

    if not isinstance(evt["data"], dict):
        raise ValueError("data must be dict")

def build_event(
    event_type: str,
    process: Dict[str, Any],
    data: Optional[Dict[str, Any]] = None,
    ts_ns: Optional[int] = None,
    event_id: Optional[str] = None,
) -> Dict[str, Any]:

    if data is None:
        data = {}

    evt = {
        "version": EVENT_VERSION,
        "event_id": event_id or str(uuid.uuid4()),
        "event_type": event_type,
        "ts_ns": ts_ns or _now_ts_ns(),
        "host": _get_host_info(),
        "process": process,
        "data": data,
    }

    validate_event(evt)
    return evt

def write_jsonl(path: str, evt: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, separators=(",", ":"), ensure_ascii=False) + "\n")

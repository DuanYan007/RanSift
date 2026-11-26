"""Procmon event normalization for the coarse process-tree layer."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

PROCESS_CREATE_OPS = {"process create", "process start", "createprocess"}

_TIME_FIELDS = ("timestamp", "time", "Time of Day", "Time", "raw_time")
_PROCESS_FIELDS = ("process_name", "Process Name", "process", "image")
_PID_FIELDS = ("pid", "PID", "Process ID")
_OPERATION_FIELDS = ("operation", "Operation", "event_type")
_PATH_FIELDS = ("path", "Path", "target", "object")
_DETAIL_FIELDS = ("detail", "Detail", "command_line", "Command Line")
_RESULT_FIELDS = ("result", "Result")


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    timestamp: float
    raw_time: str
    process_name: str
    pid: int
    operation: str
    path: str = ""
    detail: str = ""
    result: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "raw_time": self.raw_time,
            "process_name": self.process_name,
            "pid": self.pid,
            "operation": self.operation,
            "path": self.path,
            "detail": self.detail,
            "result": self.result,
        }


def normalize_event(row: dict, ordinal: int) -> EventRecord:
    raw_time = _first(row, _TIME_FIELDS, str(ordinal))
    return EventRecord(
        event_id=str(row.get("event_id") or row.get("Event ID") or f"ev_{ordinal:08d}"),
        timestamp=_parse_time(raw_time, ordinal),
        raw_time=raw_time,
        process_name=_first(row, _PROCESS_FIELDS),
        pid=_parse_pid(_first(row, _PID_FIELDS, "0")),
        operation=_first(row, _OPERATION_FIELDS),
        path=_first(row, _PATH_FIELDS),
        detail=_first(row, _DETAIL_FIELDS),
        result=_first(row, _RESULT_FIELDS),
        raw=dict(row),
    )


def extract_child_pid(detail: str) -> int | None:
    for pattern in (r"Child PID:\s*(\d+)", r"(?<!Parent )\bPID:\s*(\d+)", r"Process ID:\s*(\d+)"):
        match = re.search(pattern, detail or "", flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def extract_parent_pid(detail: str) -> int | None:
    match = re.search(r"Parent PID:\s*(\d+)", detail or "", flags=re.IGNORECASE)
    return int(match.group(1)) if match else None


def _first(row: dict, names: tuple[str, ...], default: str = "") -> str:
    for name in names:
        if name in row and row[name] not in (None, ""):
            return str(row[name])
    return default


def _parse_time(value: str, ordinal: int) -> float:
    if value is None or value == "":
        return float(ordinal)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    match = re.search(r"(?:(\d+):)?(\d+):(\d+)(?:\.(\d+))?", text)
    if not match:
        return float(ordinal)
    hours = int(match.group(1) or 0)
    minutes = int(match.group(2) or 0)
    seconds = int(match.group(3) or 0)
    frac = float(f"0.{match.group(4)}") if match.group(4) else 0.0
    return hours * 3600 + minutes * 60 + seconds + frac


def _parse_pid(value: str) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0

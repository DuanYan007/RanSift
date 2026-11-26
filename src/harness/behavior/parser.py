"""Parser for tree-filtered behavior event streams."""
from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterator
from pathlib import Path, PureWindowsPath
from typing import Any

from .classification import classify_operation_family
from .path_scope import is_controlled_sample_path
from .models import (
    BehaviorAction,
    BehaviorDetail,
    BehaviorEvent,
    BehaviorOrder,
    BehaviorProcessContext,
    BehaviorSummary,
    BehaviorTarget,
    BehaviorTime,
)

EVENT_ID_RE = re.compile(r"^ev_(\d+)$", re.IGNORECASE)
CHILD_PID_RE = re.compile(r"(?:^|,\s*)(?:Child PID|PID):\s*(\d+)", re.IGNORECASE)
PARENT_PID_RE = re.compile(r"Parent PID:\s*(\d+)", re.IGNORECASE)
COMMAND_LINE_RE = re.compile(r"Command line:\s*(.+?)(?:,\s*(?:Current directory|Parent PID|User|Integrity|Virtualized):|$)", re.IGNORECASE)
RENAME_DESTINATION_RE = re.compile(r"(?:^|,\s*)FileName:\s*(.+)$", re.IGNORECASE)

FILE_OPERATIONS = {
    "createfile",
    "readfile",
    "writefile",
    "closefile",
    "queryopen",
    "querydirectory",
    "queryeafile",
    "queryattributetagfile",
    "querybasicinformationfile",
    "querystandardinformationfile",
    "querynetworkopeninformationfile",
    "querysecurityfile",
    "setendoffileinformationfile",
    "setrenameinformationfile",
    "setdispositioninformationfile",
    "setdispositioninformationex",
    "createfilemapping",
}


def iter_behavior_events(path: str | Path) -> Iterator[BehaviorEvent]:
    """Streams normalized behavior events from a filtered-events JSONL file."""

    with Path(path).open("r", encoding="utf-8") as f:
        for filtered_order, line in enumerate(f):
            if not line.strip():
                continue
            yield parse_filtered_event(json.loads(line), filtered_order)


def parse_filtered_event(row: dict[str, Any], filtered_order: int) -> BehaviorEvent:
    event = row.get("event")
    if not isinstance(event, dict):
        raise ValueError("filtered event row must contain an event object")

    source = str(event.get("event_id") or "")
    timestamp = float(event.get("timestamp") or 0.0)
    operation = str(event.get("operation") or "")
    path = str(event.get("path") or "")
    raw_detail = str(event.get("detail") or "")
    normalized_path = normalize_path(path)
    process_name = str(event.get("process_name") or row.get("tree_process") or "")
    pid = int(event.get("pid") or 0)
    node_id = str(row.get("node_id") or "")
    operation_family = classify_operation_family(operation)
    return BehaviorEvent(
        order=BehaviorOrder(
            filtered=filtered_order,
            source=source,
            source_numeric=parse_source_numeric(source),
        ),
        time=BehaviorTime(
            timestamp=timestamp,
            raw_time=str(event.get("raw_time") or ""),
        ),
        action=BehaviorAction(
            operation=operation,
            category=categorize_operation(operation),
            result=str(event.get("result") or ""),
            operation_family=operation_family,
        ),
        target=BehaviorTarget(
            path=path,
            normalized_path=normalized_path,
            namespace=classify_namespace(normalized_path),
            extension=extract_extension(path),
        ),
        detail=BehaviorDetail(
            raw_detail=raw_detail,
            parsed=parse_detail(raw_detail),
        ),
        process_context=BehaviorProcessContext(
            pid=pid,
            process_name=process_name,
            node_id=node_id,
            depth=int(row.get("depth") or 0),
            process_key=make_process_key(node_id, pid, process_name),
        ),
    )


def summarize_behavior_events(path: str | Path) -> BehaviorSummary:
    operations: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    namespaces: Counter[str] = Counter()
    processes: set[tuple[int, str]] = set()
    nodes: set[str] = set()
    event_count = 0
    time_start: float | None = None
    time_end: float | None = None
    previous_time: float | None = None
    time_inversions = 0

    for event in iter_behavior_events(path):
        event_count += 1
        timestamp = event.time.timestamp
        if time_start is None:
            time_start = timestamp
        time_end = timestamp
        if previous_time is not None and timestamp < previous_time:
            time_inversions += 1
        previous_time = timestamp
        operations[event.action.operation] += 1
        categories[event.action.category] += 1
        namespaces[event.target.namespace] += 1
        processes.add((event.process_context.pid, event.process_context.process_name))
        if event.process_context.node_id:
            nodes.add(event.process_context.node_id)

    duration = None
    if time_start is not None and time_end is not None:
        duration = round(time_end - time_start, 6)
    return BehaviorSummary(
        event_count=event_count,
        time_start=time_start,
        time_end=time_end,
        duration_s=duration,
        time_inversions=time_inversions,
        process_count=len(processes),
        node_count=len(nodes),
        operation_counts=dict(sorted(operations.items())),
        category_counts=dict(sorted(categories.items())),
        namespace_counts=dict(sorted(namespaces.items())),
    )


def parse_source_numeric(source: str) -> int | None:
    match = EVENT_ID_RE.match(source.strip())
    if not match:
        return None
    return int(match.group(1))


def categorize_operation(operation: str) -> str:
    op = operation.lower().strip()
    if op.startswith("reg"):
        return "registry"
    if op.startswith("tcp") or op.startswith("udp"):
        return "network"
    if "process" in op or "thread" in op or op == "load image":
        return "process"
    if op.startswith("irp_") or op in FILE_OPERATIONS or "file" in op:
        return "file"
    return "other"


def normalize_path(path: str) -> str:
    cleaned = (path or "").strip()
    if not cleaned:
        return ""
    return cleaned.replace("/", "\\").casefold()


def classify_namespace(normalized_path: str) -> str:
    if not normalized_path:
        return "empty"
    if normalized_path.startswith(("hklm", "hkcu", "hkcr", "hku", "hkcc", "\\registry")):
        return "registry"
    if normalized_path.startswith(("tcp ", "udp ", "tcp:", "udp:")):
        return "network"
    if normalized_path.startswith("c:\\users\\"):
        return "users"
    if normalized_path.startswith("c:\\windows\\"):
        return "windows"
    if normalized_path.startswith("c:\\programdata\\"):
        return "programdata"
    if normalized_path.startswith(("c:\\program files\\", "c:\\program files (x86)\\")):
        return "program_files"
    if is_controlled_sample_path(normalized_path):
        return "controlled_sample"
    return "other"


def extract_extension(path: str) -> str:
    if not path:
        return ""
    normalized = path.replace("/", "\\")
    if normalized.casefold().startswith(("hklm", "hkcu", "hkcr", "hku", "hkcc", "\\registry")):
        return ""
    try:
        suffix = PureWindowsPath(normalized).suffix
    except Exception:
        return ""
    return suffix[1:].casefold() if suffix.startswith(".") else ""


def parse_detail(detail: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    text = detail or ""
    command = COMMAND_LINE_RE.search(text)
    if command:
        parsed["command_line"] = command.group(1).strip()
    parent = PARENT_PID_RE.search(text)
    if parent:
        parsed["parent_pid"] = int(parent.group(1))
    child = CHILD_PID_RE.search(text)
    if child:
        parsed["child_pid"] = int(child.group(1))
    rename_destination = RENAME_DESTINATION_RE.search(text)
    if rename_destination:
        parsed["rename_destination"] = rename_destination.group(1).strip()
    return parsed


def make_process_key(node_id: str, pid: int, process_name: str) -> str:
    node = node_id or "node_unknown"
    return f"{node}|{int(pid or 0)}|{str(process_name or '').casefold()}"

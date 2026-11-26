"""Index builder for normalized behavior event streams."""
from __future__ import annotations

import json
import math
import re
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .blocks import make_target_scope
from .classification import classify_operation_family
from .models import BehaviorEvent
from .parser import iter_behavior_events

INDEX_SCHEMA_VERSION = "behavior-index-v1"

IndexMap = dict[str, list[int]]


@dataclass(frozen=True)
class BehaviorIndex:
    event_count: int
    time_bucket_seconds: float
    time_start: float | None
    time_end: float | None
    operation_index: IndexMap
    operation_family_index: IndexMap
    category_index: IndexMap
    result_index: IndexMap
    path_index: IndexMap
    namespace_index: IndexMap
    extension_index: IndexMap
    pid_index: IndexMap
    process_name_index: IndexMap
    process_key_index: IndexMap
    node_index: IndexMap
    target_scope_index: IndexMap
    command_token_index: IndexMap
    time_bucket_index: IndexMap

    def get(self, index_name: str, key: str) -> list[int]:
        index = getattr(self, index_name)
        if not isinstance(index, dict):
            raise KeyError(f"unknown index: {index_name}")
        return list(index.get(normalize_key(key), ()))

    def key_counts(self) -> dict[str, int]:
        return {name: len(getattr(self, name)) for name in INDEX_FIELD_NAMES}

    def link_counts(self) -> dict[str, int]:
        return {
            name: sum(len(offsets) for offsets in getattr(self, name).values())
            for name in INDEX_FIELD_NAMES
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": INDEX_SCHEMA_VERSION,
            "event_count": self.event_count,
            "time_bucket_seconds": self.time_bucket_seconds,
            "time_start": self.time_start,
            "time_end": self.time_end,
            "duration_s": duration(self.time_start, self.time_end),
            "key_counts": self.key_counts(),
            "link_counts": self.link_counts(),
            "indexes": {name: compact_index(getattr(self, name)) for name in INDEX_FIELD_NAMES},
        }


INDEX_FIELD_NAMES = (
    "operation_index",
    "operation_family_index",
    "category_index",
    "result_index",
    "path_index",
    "namespace_index",
    "extension_index",
    "pid_index",
    "process_name_index",
    "process_key_index",
    "node_index",
    "target_scope_index",
    "command_token_index",
    "time_bucket_index",
)


class BehaviorIndexBuilder:
    def __init__(self, time_bucket_seconds: float = 1.0) -> None:
        if time_bucket_seconds <= 0:
            raise ValueError("time_bucket_seconds must be positive")
        self.time_bucket_seconds = float(time_bucket_seconds)
        self.event_count = 0
        self.time_start: float | None = None
        self.time_end: float | None = None
        self.operation_index: defaultdict[str, list[int]] = defaultdict(list)
        self.operation_family_index: defaultdict[str, list[int]] = defaultdict(list)
        self.category_index: defaultdict[str, list[int]] = defaultdict(list)
        self.result_index: defaultdict[str, list[int]] = defaultdict(list)
        self.path_index: defaultdict[str, list[int]] = defaultdict(list)
        self.namespace_index: defaultdict[str, list[int]] = defaultdict(list)
        self.extension_index: defaultdict[str, list[int]] = defaultdict(list)
        self.pid_index: defaultdict[str, list[int]] = defaultdict(list)
        self.process_name_index: defaultdict[str, list[int]] = defaultdict(list)
        self.process_key_index: defaultdict[str, list[int]] = defaultdict(list)
        self.node_index: defaultdict[str, list[int]] = defaultdict(list)
        self.target_scope_index: defaultdict[str, list[int]] = defaultdict(list)
        self.command_token_index: defaultdict[str, list[int]] = defaultdict(list)
        self.time_bucket_index: defaultdict[str, list[int]] = defaultdict(list)

    def add(self, event: BehaviorEvent) -> None:
        order = event.order.filtered
        self.event_count += 1
        timestamp = event.time.timestamp
        self.time_start = timestamp if self.time_start is None else min(self.time_start, timestamp)
        self.time_end = timestamp if self.time_end is None else max(self.time_end, timestamp)

        operation_family = event.action.operation_family or classify_operation_family(event.action.operation)
        process_key = event.process_context.process_key or make_process_key(
            event.process_context.node_id,
            event.process_context.pid,
            event.process_context.process_name,
        )
        add_key(self.operation_index, event.action.operation, order)
        add_key(self.operation_family_index, operation_family, order)
        add_key(self.category_index, event.action.category, order)
        add_key(self.result_index, event.action.result, order)
        add_key(self.path_index, event.target.normalized_path, order)
        add_key(self.namespace_index, event.target.namespace, order)
        add_key(self.extension_index, event.target.extension, order)
        if event.process_context.pid > 0:
            add_key(self.pid_index, str(event.process_context.pid), order)
        add_key(self.process_name_index, event.process_context.process_name, order)
        add_key(self.process_key_index, process_key, order)
        add_key(self.node_index, event.process_context.node_id, order)
        add_key(self.target_scope_index, make_target_scope(event, operation_family), order)
        for token in command_tokens(event):
            add_key(self.command_token_index, token, order)
        add_key(self.time_bucket_index, time_bucket_key(timestamp, self.time_bucket_seconds), order)

    def build(self) -> BehaviorIndex:
        return BehaviorIndex(
            event_count=self.event_count,
            time_bucket_seconds=self.time_bucket_seconds,
            time_start=self.time_start,
            time_end=self.time_end,
            operation_index=dict(self.operation_index),
            operation_family_index=dict(self.operation_family_index),
            category_index=dict(self.category_index),
            result_index=dict(self.result_index),
            path_index=dict(self.path_index),
            namespace_index=dict(self.namespace_index),
            extension_index=dict(self.extension_index),
            pid_index=dict(self.pid_index),
            process_name_index=dict(self.process_name_index),
            process_key_index=dict(self.process_key_index),
            node_index=dict(self.node_index),
            target_scope_index=dict(self.target_scope_index),
            command_token_index=dict(self.command_token_index),
            time_bucket_index=dict(self.time_bucket_index),
        )


def build_behavior_index(events: Iterable[BehaviorEvent], time_bucket_seconds: float = 1.0) -> BehaviorIndex:
    builder = BehaviorIndexBuilder(time_bucket_seconds=time_bucket_seconds)
    for event in events:
        builder.add(event)
    return builder.build()


def materialize_behavior_artifacts(
    events_path: str | Path,
    out_root: str | Path,
    family: str,
    sha256: str,
    time_bucket_seconds: float = 1.0,
) -> dict[str, Any]:
    events_path = Path(events_path)
    out_root = Path(out_root)
    trace_path = out_root / "traces" / family / f"{sha256}.behavior_trace.jsonl"
    trace_meta_path = out_root / "traces" / family / f"{sha256}.behavior_trace.meta.json"
    index_path = out_root / "indexes" / family / f"{sha256}.behavior_index.json"
    index_meta_path = out_root / "indexes" / family / f"{sha256}.behavior_index.meta.json"
    audit_path = out_root / "samples" / family / f"{sha256}.index_audit.json"

    for path in (trace_path, trace_meta_path, index_path, index_meta_path, audit_path):
        path.parent.mkdir(parents=True, exist_ok=True)

    start = time.perf_counter()
    builder = BehaviorIndexBuilder(time_bucket_seconds=time_bucket_seconds)
    with trace_path.open("w", encoding="utf-8") as out:
        for event in iter_behavior_events(events_path):
            builder.add(event)
            out.write(json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
    parse_index_wall_time_s = time.perf_counter() - start

    index = builder.build()
    trace_meta = trace_metadata(index, events_path, trace_path)
    write_json(trace_meta_path, trace_meta)
    write_json(index_path, index.to_dict())

    index_meta = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "source_events_path": str(events_path),
        "trace_path": str(trace_path),
        "index_path": str(index_path),
        "event_count": index.event_count,
        "time_bucket_seconds": time_bucket_seconds,
        "parse_index_wall_time_s": round(parse_index_wall_time_s, 6),
        "trace_bytes": trace_path.stat().st_size,
        "index_bytes": index_path.stat().st_size,
        "key_counts": index.key_counts(),
        "link_counts": index.link_counts(),
    }
    write_json(index_meta_path, index_meta)

    audit = build_index_audit(index, trace_path)
    write_json(audit_path, audit)

    return {
        "family": family,
        "sha256": sha256,
        "events_path": str(events_path),
        "trace_path": str(trace_path),
        "trace_meta_path": str(trace_meta_path),
        "index_path": str(index_path),
        "index_meta_path": str(index_meta_path),
        "audit_path": str(audit_path),
        "event_count": index.event_count,
        "parse_index_wall_time_s": round(parse_index_wall_time_s, 6),
        "trace_bytes": trace_path.stat().st_size,
        "index_bytes": index_path.stat().st_size,
        "key_counts": index.key_counts(),
    }


def read_trace_events_at_offsets(trace_path: str | Path, offsets: Iterable[int]) -> dict[int, dict[str, Any]]:
    wanted = set(offsets)
    if not wanted:
        return {}
    found: dict[int, dict[str, Any]] = {}
    with Path(trace_path).open("r", encoding="utf-8") as f:
        for order, line in enumerate(f):
            if order in wanted:
                found[order] = json.loads(line)
                if len(found) == len(wanted):
                    break
    return found


def build_index_audit(index: BehaviorIndex, trace_path: str | Path) -> dict[str, Any]:
    offsets = sampled_offsets(index)
    events = read_trace_events_at_offsets(trace_path, offsets)
    resolved = []
    for offset in offsets:
        event = events.get(offset)
        resolved.append(
            {
                "offset": offset,
                "resolved": event is not None,
                "source": None if event is None else event["order"]["source"],
                "operation": None if event is None else event["action"]["operation"],
                "process_name": None if event is None else event["process_context"]["process_name"],
            }
        )
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "event_count": index.event_count,
        "sampled_offsets": offsets,
        "resolved_events": resolved,
        "all_sampled_offsets_resolved": all(item["resolved"] for item in resolved),
    }


def sampled_offsets(index: BehaviorIndex, limit: int = 12) -> list[int]:
    offsets: set[int] = set()
    if index.event_count:
        offsets.add(0)
        offsets.add(index.event_count - 1)
    for name in INDEX_FIELD_NAMES:
        mapping = getattr(index, name)
        for key in sorted(mapping):
            values = mapping[key]
            if values:
                offsets.add(values[0])
                offsets.add(values[-1])
                break
        if len(offsets) >= limit:
            break
    return sorted(offsets)[:limit]


def trace_metadata(index: BehaviorIndex, events_path: Path, trace_path: Path) -> dict[str, Any]:
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "source_events_path": str(events_path),
        "trace_path": str(trace_path),
        "event_count": index.event_count,
        "time_start": index.time_start,
        "time_end": index.time_end,
        "duration_s": duration(index.time_start, index.time_end),
        "key_counts": index.key_counts(),
        "link_counts": index.link_counts(),
    }


def add_key(index: defaultdict[str, list[int]], key: str, order: int) -> None:
    normalized = normalize_key(key)
    if normalized:
        index[normalized].append(order)


def normalize_key(value: str) -> str:
    return str(value or "").strip().casefold()


def time_bucket_key(timestamp: float, bucket_seconds: float) -> str:
    return str(int(math.floor(timestamp / bucket_seconds)))


def compact_index(index: IndexMap) -> IndexMap:
    return {key: index[key] for key in sorted(index)}


def duration(start: float | None, end: float | None) -> float | None:
    if start is None or end is None:
        return None
    return round(end - start, 6)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


COMMAND_TOKEN_RE = re.compile(r"[a-zA-Z0-9_.:/\\-]{2,}")


def command_tokens(event: BehaviorEvent, limit: int = 64) -> tuple[str, ...]:
    pieces = [
        event.detail.parsed.get("command_line", ""),
        event.detail.raw_detail,
    ]
    if event.action.category == "process":
        pieces.append(event.target.normalized_path)
        pieces.append(event.process_context.process_name)
    tokens: list[str] = []
    seen: set[str] = set()
    for piece in pieces:
        for token in COMMAND_TOKEN_RE.findall(str(piece or "")):
            normalized = normalize_key(token.strip('"'))
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            tokens.append(normalized)
            if len(tokens) >= limit:
                return tuple(tokens)
    return tuple(tokens)


def make_process_key(node_id: str, pid: int, process_name: str) -> str:
    node = node_id or "node_unknown"
    return f"{node}|{int(pid or 0)}|{str(process_name or '').casefold()}"

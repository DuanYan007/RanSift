"""Memory-bounded event indexes, byte checkpoints and process-local phase fragments."""
from __future__ import annotations

import hashlib
import heapq
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .blocks import HIGH_SIGNAL_FAMILIES, classify_behavior_kind
from .classification import classify_operation_family
from .file_transitions import direct_user_shared_target_scope


BEHAVIOR_CATALOG_SCHEMA = "behavior-catalog-v1"
BEHAVIOR_PHASE_BLOCK_SCHEMA = "behavior-phase-block-v1"
TRACE_CHECKPOINT_SCHEMA = "behavior-trace-checkpoints-v1"

DEFAULT_CHECKPOINT_STRIDE = 1024
DEFAULT_REPRESENTATIVE_LIMIT = 12
DEFAULT_PHASE_TIME_GAP_S = 10.0
DEFAULT_PHASE_ORDER_GAP = 250
DEFAULT_PHASE_EVENT_CAP = 2048
DEFAULT_TARGET_EXAMPLE_LIMIT = 5
DEFAULT_EXTENSION_EXAMPLE_LIMIT = 8

COMMAND_TOKEN_RE = re.compile(r"[a-zA-Z0-9_.:/\\\\-]{2,}")

INDEX_LIMITS = {
    "operation_index": 256,
    "operation_family_index": 128,
    "category_index": 32,
    "result_index": 128,
    "namespace_index": 32,
    "extension_index": 4096,
    "process_name_index": 1024,
    "process_key_index": 4096,
    "node_index": 4096,
    "target_scope_index": 256,
    "command_token_index": 4096,
    "basename_token_index": 4096,
}


class BehaviorCatalogError(ValueError):
    """Raised when a normalized trace cannot produce a valid catalog."""


@dataclass
class RepresentativeOffsets:
    """Keep deterministic bounded representatives without retaining all offsets."""

    key: str
    capacity: int = DEFAULT_REPRESENTATIVE_LIMIT
    first_offset: int | None = None
    last_offset: int | None = None
    _reservoir: list[tuple[int, int, int]] = field(default_factory=list)

    def add(self, offset: int) -> None:
        if self.first_offset is None:
            self.first_offset = offset
        self.last_offset = offset
        if self.capacity <= 0:
            return
        score = int.from_bytes(
            hashlib.blake2b(f"{self.key}\0{offset}".encode("utf-8"), digest_size=8).digest(),
            "big",
        )
        # The heap root is the least desirable retained sample: highest score,
        # represented by the smallest negative score.
        candidate = (-score, -offset, offset)
        if len(self._reservoir) < self.capacity:
            heapq.heappush(self._reservoir, candidate)
        elif candidate > self._reservoir[0]:
            heapq.heapreplace(self._reservoir, candidate)

    def offsets(self) -> list[int]:
        values = {item[2] for item in self._reservoir}
        if self.first_offset is not None:
            values.add(self.first_offset)
        if self.last_offset is not None:
            values.add(self.last_offset)
        return sorted(values)


@dataclass
class _IndexEntry:
    key: str
    representative_limit: int
    count: int = 0
    representatives: RepresentativeOffsets = field(init=False)

    def __post_init__(self) -> None:
        self.representatives = RepresentativeOffsets(self.key, self.representative_limit)

    def add(self, offset: int) -> None:
        self.count += 1
        self.representatives.add(offset)

    def to_dict(self) -> dict[str, Any]:
        offsets = self.representatives.offsets()
        return {
            "key": self.key,
            "event_count": self.count,
            "representative_offsets": offsets,
            "first_offset": self.representatives.first_offset,
            "last_offset": self.representatives.last_offset,
        }


class BoundedEvidenceIndex:
    """Exact retained-key counts with a documented key-cardinality bound."""

    def __init__(self, name: str, key_limit: int, representative_limit: int) -> None:
        if key_limit <= 0:
            raise ValueError("key_limit must be positive")
        self.name = name
        self.key_limit = key_limit
        self.representative_limit = representative_limit
        self.entries: dict[str, _IndexEntry] = {}
        self.omitted_new_key_observations = 0
        self.omitted_event_observations = 0

    def add(self, value: str, offset: int) -> None:
        key = normalize_key(value)
        if not key:
            return
        entry = self.entries.get(key)
        if entry is None:
            if len(self.entries) >= self.key_limit:
                self.omitted_new_key_observations += 1
                self.omitted_event_observations += 1
                return
            entry = _IndexEntry(key, self.representative_limit)
            self.entries[key] = entry
        entry.add(offset)

    def to_dict(self) -> dict[str, Any]:
        entries = sorted(
            (entry.to_dict() for entry in self.entries.values()),
            key=lambda item: (-int(item["event_count"]), str(item["key"])),
        )
        return {
            "key_limit": self.key_limit,
            "retained_key_count": len(entries),
            "omitted_new_key_observations": self.omitted_new_key_observations,
            "omitted_event_observations": self.omitted_event_observations,
            "representative_limit": self.representative_limit,
            "entries": entries,
        }


@dataclass
class _OpenPhase:
    block_id: str
    process_instance: dict[str, Any]
    behavior_kind: str
    category: str
    target_scope: str
    representative_limit: int
    target_example_limit: int
    extension_example_limit: int
    time_start: float
    time_end: float
    order_start: int
    order_end: int
    event_count: int = 0
    operation_counts: Counter[str] = field(default_factory=Counter)
    family_counts: Counter[str] = field(default_factory=Counter)
    result_counts: Counter[str] = field(default_factory=Counter)
    namespace_counts: Counter[str] = field(default_factory=Counter)
    extension_counts: Counter[str] = field(default_factory=Counter)
    target_examples: list[str] = field(default_factory=list)
    representatives: RepresentativeOffsets = field(init=False)
    contains_non_success: bool = False
    contains_high_signal_family: bool = False
    timestamp_inversion: bool = False

    def __post_init__(self) -> None:
        self.representatives = RepresentativeOffsets(self.block_id, self.representative_limit)

    def accepts(
        self,
        *,
        timestamp: float,
        offset: int,
        max_time_gap_s: float,
        max_order_gap: int,
        max_event_count: int,
    ) -> bool:
        if self.event_count >= max_event_count:
            return False
        if offset - self.order_end > max_order_gap:
            return False
        return max(0.0, timestamp - self.time_end) <= max_time_gap_s

    def add(self, event: dict[str, Any], *, family: str, offset: int, timestamp: float) -> None:
        action = event.get("action") or {}
        target = event.get("target") or {}
        operation = str(action.get("operation") or "")
        result = str(action.get("result") or "")
        namespace = str(target.get("namespace") or "empty")
        extension = normalize_key(str(target.get("extension") or "")) or "noext"
        target_path = normalize_key(str(target.get("normalized_path") or target.get("path") or ""))

        self.event_count += 1
        self.time_end = timestamp
        self.order_end = offset
        self.operation_counts[operation] += 1
        self.family_counts[family] += 1
        self.result_counts[result] += 1
        self.namespace_counts[namespace] += 1
        self.extension_counts[extension] += 1
        if target_path and len(self.target_examples) < self.target_example_limit and target_path not in self.target_examples:
            self.target_examples.append(target_path)
        self.representatives.add(offset)
        self.contains_non_success = self.contains_non_success or normalize_key(result) not in {"", "success"}
        self.contains_high_signal_family = self.contains_high_signal_family or family in HIGH_SIGNAL_FAMILIES
        self.timestamp_inversion = self.timestamp_inversion or timestamp < self.time_start

    def to_dict(self) -> dict[str, Any]:
        limitations = [
            "phase block aggregates one process, behavior kind, and coarse target scope",
            "order_range may include interleaved events from other open phase blocks; use representative_offsets for evidence retrieval",
        ]
        if self.contains_non_success:
            limitations.append("contains non-success results")
        if self.timestamp_inversion:
            limitations.append("timestamp inversion observed; filtered order remains authoritative")
        return {
            "schema_version": BEHAVIOR_PHASE_BLOCK_SCHEMA,
            "block_id": self.block_id,
            "level": "phase",
            "process_instance": dict(self.process_instance),
            "behavior_kind": self.behavior_kind,
            "category": self.category,
            "target_scope": self.target_scope,
            "time_range": [self.time_start, self.time_end],
            "order_range": [self.order_start, self.order_end],
            "event_count": self.event_count,
            "operation_families": sorted(self.family_counts),
            "operation_counts": dict(sorted(self.operation_counts.items())),
            "operation_family_counts": dict(sorted(self.family_counts.items())),
            "result_counts": dict(sorted(self.result_counts.items())),
            "namespace_counts": dict(sorted(self.namespace_counts.items())),
            "extension_examples": top_counter_values(self.extension_counts, self.extension_example_limit),
            "target_examples": list(self.target_examples),
            "representative_offsets": self.representatives.offsets(),
            "limitations": limitations,
        }


class PhaseBlockBuilder:
    """Build bounded coarse-scope behavior phases without retaining event rows."""

    def __init__(
        self,
        emit: Callable[[dict[str, Any]], None],
        *,
        max_time_gap_s: float,
        max_order_gap: int,
        max_event_count: int,
        representative_limit: int,
        target_example_limit: int,
        extension_example_limit: int,
    ) -> None:
        if max_time_gap_s < 0 or max_order_gap <= 0 or max_event_count <= 0:
            raise ValueError("phase parameters must be positive")
        self.emit = emit
        self.max_time_gap_s = float(max_time_gap_s)
        self.max_order_gap = int(max_order_gap)
        self.max_event_count = int(max_event_count)
        self.representative_limit = int(representative_limit)
        self.target_example_limit = int(target_example_limit)
        self.extension_example_limit = int(extension_example_limit)
        self._open: dict[tuple[str, str, str], _OpenPhase] = {}
        self._next_id = 1
        self.block_count = 0
        self.block_event_count = 0
        self.blocks_by_kind: Counter[str] = Counter()
        self.blocks_by_category: Counter[str] = Counter()
        self.process_partition_violations = 0

    def add(self, event: dict[str, Any], offset: int) -> None:
        action = event.get("action") or {}
        category = str(action.get("category") or "other")
        family = normalize_key(str(action.get("operation_family") or ""))
        if not family:
            family = classify_operation_family(str(action.get("operation") or ""))
        behavior_kind = classify_behavior_kind(family, category)
        process = process_instance(event)
        process_key = str(process["key"])
        target_scope = phase_target_scope(event, family)
        timestamp = event_timestamp(event)
        key = (process_key, behavior_kind, target_scope)
        current = self._open.get(key)
        if current is None or not current.accepts(
            timestamp=timestamp,
            offset=offset,
            max_time_gap_s=self.max_time_gap_s,
            max_order_gap=self.max_order_gap,
            max_event_count=self.max_event_count,
        ):
            if current is not None:
                self._close(key)
            current = self._new_phase(
                process=process,
                behavior_kind=behavior_kind,
                category=category,
                target_scope=target_scope,
                timestamp=timestamp,
                offset=offset,
            )
            self._open[key] = current
        current.add(event, family=family, offset=offset, timestamp=timestamp)

    def finish(self) -> None:
        for key in sorted(self._open.keys()):
            self._close(key)
        self._open.clear()

    def _new_phase(
        self,
        *,
        process: dict[str, Any],
        behavior_kind: str,
        category: str,
        target_scope: str,
        timestamp: float,
        offset: int,
    ) -> _OpenPhase:
        block_id = f"phase_{self._next_id:08d}"
        self._next_id += 1
        return _OpenPhase(
            block_id=block_id,
            process_instance=process,
            behavior_kind=behavior_kind,
            category=category,
            target_scope=target_scope,
            representative_limit=self.representative_limit,
            target_example_limit=self.target_example_limit,
            extension_example_limit=self.extension_example_limit,
            time_start=timestamp,
            time_end=timestamp,
            order_start=offset,
            order_end=offset,
        )

    def _close(self, key: tuple[str, str, str]) -> None:
        phase = self._open.pop(key)
        if phase.process_instance.get("key") != key[0]:
            self.process_partition_violations += 1
        payload = phase.to_dict()
        self.emit(payload)
        self.block_count += 1
        self.block_event_count += phase.event_count
        self.blocks_by_kind[phase.behavior_kind] += 1
        self.blocks_by_category[phase.category] += 1


class _BlockWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._stream = path.open("wb")
        self._digest = hashlib.sha256()
        self.byte_count = 0

    def emit(self, block: dict[str, Any]) -> None:
        payload = (json.dumps(block, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        self._stream.write(payload)
        self._digest.update(payload)
        self.byte_count += len(payload)

    def close(self) -> dict[str, Any]:
        self._stream.close()
        return {"sha256": self._digest.hexdigest(), "size_bytes": self.byte_count}


def build_behavior_catalog(
    *,
    trace_path: str | Path,
    phase_blocks_path: str | Path,
    checkpoints_path: str | Path,
    checkpoint_stride: int = DEFAULT_CHECKPOINT_STRIDE,
    representative_limit: int = DEFAULT_REPRESENTATIVE_LIMIT,
    phase_time_gap_s: float = DEFAULT_PHASE_TIME_GAP_S,
    phase_order_gap: int = DEFAULT_PHASE_ORDER_GAP,
    phase_event_cap: int = DEFAULT_PHASE_EVENT_CAP,
) -> dict[str, Any]:
    """Stream one normalized trace into compact indexes, checkpoints, and phases."""

    trace = Path(trace_path)
    blocks_path = Path(phase_blocks_path)
    checkpoints = Path(checkpoints_path)
    if not trace.is_file():
        raise BehaviorCatalogError(f"trace does not exist: {trace}")
    if checkpoint_stride <= 0 or representative_limit <= 0:
        raise BehaviorCatalogError("checkpoint stride and representative limit must be positive")

    blocks_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoints.parent.mkdir(parents=True, exist_ok=True)
    indexes = {
        name: BoundedEvidenceIndex(name, limit, representative_limit)
        for name, limit in INDEX_LIMITS.items()
    }
    writer = _BlockWriter(blocks_path)
    builder = PhaseBlockBuilder(
        writer.emit,
        max_time_gap_s=phase_time_gap_s,
        max_order_gap=phase_order_gap,
        max_event_count=phase_event_cap,
        representative_limit=representative_limit,
        target_example_limit=DEFAULT_TARGET_EXAMPLE_LIMIT,
        extension_example_limit=DEFAULT_EXTENSION_EXAMPLE_LIMIT,
    )
    checkpoint_rows: list[list[int]] = []
    event_count = 0
    previous_timestamp: float | None = None
    time_inversions = 0
    try:
        with trace.open("rb") as stream:
            while True:
                byte_offset = stream.tell()
                line = stream.readline()
                if not line:
                    break
                if not line.strip():
                    continue
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise BehaviorCatalogError(f"trace row {event_count} is not an object")
                offset = event_offset(event)
                if offset != event_count:
                    raise BehaviorCatalogError(f"trace order is not contiguous: {offset}!={event_count}")
                if event_count % checkpoint_stride == 0:
                    checkpoint_rows.append([event_count, byte_offset])
                timestamp = event_timestamp(event)
                if previous_timestamp is not None and timestamp < previous_timestamp:
                    time_inversions += 1
                previous_timestamp = timestamp
                add_event_indexes(indexes, event, offset)
                builder.add(event, offset)
                event_count += 1
        builder.finish()
    except Exception:
        writer.close()
        raise
    blocks_artifact = writer.close()

    checkpoints_payload = {
        "schema_version": TRACE_CHECKPOINT_SCHEMA,
        "trace_size_bytes": trace.stat().st_size,
        "event_count": event_count,
        "stride": checkpoint_stride,
        "checkpoints": checkpoint_rows,
    }
    checkpoints.write_text(
        json.dumps(checkpoints_payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if builder.block_event_count != event_count:
        raise BehaviorCatalogError(
            f"phase block event conservation failed: {builder.block_event_count}!={event_count}"
        )

    return {
        "schema_version": BEHAVIOR_CATALOG_SCHEMA,
        "event_count": event_count,
        "trace_size_bytes": trace.stat().st_size,
        "trace_time_inversions": time_inversions,
        "checkpoints": {
            "schema_version": TRACE_CHECKPOINT_SCHEMA,
            "stride": checkpoint_stride,
            "count": len(checkpoint_rows),
        },
        "phase_parameters": {
            "max_time_gap_s": phase_time_gap_s,
            "max_order_gap": phase_order_gap,
            "max_event_count": phase_event_cap,
            "target_scope_policy": "namespace-or-direct-user-shared",
        },
        "phase_blocks": {
            "schema_version": BEHAVIOR_PHASE_BLOCK_SCHEMA,
            "count": builder.block_count,
            "event_count": builder.block_event_count,
            "sha256": blocks_artifact["sha256"],
            "size_bytes": blocks_artifact["size_bytes"],
            "by_behavior_kind": dict(sorted(builder.blocks_by_kind.items())),
            "by_category": dict(sorted(builder.blocks_by_category.items())),
        },
        "indexes": {name: index.to_dict() for name, index in sorted(indexes.items())},
        "integrity": {
            "event_count_matches_phase_blocks": builder.block_event_count == event_count,
            "non_contiguous_offset_count": 0,
            "process_partition_violations": builder.process_partition_violations,
            "status": "pass" if builder.process_partition_violations == 0 else "fail",
        },
        "limitations": [
            "indexes retain exact counts only for keys admitted before their documented key limit",
            "each retained index key stores bounded representative offsets rather than a complete posting list",
            "phase blocks are descriptive compression units and do not establish execution intent or maliciousness",
        ],
    }


def add_event_indexes(indexes: dict[str, BoundedEvidenceIndex], event: dict[str, Any], offset: int) -> None:
    action = event.get("action") or {}
    target = event.get("target") or {}
    process = process_instance(event)
    operation = str(action.get("operation") or "")
    family = normalize_key(str(action.get("operation_family") or "")) or classify_operation_family(operation)
    category = str(action.get("category") or "other")
    indexes["operation_index"].add(operation, offset)
    indexes["operation_family_index"].add(family, offset)
    indexes["category_index"].add(category, offset)
    indexes["result_index"].add(str(action.get("result") or ""), offset)
    indexes["namespace_index"].add(str(target.get("namespace") or "empty"), offset)
    indexes["extension_index"].add(str(target.get("extension") or "noext"), offset)
    indexes["process_name_index"].add(str(process.get("process_name") or ""), offset)
    indexes["process_key_index"].add(str(process["key"]), offset)
    indexes["node_index"].add(str(process.get("node_id") or ""), offset)
    indexes["target_scope_index"].add(phase_target_scope(event, family), offset)
    for token in command_tokens(event):
        indexes["command_token_index"].add(token, offset)
    for token in basename_tokens(event):
        indexes["basename_token_index"].add(token, offset)


def process_instance(event: dict[str, Any]) -> dict[str, Any]:
    process = event.get("process_context") or {}
    node_id = str(process.get("node_id") or "")
    process_name = str(process.get("process_name") or "")
    try:
        pid = int(process.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    key = str(process.get("process_key") or "").strip()
    if not key:
        key = f"{node_id or 'node_unknown'}|{pid}|{process_name.casefold()}"
    return {
        "key": key,
        "node_id": node_id,
        "pid": pid,
        "process_name": process_name,
        "depth": int_or_default(process.get("depth"), 0),
    }


def phase_target_scope(event: dict[str, Any], operation_family: str) -> str:
    action = event.get("action") or {}
    target = event.get("target") or {}
    category = str(action.get("category") or "other")
    namespace = normalize_key(str(target.get("namespace") or "")) or "empty"
    path = normalize_key(str(target.get("normalized_path") or target.get("path") or ""))
    if category == "file":
        direct_scope = direct_user_shared_target_scope(path)
        if direct_scope:
            return f"direct_user_shared:{direct_scope}"
        return f"file:{namespace}"
    if category == "registry":
        hive = path.split("\\", 1)[0] if path else "empty"
        return f"registry:{hive}"
    if category == "network":
        protocol = path.split(" ", 1)[0].split(":", 1)[0] if path else "other"
        return f"network:{protocol}"
    if category == "process":
        return "process:execution" if operation_family == "process_start" else "process:runtime"
    return f"{category}:{namespace}"


def command_tokens(event: dict[str, Any], limit: int = 32) -> list[str]:
    action = event.get("action") or {}
    detail = event.get("detail") or {}
    parsed = detail.get("parsed") if isinstance(detail.get("parsed"), dict) else {}
    command_line = str(parsed.get("command_line") or "")
    category = normalize_key(str(action.get("category") or ""))
    raw_detail = str(detail.get("raw_detail") or "")
    if not command_line and category != "process":
        return []
    text = f"{command_line} {raw_detail}".strip()
    return distinct_tokens(text, limit)


def basename_tokens(event: dict[str, Any], limit: int = 12) -> list[str]:
    target = event.get("target") or {}
    path = normalize_key(str(target.get("normalized_path") or target.get("path") or ""))
    if not path:
        return []
    basename = path.rsplit("\\", 1)[-1]
    return distinct_tokens(basename, limit)


def distinct_tokens(text: str, limit: int) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for token in COMMAND_TOKEN_RE.findall(str(text or "")):
        normalized = normalize_key(token.strip("\"'"))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        values.append(normalized)
        if len(values) >= limit:
            break
    return values


def event_offset(event: dict[str, Any]) -> int:
    order = event.get("order") or {}
    try:
        return int(order.get("filtered"))
    except (TypeError, ValueError) as exc:
        raise BehaviorCatalogError("trace event has no integer filtered offset") from exc


def event_timestamp(event: dict[str, Any]) -> float:
    time = event.get("time") or {}
    try:
        return float(time.get("timestamp"))
    except (TypeError, ValueError) as exc:
        raise BehaviorCatalogError("trace event has no numeric timestamp") from exc


def normalize_key(value: str) -> str:
    return str(value or "").strip().casefold()


def int_or_default(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def top_counter_values(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    return [
        {"key": key, "count": count}
        for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]

"""Typed models for the second-layer behavior evidence stream."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BehaviorOrder:
    filtered: int
    source: str
    source_numeric: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "filtered": self.filtered,
            "source": self.source,
            "source_numeric": self.source_numeric,
        }


@dataclass(frozen=True)
class BehaviorTime:
    timestamp: float
    raw_time: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "raw_time": self.raw_time,
        }


@dataclass(frozen=True)
class BehaviorAction:
    operation: str
    category: str
    result: str
    operation_family: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "category": self.category,
            "result": self.result,
            "operation_family": self.operation_family,
        }


@dataclass(frozen=True)
class BehaviorTarget:
    path: str
    normalized_path: str
    namespace: str
    extension: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "normalized_path": self.normalized_path,
            "namespace": self.namespace,
            "extension": self.extension,
        }


@dataclass(frozen=True)
class BehaviorDetail:
    raw_detail: str
    parsed: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_detail": self.raw_detail,
            "parsed": self.parsed,
        }


@dataclass(frozen=True)
class BehaviorProcessContext:
    pid: int
    process_name: str
    node_id: str
    depth: int
    process_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "node_id": self.node_id,
            "depth": self.depth,
            "process_key": self.process_key,
        }


@dataclass(frozen=True)
class BehaviorEvent:
    order: BehaviorOrder
    time: BehaviorTime
    action: BehaviorAction
    target: BehaviorTarget
    detail: BehaviorDetail
    process_context: BehaviorProcessContext

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order.to_dict(),
            "time": self.time.to_dict(),
            "action": self.action.to_dict(),
            "target": self.target.to_dict(),
            "detail": self.detail.to_dict(),
            "process_context": self.process_context.to_dict(),
        }


@dataclass(frozen=True)
class BehaviorSummary:
    event_count: int
    time_start: float | None
    time_end: float | None
    duration_s: float | None
    time_inversions: int
    process_count: int
    node_count: int
    operation_counts: dict[str, int]
    category_counts: dict[str, int]
    namespace_counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": self.event_count,
            "time_start": self.time_start,
            "time_end": self.time_end,
            "duration_s": self.duration_s,
            "time_inversions": self.time_inversions,
            "process_count": self.process_count,
            "node_count": self.node_count,
            "operation_counts": self.operation_counts,
            "category_counts": self.category_counts,
            "namespace_counts": self.namespace_counts,
        }

"""Data models for watch-set driven process-tree construction."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

FactKind = Literal["spawn", "observe", "exit"]
NodeStatus = Literal["open", "closed"]

FACT_PRIORITY = {
    "spawn": 10,
    "observe": 20,
    "exit": 30,
}


@dataclass(frozen=True)
class SliceMeta:
    """Metadata that makes a slice traceable without binding the builder to one slicing strategy."""

    slice_id: str
    strategy: str
    ordinal: int
    event_start: int
    event_end: int
    time_start: float | None
    time_end: float | None
    event_count: int
    source_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "slice_id": self.slice_id,
            "strategy": self.strategy,
            "ordinal": self.ordinal,
            "event_start": self.event_start,
            "event_end": self.event_end,
            "time_start": self.time_start,
            "time_end": self.time_end,
            "event_count": self.event_count,
            "source_ref": self.source_ref,
        }


@dataclass(frozen=True)
class ProcessFact:
    """Normalized fact consumed by the tree builder.

    Tree construction only depends on this fact schema, not on the raw log format
    or the slicing strategy that produced it.
    """

    fact_id: str
    kind: FactKind
    slice_id: str
    event_index: int
    time: float
    pid: int = 0
    process_name: str = ""
    operation: str = ""
    parent_pid: int = 0
    child_pid: int = 0
    child_name: str = ""
    child_path: str = ""
    result: str = ""
    parent_pid_conflict: bool = False
    parent_pid_candidates: tuple[int, ...] = ()
    source_event_ids: tuple[str, ...] = ()
    source: str = ""

    @property
    def priority(self) -> int:
        return FACT_PRIORITY[self.kind]

    def sort_key(self) -> tuple[float, int, int, str]:
        return (self.time, self.event_index, self.priority, self.fact_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "kind": self.kind,
            "slice_id": self.slice_id,
            "event_index": self.event_index,
            "time": self.time,
            "pid": self.pid,
            "process_name": self.process_name,
            "operation": self.operation,
            "parent_pid": self.parent_pid,
            "child_pid": self.child_pid,
            "child_name": self.child_name,
            "child_path": self.child_path,
            "result": self.result,
            "parent_pid_conflict": self.parent_pid_conflict,
            "parent_pid_candidates": list(self.parent_pid_candidates),
            "source_event_ids": list(self.source_event_ids),
            "source": self.source,
        }


@dataclass(frozen=True)
class SliceEnvelope:
    meta: SliceMeta
    facts: tuple[ProcessFact, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta.to_dict(),
            "facts": [fact.to_dict() for fact in self.facts],
        }


@dataclass
class NodeProcess:
    pid: int
    name: str
    start_time: float
    end_time: float
    pid_generation: int
    start_event_index: int = -1
    end_event_index: int = -1
    observed_events: int = 0
    close_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "pid_generation": self.pid_generation,
            "start_event_index": self.start_event_index,
            "end_event_index": self.end_event_index,
            "observed_events": self.observed_events,
            "close_reason": self.close_reason,
        }


@dataclass
class ProcessTreeNode:
    node_id: str
    parent_node_id: str | None
    depth: int
    status: NodeStatus
    process: NodeProcess
    source_facts: list[str] = field(default_factory=list)
    children: list["ProcessTreeNode"] = field(default_factory=list)

    def to_summary(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "parent_node_id": self.parent_node_id,
            "depth": self.depth,
            "status": self.status,
            "process": self.process.to_dict(),
            "source_facts": list(self.source_facts),
            "child_count": len(self.children),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.to_summary()
        payload["children"] = [child.to_dict() for child in self.children]
        return payload


@dataclass(frozen=True)
class TreeDiagnostic:
    code: str
    message: str
    fact_id: str | None = None
    node_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "fact_id": self.fact_id,
            "node_id": self.node_id,
            "metadata": self.metadata,
        }


@dataclass
class ProcessTreeOutput:
    trace_id: str
    root_nodes: list[ProcessTreeNode]
    node_index: dict[str, ProcessTreeNode]
    diagnostics: list[TreeDiagnostic]
    slice_count: int
    fact_count: int
    ignored_fact_count: int
    attribution: dict[str, Any] = field(default_factory=dict)

    @property
    def node_count(self) -> int:
        return len(self.node_index)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "node_count": self.node_count,
            "slice_count": self.slice_count,
            "fact_count": self.fact_count,
            "ignored_fact_count": self.ignored_fact_count,
            "attribution": self.attribution,
            "root_nodes": [node.to_dict() for node in self.root_nodes],
            "node_index": {
                node_id: node.to_summary()
                for node_id, node in sorted(self.node_index.items())
            },
            "diagnostics": [diag.to_dict() for diag in self.diagnostics],
        }

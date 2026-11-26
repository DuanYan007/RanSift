"""Tree-indexed log filtering.

The filter treats a process tree as a fixed attribution index. It does not
modify the tree, infer new children, or perform behavior classification.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .events import PROCESS_CREATE_OPS, extract_child_pid, normalize_event


@dataclass(frozen=True)
class NodeInterval:
    node_id: str
    pid: int
    process_name: str
    depth: int
    start_time: float
    end_time: float
    start_event_index: int = -1
    end_event_index: int = -1

    def contains(self, timestamp: float, event_index: int, grace_seconds: float) -> bool:
        if self.start_event_index >= 0 and event_index < self.start_event_index:
            return False
        if self.end_event_index >= 0 and event_index > self.end_event_index:
            return False
        return self.start_time - grace_seconds <= timestamp <= self.end_time + grace_seconds


def load_tree_intervals(tree: dict[str, Any]) -> dict[int, list[NodeInterval]]:
    """Builds a PID -> interval index from a serialized tree output."""

    intervals: dict[int, list[NodeInterval]] = defaultdict(list)
    for node in tree.get("node_index", {}).values():
        process = node.get("process", {})
        pid = int(process.get("pid") or 0)
        if not pid:
            continue
        interval = NodeInterval(
            node_id=node["node_id"],
            pid=pid,
            process_name=process.get("name", ""),
            depth=int(node.get("depth") or 0),
            start_time=float(process.get("start_time") or 0.0),
            end_time=float(process.get("end_time") or process.get("start_time") or 0.0),
            start_event_index=int(process.get("start_event_index") if process.get("start_event_index") is not None else -1),
            end_event_index=int(process.get("end_event_index") if process.get("end_event_index") is not None else -1),
        )
        intervals[pid].append(interval)
    for pid in intervals:
        intervals[pid].sort(key=lambda item: (item.start_time, item.end_time, item.node_id))
    return dict(intervals)


def filter_csv_by_tree(
    log_path: str | Path,
    tree_path: str | Path,
    out_events_path: str | Path | None,
    out_summary_path: str | Path,
    grace_seconds: float = 0.5,
    write_events: bool = True,
) -> dict[str, Any]:
    """Filters a Procmon CSV using a fixed process-tree interval index.

    When ``write_events`` is false, the function still scans the raw log and
    computes exactly the same summary counters, but it does not materialize the
    retained events. This mode is used for large full-corpus denoising audits.
    """

    tree = json.loads(Path(tree_path).read_text(encoding="utf-8"))
    intervals_by_pid = load_tree_intervals(tree)
    raw_event_count = 0
    kept_event_count = 0
    drop_reason_counts: Counter[str] = Counter()
    node_event_counts: Counter[str] = Counter()
    node_process_names = {
        interval.node_id: interval.process_name
        for intervals in intervals_by_pid.values()
        for interval in intervals
    }
    tree_pids = set(intervals_by_pid)
    tree_parent_spawn_missing_child_count = 0
    out_summary = Path(out_summary_path)
    out_summary.parent.mkdir(parents=True, exist_ok=True)

    dst = None
    if write_events:
        if out_events_path is None:
            raise ValueError("out_events_path is required when write_events=True")
        out_events = Path(out_events_path)
        out_events.parent.mkdir(parents=True, exist_ok=True)
        dst = out_events.open("w", encoding="utf-8")

    try:
        with Path(log_path).open("r", encoding="utf-8-sig", newline="") as src:
            reader = csv.DictReader(src)
            for idx, row in enumerate(reader):
                raw_event_count += 1
                event = normalize_event(row, idx)
                child_pid = _spawn_child_pid(event.operation, event.detail)
                if child_pid and event.pid in intervals_by_pid and child_pid not in tree_pids:
                    tree_parent_spawn_missing_child_count += 1
                match = _match_event(event.pid, event.timestamp, idx, intervals_by_pid, grace_seconds)
                if match is None:
                    if event.pid not in intervals_by_pid:
                        drop_reason_counts["pid_not_in_tree"] += 1
                    else:
                        drop_reason_counts["outside_lifetime"] += 1
                    continue
                kept_event_count += 1
                node_event_counts[match.node_id] += 1
                if dst is not None:
                    dst.write(json.dumps({
                        "node_id": match.node_id,
                        "depth": match.depth,
                        "tree_process": match.process_name,
                        "event": event.to_dict(),
                    }, ensure_ascii=False) + "\n")
    finally:
        if dst is not None:
            dst.close()

    tree_node_count = sum(len(v) for v in intervals_by_pid.values())
    tree_pid_count = len(intervals_by_pid)
    kept_ratio = round(kept_event_count / raw_event_count, 8) if raw_event_count else 0.0
    summary = {
        "log_path": str(log_path),
        "tree_path": str(tree_path),
        "events_path": str(out_events_path) if write_events and out_events_path is not None else None,
        "write_events": bool(write_events),
        "grace_seconds": grace_seconds,
        "tree_node_count": tree_node_count,
        "tree_pid_count": tree_pid_count,
        "raw_event_count": raw_event_count,
        "kept_event_count": kept_event_count,
        "dropped_event_count": raw_event_count - kept_event_count,
        "kept_ratio": kept_ratio,
        "tree_completeness": _tree_completeness(
            tree_node_count,
            raw_event_count,
            kept_ratio,
            tree_parent_spawn_missing_child_count,
        ),
        "drop_reason_counts": dict(sorted(drop_reason_counts.items())),
        "node_event_counts": dict(sorted(node_event_counts.items())),
        "node_process_names": dict(sorted(node_process_names.items())),
    }
    out_summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def _spawn_child_pid(operation: str, detail: str) -> int | None:
    if operation.casefold().strip() not in PROCESS_CREATE_OPS:
        return None
    return extract_child_pid(detail)


def _tree_completeness(
    tree_node_count: int,
    raw_event_count: int,
    kept_ratio: float,
    tree_parent_spawn_missing_child_count: int,
) -> dict[str, Any]:
    diagnostics: list[str] = []
    if tree_node_count == 1 and tree_parent_spawn_missing_child_count:
        diagnostics.append("root_only_tree_with_child_process_create")
    if raw_event_count and kept_ratio < 0.001:
        diagnostics.append("very_low_retention_ratio")
    return {
        "tree_parent_spawn_missing_child_count": tree_parent_spawn_missing_child_count,
        "diagnostics": diagnostics,
    }


def _match_event(
    pid: int,
    timestamp: float,
    event_index: int,
    intervals_by_pid: dict[int, list[NodeInterval]],
    grace_seconds: float,
) -> NodeInterval | None:
    candidates = intervals_by_pid.get(pid, ())
    matches = [interval for interval in candidates if interval.contains(timestamp, event_index, grace_seconds)]
    if not matches:
        return None
    return sorted(matches, key=lambda item: (item.start_time, item.end_time, item.node_id))[-1]

"""Task handlers for second-layer behavior artifact construction."""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from harness.behavior.blocks import build_process_behavior_blocks
from harness.behavior.index import BehaviorIndexBuilder, build_index_audit
from harness.behavior.models import (
    BehaviorAction,
    BehaviorDetail,
    BehaviorEvent,
    BehaviorOrder,
    BehaviorProcessContext,
    BehaviorTarget,
    BehaviorTime,
)
from harness.behavior.parser import iter_behavior_events

from .models import AnalysisSessionState, SessionFact, TaskContext, TaskResult, TaskSpec
from .runner import TaskRunner

TASK_NORMALIZE_BEHAVIOR_TRACE = "normalize_behavior_trace"
TASK_BUILD_BEHAVIOR_INDEX = "build_behavior_index"
TASK_BUILD_BEHAVIOR_BLOCKS = "build_behavior_blocks"


def behavior_task_handlers() -> dict[str, Any]:
    return {
        TASK_NORMALIZE_BEHAVIOR_TRACE: normalize_behavior_trace,
        TASK_BUILD_BEHAVIOR_INDEX: build_behavior_index_task,
        TASK_BUILD_BEHAVIOR_BLOCKS: build_behavior_blocks_task,
    }


def build_behavior_task_specs(
    filtered_events_artifact_id: str = "tree_filter_events:tree_filtered_events",
    time_bucket_seconds: float = 1.0,
    micro_time_gap_s: float = 2.0,
    micro_order_gap: int = 25,
    macro_time_gap_s: float = 10.0,
    macro_order_gap: int = 250,
) -> tuple[TaskSpec, ...]:
    return (
        TaskSpec(
            task_id="normalize_behavior_trace",
            task_type=TASK_NORMALIZE_BEHAVIOR_TRACE,
            dependencies=("tree_filter_events",),
            input_artifacts={"tree_filtered_events": filtered_events_artifact_id},
            output_names=("behavior_trace", "behavior_trace_meta"),
            acceptance_criteria=("all retained events are normalized", "filtered order is contiguous"),
        ),
        TaskSpec(
            task_id="build_behavior_index",
            task_type=TASK_BUILD_BEHAVIOR_INDEX,
            dependencies=("normalize_behavior_trace",),
            input_artifacts={"behavior_trace": "normalize_behavior_trace:behavior_trace"},
            parameters={"time_bucket_seconds": time_bucket_seconds},
            output_names=("behavior_index", "behavior_index_meta", "index_audit"),
            acceptance_criteria=("index offsets resolve into trace events", "index event count matches trace event count"),
        ),
        TaskSpec(
            task_id="build_behavior_blocks",
            task_type=TASK_BUILD_BEHAVIOR_BLOCKS,
            dependencies=("normalize_behavior_trace",),
            input_artifacts={"behavior_trace": "normalize_behavior_trace:behavior_trace"},
            parameters={
                "micro_time_gap_s": micro_time_gap_s,
                "micro_order_gap": micro_order_gap,
                "macro_time_gap_s": macro_time_gap_s,
                "macro_order_gap": macro_order_gap,
            },
            output_names=("behavior_blocks", "behavior_blocks_meta"),
            acceptance_criteria=("blocks do not cross process instances", "representative offsets resolve into trace events"),
        ),
    )


def run_behavior_task_graph(state: AnalysisSessionState) -> AnalysisSessionState:
    TaskRunner(behavior_task_handlers(), state).run_all(build_behavior_task_specs())
    return state


def normalize_behavior_trace(context: TaskContext) -> TaskResult:
    events_path = context.input_path("tree_filtered_events")
    trace_path = context.store.path_for(context.spec.task_id, "behavior_trace.jsonl")
    meta_path = context.store.path_for(context.spec.task_id, "behavior_trace.meta.json")
    operation_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    namespace_counts: Counter[str] = Counter()
    process_keys: set[tuple[int, str]] = set()
    nodes: set[str] = set()
    event_count = 0
    time_start: float | None = None
    time_end: float | None = None
    previous_time: float | None = None
    time_inversions = 0

    with trace_path.open("w", encoding="utf-8") as dst:
        for event in iter_behavior_events(events_path):
            if event.order.filtered != event_count:
                raise ValueError("normalized behavior trace order is not contiguous")
            event_count += 1
            timestamp = event.time.timestamp
            time_start = timestamp if time_start is None else time_start
            time_end = timestamp
            if previous_time is not None and timestamp < previous_time:
                time_inversions += 1
            previous_time = timestamp
            operation_counts[event.action.operation] += 1
            category_counts[event.action.category] += 1
            namespace_counts[event.target.namespace] += 1
            process_keys.add((event.process_context.pid, event.process_context.process_name))
            if event.process_context.node_id:
                nodes.add(event.process_context.node_id)
            dst.write(json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")

    meta = {
        "schema_version": "behavior-trace-v1",
        "source_events_path": str(events_path),
        "trace_path": str(trace_path),
        "event_count": event_count,
        "time_start": time_start,
        "time_end": time_end,
        "duration_s": duration(time_start, time_end),
        "time_inversions": time_inversions,
        "process_count": len(process_keys),
        "node_count": len(nodes),
        "operation_counts": dict(sorted(operation_counts.items())),
        "category_counts": dict(sorted(category_counts.items())),
        "namespace_counts": dict(sorted(namespace_counts.items())),
        "trace_bytes": trace_path.stat().st_size,
    }
    write_json(meta_path, meta)
    artifacts = {
        "behavior_trace": context.store.artifact_ref(
            context.spec.task_id,
            "behavior_trace",
            "behavior_trace",
            trace_path,
            {"event_count": event_count},
        ),
        "behavior_trace_meta": context.store.artifact_ref(context.spec.task_id, "behavior_trace_meta", "behavior_trace_meta", meta_path),
    }
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:summary",
        kind="behavior_trace_summary",
        data=meta,
        source_task_id=context.spec.task_id,
        artifact_ids=tuple(ref.artifact_id for ref in artifacts.values()),
    )
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=meta)


def build_behavior_index_task(context: TaskContext) -> TaskResult:
    trace_path = context.input_path("behavior_trace")
    time_bucket_seconds = float(context.spec.parameters.get("time_bucket_seconds") or 1.0)
    index_path = context.store.path_for(context.spec.task_id, "behavior_index.json")
    meta_path = context.store.path_for(context.spec.task_id, "behavior_index.meta.json")
    audit_path = context.store.path_for(context.spec.task_id, "index_audit.json")

    start = time.perf_counter()
    builder = BehaviorIndexBuilder(time_bucket_seconds=time_bucket_seconds)
    for event in iter_behavior_trace(trace_path):
        builder.add(event)
    index = builder.build()
    build_wall_time_s = time.perf_counter() - start
    write_json(index_path, index.to_dict())
    audit = build_index_audit(index, trace_path)
    write_json(audit_path, audit)
    meta = {
        "schema_version": "behavior-index-v1",
        "trace_path": str(trace_path),
        "index_path": str(index_path),
        "event_count": index.event_count,
        "time_bucket_seconds": time_bucket_seconds,
        "build_wall_time_s": round(build_wall_time_s, 6),
        "trace_bytes": trace_path.stat().st_size,
        "index_bytes": index_path.stat().st_size,
        "key_counts": index.key_counts(),
        "link_counts": index.link_counts(),
        "audit_path": str(audit_path),
        "all_sampled_offsets_resolved": audit["all_sampled_offsets_resolved"],
    }
    write_json(meta_path, meta)
    artifacts = {
        "behavior_index": context.store.artifact_ref(context.spec.task_id, "behavior_index", "behavior_index", index_path, {"event_count": index.event_count}),
        "behavior_index_meta": context.store.artifact_ref(context.spec.task_id, "behavior_index_meta", "behavior_index_meta", meta_path),
        "index_audit": context.store.artifact_ref(context.spec.task_id, "index_audit", "index_audit", audit_path),
    }
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:summary",
        kind="behavior_index_summary",
        data=meta,
        source_task_id=context.spec.task_id,
        artifact_ids=tuple(ref.artifact_id for ref in artifacts.values()),
    )
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=meta)


def build_behavior_blocks_task(context: TaskContext) -> TaskResult:
    trace_path = context.input_path("behavior_trace")
    blocks_path = context.store.path_for(context.spec.task_id, "behavior_blocks.json")
    meta_path = context.store.path_for(context.spec.task_id, "behavior_blocks.meta.json")
    params = {
        "micro_time_gap_s": float(context.spec.parameters.get("micro_time_gap_s") or 2.0),
        "micro_order_gap": int(context.spec.parameters.get("micro_order_gap") or 25),
        "macro_time_gap_s": float(context.spec.parameters.get("macro_time_gap_s") or 10.0),
        "macro_order_gap": int(context.spec.parameters.get("macro_order_gap") or 250),
    }
    start = time.perf_counter()
    blocks = build_process_behavior_blocks(iter_behavior_trace(trace_path), **params)
    build_wall_time_s = time.perf_counter() - start
    write_json(blocks_path, blocks.to_dict())
    meta = blocks.summary()
    meta.update({
        "trace_path": str(trace_path),
        "blocks_path": str(blocks_path),
        "build_wall_time_s": round(build_wall_time_s, 6),
        "blocks_bytes": blocks_path.stat().st_size,
        "parameters": params,
    })
    write_json(meta_path, meta)
    artifacts = {
        "behavior_blocks": context.store.artifact_ref(
            context.spec.task_id,
            "behavior_blocks",
            "behavior_blocks",
            blocks_path,
            {"micro_block_count": len(blocks.micro_blocks), "macro_block_count": len(blocks.macro_blocks)},
        ),
        "behavior_blocks_meta": context.store.artifact_ref(context.spec.task_id, "behavior_blocks_meta", "behavior_blocks_meta", meta_path),
    }
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:summary",
        kind="behavior_block_summary",
        data=meta,
        source_task_id=context.spec.task_id,
        artifact_ids=tuple(ref.artifact_id for ref in artifacts.values()),
    )
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=meta)


def iter_behavior_trace(path: str | Path):
    with Path(path).open("r", encoding="utf-8") as src:
        for line in src:
            if line.strip():
                yield behavior_event_from_dict(json.loads(line))


def behavior_event_from_dict(data: dict[str, Any]) -> BehaviorEvent:
    return BehaviorEvent(
        order=BehaviorOrder(
            filtered=int(data["order"]["filtered"]),
            source=str(data["order"].get("source") or ""),
            source_numeric=data["order"].get("source_numeric"),
        ),
        time=BehaviorTime(
            timestamp=float(data["time"]["timestamp"]),
            raw_time=str(data["time"].get("raw_time") or ""),
        ),
        action=BehaviorAction(
            operation=str(data["action"].get("operation") or ""),
            category=str(data["action"].get("category") or ""),
            result=str(data["action"].get("result") or ""),
            operation_family=str(data["action"].get("operation_family") or ""),
        ),
        target=BehaviorTarget(
            path=str(data["target"].get("path") or ""),
            normalized_path=str(data["target"].get("normalized_path") or ""),
            namespace=str(data["target"].get("namespace") or ""),
            extension=str(data["target"].get("extension") or ""),
        ),
        detail=BehaviorDetail(
            raw_detail=str(data["detail"].get("raw_detail") or ""),
            parsed=dict(data["detail"].get("parsed") or {}),
        ),
        process_context=BehaviorProcessContext(
            pid=int(data["process_context"].get("pid") or 0),
            process_name=str(data["process_context"].get("process_name") or ""),
            node_id=str(data["process_context"].get("node_id") or ""),
            depth=int(data["process_context"].get("depth") or 0),
            process_key=str(data["process_context"].get("process_key") or ""),
        ),
    )


def duration(start: float | None, end: float | None) -> float | None:
    if start is None or end is None:
        return None
    return round(end - start, 6)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

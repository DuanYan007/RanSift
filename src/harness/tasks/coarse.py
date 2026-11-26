"""Task handlers for first-layer coarse log processing."""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from harness.coarse import EventCountSlicer, WatchTreeBuilder, filter_csv_by_tree, iter_csv_slice_envelopes
from harness.coarse.models import ProcessFact, SliceEnvelope, SliceMeta

from .models import AnalysisSessionState, SessionFact, TaskContext, TaskResult, TaskSpec
from .runner import TaskRunner

TASK_BUILD_LOGICAL_SLICE_INDEX = "build_logical_slice_index"
TASK_COLLECT_PROCESS_FACTS = "collect_process_facts"
TASK_BUILD_COARSE_PROCESS_TREE = "build_coarse_process_tree"
TASK_TREE_FILTER_EVENTS = "tree_filter_events"


def coarse_task_handlers() -> dict[str, Any]:
    return {
        TASK_BUILD_LOGICAL_SLICE_INDEX: build_logical_slice_index,
        TASK_COLLECT_PROCESS_FACTS: collect_process_facts,
        TASK_BUILD_COARSE_PROCESS_TREE: build_coarse_process_tree,
        TASK_TREE_FILTER_EVENTS: tree_filter_events,
    }


def build_coarse_task_specs(
    raw_log_artifact_id: str = "raw_log",
    sample_hint: str = "",
    trace_id: str = "trace",
    slice_size: int = 250,
    root_pid: int | None = None,
    grace_seconds: float = 0.5,
    write_events: bool = True,
) -> tuple[TaskSpec, ...]:
    return (
        TaskSpec(
            task_id="build_logical_slice_index",
            task_type=TASK_BUILD_LOGICAL_SLICE_INDEX,
            input_artifacts={"raw_log": raw_log_artifact_id},
            parameters={"slice_size": slice_size},
            output_names=("slice_manifest", "slice_summary"),
            acceptance_criteria=("raw events covered exactly once", "slice ranges are monotonic and contiguous"),
        ),
        TaskSpec(
            task_id="collect_process_facts",
            task_type=TASK_COLLECT_PROCESS_FACTS,
            dependencies=("build_logical_slice_index",),
            input_artifacts={
                "raw_log": raw_log_artifact_id,
                "slice_manifest": "build_logical_slice_index:slice_manifest",
            },
            parameters={"slice_size": slice_size},
            output_names=("slice_envelopes", "process_facts", "fact_summary"),
            acceptance_criteria=("process facts are sorted within each slice", "fact schema is independent of raw log rows"),
        ),
        TaskSpec(
            task_id="build_coarse_process_tree",
            task_type=TASK_BUILD_COARSE_PROCESS_TREE,
            dependencies=("collect_process_facts",),
            input_artifacts={"process_facts": "collect_process_facts:process_facts"},
            parameters={"sample_hint": sample_hint, "trace_id": trace_id, "root_pid": root_pid},
            output_names=("process_tree", "tree_summary"),
            acceptance_criteria=("children are created only from watched parents", "node ids are unique", "output is acyclic"),
        ),
        TaskSpec(
            task_id="tree_filter_events",
            task_type=TASK_TREE_FILTER_EVENTS,
            dependencies=("build_coarse_process_tree",),
            input_artifacts={
                "raw_log": raw_log_artifact_id,
                "process_tree": "build_coarse_process_tree:process_tree",
            },
            parameters={"grace_seconds": grace_seconds, "write_events": write_events},
            output_names=("tree_filtered_events", "filter_summary"),
            acceptance_criteria=("retained events match a process-tree interval", "summary counters cover all raw events"),
        ),
    )


def run_coarse_task_graph(
    raw_log_path: str | Path,
    work_dir: str | Path,
    sample_id: str,
    sample_hint: str,
    trace_id: str = "trace",
    slice_size: int = 250,
    root_pid: int | None = None,
    grace_seconds: float = 0.5,
    write_events: bool = True,
) -> AnalysisSessionState:
    state = AnalysisSessionState(sample_id=sample_id, work_dir=work_dir)
    state.register_input_artifact("raw_log", "raw_log", raw_log_path)
    specs = build_coarse_task_specs(
        raw_log_artifact_id="raw_log",
        sample_hint=sample_hint,
        trace_id=trace_id,
        slice_size=slice_size,
        root_pid=root_pid,
        grace_seconds=grace_seconds,
        write_events=write_events,
    )
    TaskRunner(coarse_task_handlers(), state).run_all(specs)
    return state


def build_logical_slice_index(context: TaskContext) -> TaskResult:
    log_path = context.input_path("raw_log")
    slice_size = int(context.spec.parameters.get("slice_size") or 250)
    manifest_path = context.store.path_for(context.spec.task_id, "slice_manifest.jsonl")
    summary_path = context.store.path_for(context.spec.task_id, "slice_summary.json")
    slicer = EventCountSlicer(slice_size)
    slice_count = 0
    event_count = 0
    time_start: float | None = None
    time_end: float | None = None
    with log_path.open("r", encoding="utf-8-sig", newline="") as src, manifest_path.open("w", encoding="utf-8") as dst:
        reader = csv.DictReader(src)
        for meta, _events in slicer.iter_slices(reader, source_ref=str(log_path)):
            _validate_slice_meta(meta, expected_start=event_count)
            slice_count += 1
            event_count += meta.event_count
            time_start = meta.time_start if time_start is None else time_start
            time_end = meta.time_end
            dst.write(json.dumps(meta.to_dict(), ensure_ascii=False) + "\n")
    summary = {
        "slice_size": slice_size,
        "slice_count": slice_count,
        "event_count": event_count,
        "time_start": time_start,
        "time_end": time_end,
        "source_ref": str(log_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    artifacts = {
        "slice_manifest": context.store.artifact_ref(context.spec.task_id, "slice_manifest", "slice_manifest", manifest_path, {"slice_count": slice_count}),
        "slice_summary": context.store.artifact_ref(context.spec.task_id, "slice_summary", "slice_summary", summary_path),
    }
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:summary",
        kind="slice_index_summary",
        data=summary,
        source_task_id=context.spec.task_id,
        artifact_ids=tuple(ref.artifact_id for ref in artifacts.values()),
    )
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=summary)


def collect_process_facts(context: TaskContext) -> TaskResult:
    log_path = context.input_path("raw_log")
    manifest_stats = read_slice_manifest_stats(context.input_path("slice_manifest"))
    slice_size = int(context.spec.parameters.get("slice_size") or 250)
    envelopes_path = context.store.path_for(context.spec.task_id, "slice_envelopes.jsonl")
    facts_path = context.store.path_for(context.spec.task_id, "process_facts.jsonl")
    summary_path = context.store.path_for(context.spec.task_id, "fact_summary.json")
    fact_counts: Counter[str] = Counter()
    slice_count = 0
    fact_count = 0
    with envelopes_path.open("w", encoding="utf-8") as envelope_dst, facts_path.open("w", encoding="utf-8") as fact_dst:
        for envelope in iter_csv_slice_envelopes(log_path, slice_size):
            slice_count += 1
            fact_count += len(envelope.facts)
            fact_counts.update(fact.kind for fact in envelope.facts)
            envelope_dst.write(json.dumps(envelope.to_dict(), ensure_ascii=False) + "\n")
            for fact in envelope.facts:
                fact_dst.write(json.dumps(fact.to_dict(), ensure_ascii=False) + "\n")
    if manifest_stats["event_count"] != manifest_stats["expected_event_count"]:
        raise ValueError("slice manifest is internally inconsistent")
    if manifest_stats["slice_count"] != slice_count:
        raise ValueError("process-fact extraction did not reproduce the logical slice count")
    summary = {
        "slice_size": slice_size,
        "slice_count": slice_count,
        "manifest_slice_count": manifest_stats["slice_count"],
        "event_count": manifest_stats["event_count"],
        "fact_count": fact_count,
        "fact_counts": dict(sorted(fact_counts.items())),
        "source_ref": str(log_path),
        "process_facts_path": str(facts_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    artifacts = {
        "slice_envelopes": context.store.artifact_ref(context.spec.task_id, "slice_envelopes", "slice_envelopes", envelopes_path, {"slice_count": slice_count, "fact_count": fact_count}),
        "process_facts": context.store.artifact_ref(context.spec.task_id, "process_facts", "process_facts", facts_path, {"fact_count": fact_count}),
        "fact_summary": context.store.artifact_ref(context.spec.task_id, "fact_summary", "fact_summary", summary_path),
    }
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:summary",
        kind="process_fact_summary",
        data=summary,
        source_task_id=context.spec.task_id,
        artifact_ids=tuple(ref.artifact_id for ref in artifacts.values()),
    )
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=summary)


def build_coarse_process_tree(context: TaskContext) -> TaskResult:
    facts_path = context.input_path("process_facts")
    trace_id = str(context.spec.parameters.get("trace_id") or "trace")
    sample_hint = str(context.spec.parameters.get("sample_hint") or "")
    root_pid = context.spec.parameters.get("root_pid")
    root_pid = int(root_pid) if root_pid is not None else None
    builder = WatchTreeBuilder(trace_id=trace_id, sample_hint=sample_hint, root_pid=root_pid)
    tree = builder.build_from_fact_factory(lambda: iter_process_facts_jsonl(facts_path))
    tree_payload = tree.to_dict()
    tree_hash = builder.tree_hash(tree)
    tree_path = context.store.path_for(context.spec.task_id, "process_tree.json")
    summary_path = context.store.path_for(context.spec.task_id, "tree_summary.json")
    tree_path.write_text(json.dumps(tree_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    summary = {
        "trace_id": trace_id,
        "sample_hint": sample_hint,
        "root_pid": root_pid,
        "tree_hash": tree_hash,
        "root_present": bool(tree.root_nodes),
        "node_count": tree.node_count,
        "slice_count": tree.slice_count,
        "fact_count": tree.fact_count,
        "ignored_fact_count": tree.ignored_fact_count,
        "diagnostics": [diag.to_dict() for diag in tree.diagnostics],
        "attribution": tree_payload.get("attribution", {}),
        "attribution_status": tree_payload.get("attribution", {}).get("status", "unknown"),
        "root_confidence": tree_payload.get("attribution", {}).get("confidence", "unknown"),
        "root_candidate_count": tree_payload.get("attribution", {}).get("candidate_count", 0),
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    artifacts = {
        "process_tree": context.store.artifact_ref(context.spec.task_id, "process_tree", "process_tree", tree_path, {"node_count": tree.node_count, "tree_hash": tree_hash}),
        "tree_summary": context.store.artifact_ref(context.spec.task_id, "tree_summary", "tree_summary", summary_path),
    }
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:summary",
        kind="process_tree_summary",
        data=summary,
        source_task_id=context.spec.task_id,
        artifact_ids=tuple(ref.artifact_id for ref in artifacts.values()),
    )
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=summary)


def tree_filter_events(context: TaskContext) -> TaskResult:
    log_path = context.input_path("raw_log")
    tree_path = context.input_path("process_tree")
    write_events = bool(context.spec.parameters.get("write_events", True))
    grace_seconds = float(context.spec.parameters.get("grace_seconds", 0.5))
    events_path = context.store.path_for(context.spec.task_id, "tree_filtered_events.jsonl")
    summary_path = context.store.path_for(context.spec.task_id, "filter_summary.json")
    summary = filter_csv_by_tree(
        log_path=log_path,
        tree_path=tree_path,
        out_events_path=events_path,
        out_summary_path=summary_path,
        grace_seconds=grace_seconds,
        write_events=write_events,
    )
    artifacts = {
        "filter_summary": context.store.artifact_ref(context.spec.task_id, "filter_summary", "filter_summary", summary_path, {"kept_event_count": summary["kept_event_count"]}),
    }
    if write_events:
        artifacts["tree_filtered_events"] = context.store.artifact_ref(
            context.spec.task_id,
            "tree_filtered_events",
            "tree_filtered_events",
            events_path,
            {"kept_event_count": summary["kept_event_count"]},
        )
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:summary",
        kind="tree_filter_summary",
        data=summary,
        source_task_id=context.spec.task_id,
        artifact_ids=tuple(ref.artifact_id for ref in artifacts.values()),
    )
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=summary)


def read_slice_manifest_stats(path: str | Path) -> dict[str, int]:
    slice_count = 0
    event_count = 0
    expected_start = 0
    with Path(path).open("r", encoding="utf-8") as src:
        for line in src:
            if not line.strip():
                continue
            meta = json.loads(line)
            if int(meta["event_start"]) != expected_start:
                raise ValueError(f"non-contiguous slice manifest at {meta['slice_id']}")
            slice_count += 1
            event_count += int(meta["event_count"])
            expected_start = int(meta["event_end"]) + 1
    return {"slice_count": slice_count, "event_count": event_count, "expected_event_count": expected_start}


def iter_slice_envelopes_jsonl(path: str | Path):
    with Path(path).open("r", encoding="utf-8") as src:
        for line in src:
            if line.strip():
                yield slice_envelope_from_dict(json.loads(line))


def iter_process_facts_jsonl(path: str | Path):
    with Path(path).open("r", encoding="utf-8") as src:
        for line in src:
            if line.strip():
                yield process_fact_from_dict(json.loads(line))


def process_fact_from_dict(item: dict[str, Any]) -> ProcessFact:
    return ProcessFact(
        fact_id=item["fact_id"],
        kind=item["kind"],
        slice_id=item["slice_id"],
        event_index=int(item["event_index"]),
        time=float(item["time"]),
        pid=int(item.get("pid") or 0),
        process_name=item.get("process_name", ""),
        operation=item.get("operation", ""),
        parent_pid=int(item.get("parent_pid") or 0),
        child_pid=int(item.get("child_pid") or 0),
        child_name=item.get("child_name", ""),
        child_path=item.get("child_path", ""),
        result=item.get("result", ""),
        parent_pid_conflict=bool(item.get("parent_pid_conflict", False)),
        parent_pid_candidates=tuple(int(pid) for pid in item.get("parent_pid_candidates") or ()),
        source_event_ids=tuple(item.get("source_event_ids") or ()),
        source=item.get("source", ""),
    )


def slice_envelope_from_dict(data: dict[str, Any]) -> SliceEnvelope:
    meta = SliceMeta(**data["meta"])
    facts = tuple(ProcessFact(
        fact_id=item["fact_id"],
        kind=item["kind"],
        slice_id=item["slice_id"],
        event_index=int(item["event_index"]),
        time=float(item["time"]),
        pid=int(item.get("pid") or 0),
        process_name=item.get("process_name", ""),
        operation=item.get("operation", ""),
        parent_pid=int(item.get("parent_pid") or 0),
        child_pid=int(item.get("child_pid") or 0),
        child_name=item.get("child_name", ""),
        child_path=item.get("child_path", ""),
        result=item.get("result", ""),
        parent_pid_conflict=bool(item.get("parent_pid_conflict", False)),
        parent_pid_candidates=tuple(int(pid) for pid in item.get("parent_pid_candidates") or ()),
        source_event_ids=tuple(item.get("source_event_ids") or ()),
        source=item.get("source", ""),
    ) for item in data.get("facts", ()))
    return SliceEnvelope(meta=meta, facts=facts)


def _validate_slice_meta(meta: SliceMeta, expected_start: int) -> None:
    if meta.event_count <= 0:
        raise ValueError(f"empty slice is invalid: {meta.slice_id}")
    if meta.event_start != expected_start:
        raise ValueError(f"non-contiguous slice {meta.slice_id}: expected start {expected_start}, got {meta.event_start}")
    if meta.event_end < meta.event_start:
        raise ValueError(f"invalid event range for {meta.slice_id}")

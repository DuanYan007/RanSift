"""Load validated behavior catalogs and register their artifacts with an analysis session."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.behavior.catalog import BEHAVIOR_CATALOG_SCHEMA, TRACE_CHECKPOINT_SCHEMA
from harness.tasks.models import AnalysisSessionState, ArtifactRef, SessionFact, TaskResult


BEHAVIOR_STAGE_SCHEMA = "harness-behavior-stage-v1"
TRACE_STAGE_SCHEMA = "harness-trace-stage-v1"
TRACE_SUMMARY_SCHEMA = "harness-behavior-trace-summary-v1"


class BehaviorSnapshotError(ValueError):
    """Raised when a sealed behavior snapshot cannot be consumed safely."""


@dataclass(frozen=True)
class BehaviorSnapshotSample:
    snapshot_root: Path
    snapshot_id: str
    snapshot_metadata_sha256: str
    snapshot_manifest_sha256: str
    sample_key: str
    trace_snapshot_root: Path
    trace_snapshot_id: str
    trace_metadata_sha256: str
    trace_manifest_sha256: str
    trace_path: Path
    trace_summary_path: Path
    catalog_path: Path
    phase_blocks_path: Path
    checkpoints_path: Path
    trace_summary: dict[str, Any]
    catalog: dict[str, Any]
    manifest_record: dict[str, Any]

    @property
    def event_count(self) -> int:
        return int(self.catalog.get("event_count") or 0)

    def provenance(self) -> dict[str, Any]:
        artifacts = dict(self.manifest_record.get("artifacts") or {})
        return {
            "mode": "sealed_behavior_snapshot",
            "snapshot_id": self.snapshot_id,
            "snapshot_path": str(self.snapshot_root),
            "snapshot_metadata_sha256": self.snapshot_metadata_sha256,
            "snapshot_manifest_sha256": self.snapshot_manifest_sha256,
            "sample_key": self.sample_key,
            "trace_snapshot_id": self.trace_snapshot_id,
            "trace_snapshot_path": str(self.trace_snapshot_root),
            "trace_metadata_sha256": self.trace_metadata_sha256,
            "trace_manifest_sha256": self.trace_manifest_sha256,
            "catalog_sha256": str(artifacts.get("catalog_sha256") or ""),
            "phase_blocks_sha256": str(artifacts.get("phase_blocks_sha256") or ""),
            "checkpoints_sha256": str(artifacts.get("checkpoints_sha256") or ""),
            "trace_sha256": str((self.manifest_record.get("upstream") or {}).get("trace_sha256") or ""),
            "event_count": self.event_count,
        }


def load_behavior_snapshot_sample(
    snapshot_path: str | Path,
    sample_key: str,
    *,
    verify_artifacts: bool = True,
) -> BehaviorSnapshotSample:
    """Load one sealed snapshot record without hashing the large trace again.

    The trace digest was verified during snapshot sealing.  Rehashing it for
    every LLM run would defeat the point of staged reuse, so this consumer
    checks its immutable manifest linkage and current byte size instead.
    Compact catalog artifacts are verified directly before use.
    """

    root = Path(snapshot_path).resolve()
    metadata_path = root / "snapshot.json"
    manifest_path = root / "manifest.jsonl"
    metadata = load_json_object(metadata_path)
    if (
        metadata.get("schema_version") != BEHAVIOR_STAGE_SCHEMA
        or metadata.get("stage") != "04_behavior"
        or metadata.get("state") != "sealed"
    ):
        raise BehaviorSnapshotError(f"behavior snapshot is not sealed: {root}")
    snapshot_id = required_text(metadata.get("snapshot_id"), "snapshot_id")
    records = load_jsonl(manifest_path)
    if int(metadata.get("source_sample_count") or 0) != len(records):
        raise BehaviorSnapshotError("behavior snapshot manifest count is inconsistent")
    record = unique_record(records, sample_key, stage="04_behavior", schema=BEHAVIOR_STAGE_SCHEMA)

    trace_snapshot_id = required_text(metadata.get("trace_snapshot_id"), "trace_snapshot_id")
    upstream = dict(record.get("upstream") or {})
    if str(upstream.get("trace_snapshot_id") or "") != trace_snapshot_id:
        raise BehaviorSnapshotError("behavior record points to a different trace snapshot")
    trace_root = root.parents[1] / "03_trace" / trace_snapshot_id
    trace_metadata_path = trace_root / "snapshot.json"
    trace_manifest_path = trace_root / "manifest.jsonl"
    trace_metadata = load_json_object(trace_metadata_path)
    if (
        trace_metadata.get("schema_version") != TRACE_STAGE_SCHEMA
        or trace_metadata.get("stage") != "03_trace"
        or trace_metadata.get("state") != "sealed"
    ):
        raise BehaviorSnapshotError(f"linked trace snapshot is not sealed: {trace_root}")
    trace_records = load_jsonl(trace_manifest_path)
    if int(trace_metadata.get("source_sample_count") or 0) != len(trace_records):
        raise BehaviorSnapshotError("trace snapshot manifest count is inconsistent")
    trace_record = unique_record(trace_records, sample_key, stage="03_trace", schema=TRACE_STAGE_SCHEMA)

    trace_artifacts = dict(trace_record.get("artifacts") or {})
    behavior_artifacts = dict(record.get("artifacts") or {})
    trace_path = snapshot_child(trace_root, required_text(trace_artifacts.get("trace_relative_path"), "trace_relative_path"))
    trace_summary_path = snapshot_child(trace_root, required_text(trace_artifacts.get("summary_relative_path"), "summary_relative_path"))
    catalog_path = snapshot_child(root, required_text(behavior_artifacts.get("catalog_relative_path"), "catalog_relative_path"))
    phase_blocks_path = snapshot_child(root, required_text(behavior_artifacts.get("phase_blocks_relative_path"), "phase_blocks_relative_path"))
    checkpoints_path = snapshot_child(root, required_text(behavior_artifacts.get("checkpoints_relative_path"), "checkpoints_relative_path"))
    require_file(trace_path, "trace")
    require_file(trace_summary_path, "trace summary")
    require_file(catalog_path, "behavior catalog")
    require_file(phase_blocks_path, "phase blocks")
    require_file(checkpoints_path, "trace checkpoints")
    require_size(trace_path, trace_artifacts.get("trace_size_bytes"), "trace")
    require_size(catalog_path, behavior_artifacts.get("catalog_size_bytes"), "behavior catalog")
    require_size(phase_blocks_path, behavior_artifacts.get("phase_blocks_size_bytes"), "phase blocks")
    require_size(checkpoints_path, behavior_artifacts.get("checkpoints_size_bytes"), "trace checkpoints")
    if verify_artifacts:
        require_sha256(catalog_path, behavior_artifacts.get("catalog_sha256"), "behavior catalog")
        require_sha256(phase_blocks_path, behavior_artifacts.get("phase_blocks_sha256"), "phase blocks")
        require_sha256(checkpoints_path, behavior_artifacts.get("checkpoints_sha256"), "trace checkpoints")

    trace_summary = load_json_object(trace_summary_path)
    if trace_summary.get("schema_version") != TRACE_SUMMARY_SCHEMA:
        raise BehaviorSnapshotError("trace summary schema is incompatible")
    catalog = load_json_object(catalog_path)
    checkpoints = load_json_object(checkpoints_path)
    validate_catalog_contract(
        catalog=catalog,
        checkpoints=checkpoints,
        record=record,
        trace_record=trace_record,
        trace_path=trace_path,
        phase_blocks_path=phase_blocks_path,
    )
    return BehaviorSnapshotSample(
        snapshot_root=root,
        snapshot_id=snapshot_id,
        snapshot_metadata_sha256=sha256_file(metadata_path),
        snapshot_manifest_sha256=sha256_file(manifest_path),
        sample_key=sample_key,
        trace_snapshot_root=trace_root,
        trace_snapshot_id=trace_snapshot_id,
        trace_metadata_sha256=sha256_file(trace_metadata_path),
        trace_manifest_sha256=sha256_file(trace_manifest_path),
        trace_path=trace_path,
        trace_summary_path=trace_summary_path,
        catalog_path=catalog_path,
        phase_blocks_path=phase_blocks_path,
        checkpoints_path=checkpoints_path,
        trace_summary=trace_summary,
        catalog=catalog,
        manifest_record=record,
    )


def hydrate_behavior_snapshot(state: AnalysisSessionState, snapshot: BehaviorSnapshotSample) -> tuple[str, ...]:
    """Register the trace and catalog as completed evidence-preparation tasks."""

    task_ids = (
        "normalize_behavior_trace",
        "build_behavior_index",
        "build_behavior_blocks",
    )
    duplicate = [task_id for task_id in task_ids if task_id in state.task_results]
    if duplicate:
        raise BehaviorSnapshotError(f"session already has behavior task results: {duplicate}")
    provenance = snapshot.provenance()
    trace_summary = compact_trace_summary(snapshot.trace_summary, snapshot)
    catalog_summary = compact_catalog_summary(snapshot.catalog, snapshot)
    phase_summary = compact_phase_summary(snapshot.catalog, snapshot)
    block_representation = 'hierarchical_fragments' if snapshot.catalog.get('hierarchical_fragments') else 'phase_blocks'
    trace_artifacts = {
        "behavior_trace": artifact(
            "normalize_behavior_trace", "behavior_trace", "behavior_trace", snapshot.trace_path,
            {"event_count": snapshot.event_count, "snapshot": provenance},
        ),
        "behavior_trace_meta": artifact(
            "normalize_behavior_trace", "behavior_trace_meta", "behavior_trace_meta", snapshot.trace_summary_path,
            {"snapshot": provenance},
        ),
    }
    index_artifacts = {
        "behavior_index": artifact(
            "build_behavior_index", "behavior_index", "behavior_index", snapshot.catalog_path,
            {
                "event_count": snapshot.event_count,
                "representation": "behavior_catalog",
                "catalog_mode": True,
                "trace_checkpoints_path": str(snapshot.checkpoints_path),
                "phase_blocks_path": str(snapshot.phase_blocks_path),
                "snapshot": provenance,
            },
        ),
        "behavior_index_meta": artifact(
            "build_behavior_index", "behavior_index_meta", "behavior_index_meta", snapshot.catalog_path,
            {"representation": "behavior_catalog", "snapshot": provenance},
        ),
        "behavior_trace_checkpoints": artifact(
            "build_behavior_index", "behavior_trace_checkpoints", "behavior_trace_checkpoints", snapshot.checkpoints_path,
            {"snapshot": provenance},
        ),
    }
    block_artifacts = {
        "behavior_blocks": artifact(
            "build_behavior_blocks", "behavior_blocks", "behavior_blocks", snapshot.phase_blocks_path,
            {"representation": block_representation, "catalog_mode": True, "snapshot": provenance},
        ),
        "behavior_blocks_meta": artifact(
            "build_behavior_blocks", "behavior_blocks_meta", "behavior_blocks_meta", snapshot.catalog_path,
            {"representation": block_representation, "snapshot": provenance},
        ),
    }
    state.commit(TaskResult.completed(
        "normalize_behavior_trace",
        artifacts=trace_artifacts,
        facts=(SessionFact(
            fact_id="normalize_behavior_trace:summary",
            kind="behavior_trace_summary",
            data=trace_summary,
            source_task_id="normalize_behavior_trace",
            artifact_ids=tuple(ref.artifact_id for ref in trace_artifacts.values()),
        ),),
        diagnostics=trace_summary,
    ))
    state.commit(TaskResult.completed(
        "build_behavior_index",
        artifacts=index_artifacts,
        facts=(SessionFact(
            fact_id="build_behavior_index:summary",
            kind="behavior_index_summary",
            data=catalog_summary,
            source_task_id="build_behavior_index",
            artifact_ids=tuple(ref.artifact_id for ref in index_artifacts.values()),
        ),),
        diagnostics=catalog_summary,
    ))
    state.commit(TaskResult.completed(
        "build_behavior_blocks",
        artifacts=block_artifacts,
        facts=(SessionFact(
            fact_id="build_behavior_blocks:summary",
            kind="behavior_block_summary",
            data=phase_summary,
            source_task_id="build_behavior_blocks",
            artifact_ids=tuple(ref.artifact_id for ref in block_artifacts.values()),
        ),),
        diagnostics=phase_summary,
    ))
    return task_ids


def artifact(task_id: str, name: str, kind: str, path: Path, metadata: dict[str, Any]) -> ArtifactRef:
    return ArtifactRef(
        artifact_id=f"{task_id}:{name}",
        kind=kind,
        path=str(path),
        producer_task_id=task_id,
        metadata=metadata,
    )


def compact_trace_summary(summary: dict[str, Any], snapshot: BehaviorSnapshotSample) -> dict[str, Any]:
    result = dict(summary)
    result.update({
        "source": "sealed_behavior_snapshot",
        "snapshot": snapshot.provenance(),
        "trace_path": str(snapshot.trace_path),
        "event_count": snapshot.event_count,
    })
    return result


def compact_catalog_summary(catalog: dict[str, Any], snapshot: BehaviorSnapshotSample) -> dict[str, Any]:
    indexes = dict(catalog.get("indexes") or {})
    return {
        "schema_version": "behavior-catalog-summary-v1",
        "source": "sealed_behavior_snapshot",
        "snapshot": snapshot.provenance(),
        "event_count": snapshot.event_count,
        "index_names": sorted(indexes),
        "retained_key_count": sum(int((entry or {}).get("retained_key_count") or 0) for entry in indexes.values()),
        "omitted_index_event_observations": sum(int((entry or {}).get("omitted_event_observations") or 0) for entry in indexes.values()),
        "limitations": list(catalog.get("limitations") or ()),
    }


def compact_phase_summary(catalog: dict[str, Any], snapshot: BehaviorSnapshotSample) -> dict[str, Any]:
    hierarchy = catalog.get('hierarchical_fragments')
    if hierarchy:
        return {'schema_version': 'behavior-fragment-summary-v1',
                'source': 'sealed_behavior_snapshot', 'snapshot': snapshot.provenance(),
                'event_count': hierarchy['event_count'],
                'micro_block_count': hierarchy['micro']['count'],
                'macro_block_count': hierarchy['macro']['count'],
                'parameters': hierarchy['parameters'],
                'by_behavior_kind': hierarchy['macro']['by_behavior_kind'],
                'limitations': ['Macro fragments aggregate same-process micro fragments; temporal order alone does not establish causality.']}
    phases = dict(catalog.get("phase_blocks") or {})
    return {
        "schema_version": "behavior-phase-block-summary-v1",
        "source": "sealed_behavior_snapshot",
        "snapshot": snapshot.provenance(),
        "phase_block_count": int(phases.get("count") or 0),
        "event_count": int(phases.get("event_count") or 0),
        "by_behavior_kind": dict(phases.get("by_behavior_kind") or {}),
        "by_category": dict(phases.get("by_category") or {}),
        "limitations": [
            "phase blocks are compact descriptive units with bounded representative offsets",
        ],
    }


def validate_catalog_contract(
    *,
    catalog: dict[str, Any],
    checkpoints: dict[str, Any],
    record: dict[str, Any],
    trace_record: dict[str, Any],
    trace_path: Path,
    phase_blocks_path: Path,
) -> None:
    if catalog.get("schema_version") != BEHAVIOR_CATALOG_SCHEMA:
        raise BehaviorSnapshotError("behavior catalog schema is incompatible")
    if checkpoints.get("schema_version") != TRACE_CHECKPOINT_SCHEMA:
        raise BehaviorSnapshotError("trace checkpoint schema is incompatible")
    expected_events = int((trace_record.get("summary") or {}).get("event_count") or -1)
    if int(catalog.get("event_count") or -2) != expected_events:
        raise BehaviorSnapshotError("catalog event count does not match trace manifest")
    if int(checkpoints.get("event_count") or -3) != expected_events:
        raise BehaviorSnapshotError("checkpoint event count does not match trace manifest")
    if int(checkpoints.get("trace_size_bytes") or -4) != trace_path.stat().st_size:
        raise BehaviorSnapshotError("checkpoint trace size does not match trace artifact")
    upstream = dict(record.get("upstream") or {})
    trace_artifacts = dict(trace_record.get("artifacts") or {})
    if str(upstream.get("trace_sha256") or "") != str(trace_artifacts.get("trace_sha256") or ""):
        raise BehaviorSnapshotError("behavior and trace manifest digests disagree")
    catalog_upstream = dict(catalog.get("upstream") or {})
    if str(catalog_upstream.get("trace_sha256") or "") != str(upstream.get("trace_sha256") or ""):
        raise BehaviorSnapshotError("catalog and behavior manifest digests disagree")
    phases = dict(catalog.get("phase_blocks") or {})
    artifacts = dict(record.get("artifacts") or {})
    if int(phases.get("size_bytes") or -1) != phase_blocks_path.stat().st_size:
        raise BehaviorSnapshotError("catalog phase-block size does not match artifact")
    if str(phases.get("sha256") or "") != str(artifacts.get("phase_blocks_sha256") or ""):
        raise BehaviorSnapshotError("catalog phase-block digest does not match manifest")
    if str((catalog.get("integrity") or {}).get("status") or "") != "pass":
        raise BehaviorSnapshotError("behavior catalog integrity check did not pass")


def unique_record(records: list[dict[str, Any]], sample_key: str, *, stage: str, schema: str) -> dict[str, Any]:
    matches = [record for record in records if str(record.get("sample_key") or "") == sample_key]
    if len(matches) != 1:
        raise BehaviorSnapshotError(f"snapshot has no unique record for sample_key={sample_key!r}")
    record = matches[0]
    if record.get("schema_version") != schema or record.get("stage") != stage or record.get("status") != "sealed":
        raise BehaviorSnapshotError(f"snapshot record is not sealed: {sample_key}")
    return record


def snapshot_child(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve()
    if root != candidate and root not in candidate.parents:
        raise BehaviorSnapshotError(f"snapshot artifact escapes root: {relative_path!r}")
    return candidate


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise BehaviorSnapshotError(f"{label} is unavailable: {path}")


def require_size(path: Path, expected: Any, label: str) -> None:
    try:
        value = int(expected)
    except (TypeError, ValueError) as exc:
        raise BehaviorSnapshotError(f"{label} has no valid expected size") from exc
    if path.stat().st_size != value:
        raise BehaviorSnapshotError(f"{label} size changed: {path}")


def require_sha256(path: Path, expected: Any, label: str) -> None:
    expected_text = str(expected or "")
    if not expected_text or sha256_file(path) != expected_text:
        raise BehaviorSnapshotError(f"{label} digest changed: {path}")


def required_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise BehaviorSnapshotError(f"missing {label}")
    return text


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BehaviorSnapshotError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BehaviorSnapshotError(f"expected JSON object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise BehaviorSnapshotError(f"non-object JSONL row at {path}:{line_number}")
                rows.append(row)
    except OSError as exc:
        raise BehaviorSnapshotError(f"could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BehaviorSnapshotError(f"invalid JSONL at {path}: {exc}") from exc
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

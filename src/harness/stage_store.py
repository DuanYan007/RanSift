"""Validation and reuse of deterministic preprocessing artifacts."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from harness.tasks.models import AnalysisSessionState, ArtifactRef, SessionFact, TaskResult, TaskSpec


STAGE_BUNDLE_SCHEMA = "harness-stage-bundle-v1"
STAGE_CHECKPOINT_RETENTION = "harness-stage-checkpoint-v2"
STAGE_ASSET_ID_PREFIX = "stage"
STAGE_TASK_IDS = (
    "build_logical_slice_index",
    "collect_process_facts",
    "build_coarse_process_tree",
    "tree_filter_events",
    "normalize_behavior_trace",
    "build_behavior_index",
    "build_behavior_blocks",
)
DEFAULT_BEHAVIOR_PARAMETERS = {
    "time_bucket_seconds": 1.0,
    "micro_time_gap_s": 2.0,
    "micro_order_gap": 25,
    "macro_time_gap_s": 10.0,
    "macro_order_gap": 250,
}
# Keep only artifacts needed by later stages, evidence agents, or compact audit.
# The omitted first-layer streams are reproducible from the raw log and tree,
# but consume hundreds of megabytes per sample when retained indefinitely.
STAGE_CHECKPOINT_ARTIFACTS = {
    "build_logical_slice_index": frozenset({"slice_manifest", "slice_summary"}),
    "collect_process_facts": frozenset({"fact_summary"}),
    "build_coarse_process_tree": frozenset({"process_tree", "tree_summary"}),
    "tree_filter_events": frozenset({"filter_summary"}),
    "normalize_behavior_trace": frozenset({"behavior_trace", "behavior_trace_meta"}),
    "build_behavior_index": frozenset({"behavior_index", "behavior_index_meta", "index_audit"}),
    "build_behavior_blocks": frozenset({"behavior_blocks", "behavior_blocks_meta"}),
}


class StageBundleError(ValueError):
    """Raised when a deterministic stage bundle is incomplete or incompatible."""


def build_stage_parameters(
    *,
    sample_hint: str,
    slice_size: int,
    root_pid: int | None,
    grace_seconds: float,
    write_events: bool,
    behavior_parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    behavior = dict(DEFAULT_BEHAVIOR_PARAMETERS)
    behavior.update(dict(behavior_parameters or {}))
    return {
        "sample_hint": str(sample_hint),
        "slice_size": int(slice_size),
        "root_pid": int(root_pid) if root_pid is not None else None,
        "grace_seconds": float(grace_seconds),
        "write_events": bool(write_events),
        "behavior": {
            "time_bucket_seconds": float(behavior["time_bucket_seconds"]),
            "micro_time_gap_s": float(behavior["micro_time_gap_s"]),
            "micro_order_gap": int(behavior["micro_order_gap"]),
            "macro_time_gap_s": float(behavior["macro_time_gap_s"]),
            "macro_order_gap": int(behavior["macro_order_gap"]),
        },
    }


def stage_parameters_from_specs(specs: Iterable[TaskSpec]) -> dict[str, Any]:
    by_id = {spec.task_id: spec for spec in specs}
    missing = [task_id for task_id in STAGE_TASK_IDS if task_id not in by_id]
    if missing:
        raise StageBundleError(f"stage task specifications are incomplete: {missing}")
    slice_spec = by_id["build_logical_slice_index"]
    tree_spec = by_id["build_coarse_process_tree"]
    filter_spec = by_id["tree_filter_events"]
    index_spec = by_id["build_behavior_index"]
    blocks_spec = by_id["build_behavior_blocks"]
    behavior = {
        "time_bucket_seconds": index_spec.parameters.get("time_bucket_seconds", 1.0),
        "micro_time_gap_s": blocks_spec.parameters.get("micro_time_gap_s", 2.0),
        "micro_order_gap": blocks_spec.parameters.get("micro_order_gap", 25),
        "macro_time_gap_s": blocks_spec.parameters.get("macro_time_gap_s", 10.0),
        "macro_order_gap": blocks_spec.parameters.get("macro_order_gap", 250),
    }
    grace_seconds = filter_spec.parameters.get("grace_seconds")
    return build_stage_parameters(
        sample_hint=str(tree_spec.parameters.get("sample_hint") or ""),
        slice_size=int(slice_spec.parameters.get("slice_size") or 250),
        root_pid=optional_int(tree_spec.parameters.get("root_pid")),
        grace_seconds=float(0.5 if grace_seconds is None else grace_seconds),
        write_events=bool(filter_spec.parameters.get("write_events", True)),
        behavior_parameters=behavior,
    )


def file_fingerprint(path: str | Path) -> dict[str, Any]:
    source = Path(path).resolve()
    if not source.is_file():
        raise StageBundleError(f"stage source file does not exist: {source}")
    stat = source.stat()
    return {
        "resolved_path": str(source),
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def stage_asset_id(
    *,
    raw_log_path: str | Path,
    parameters: dict[str, Any],
    harness_root: str | Path | None = None,
) -> str:
    """Return the content-addressed identifier for one deterministic stage asset.

    The identifier intentionally covers the raw-log metadata, all deterministic
    stage parameters, and the implementation digest. LLM role profiles and
    static-evidence inputs are excluded because they do not affect these stages.
    """

    identity = {
        "schema_version": STAGE_BUNDLE_SCHEMA,
        "source": {"raw_log": file_fingerprint(raw_log_path)},
        "parameters": normalize_stage_parameters(parameters),
        "deterministic_source_digest": deterministic_source_digest(harness_root),
    }
    digest = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{STAGE_ASSET_ID_PREFIX}-{digest[:20]}"


def deterministic_source_digest(harness_root: str | Path | None = None) -> str:
    package_root = Path(__file__).resolve().parents[2]
    requested_root = Path(harness_root) if harness_root is not None else package_root
    # Tests and embedding callers may use a temporary output root. The digest
    # must still describe the installed Harness implementation.
    root = requested_root if (requested_root / "src" / "harness").is_dir() else package_root
    source_root = root / "src" / "harness"
    fixed = (
        source_root / "tasks" / "coarse.py",
        source_root / "tasks" / "behavior.py",
        source_root / "behavior" / "parser.py",
        source_root / "behavior" / "classification.py",
        source_root / "behavior" / "blocks.py",
        source_root / "behavior" / "index.py",
        source_root / "behavior" / "models.py",
    )
    paths = [path for path in fixed if path.is_file()]
    coarse_root = source_root / "coarse"
    if coarse_root.is_dir():
        paths.extend(sorted(coarse_root.rglob("*.py")))
    if not paths:
        raise StageBundleError(f"could not locate deterministic Harness sources below {source_root}")
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def build_stage_bundle_payload(
    *,
    bundle_id: str,
    state: AnalysisSessionState,
    raw_log_path: str | Path,
    parameters: dict[str, Any],
    harness_root: str | Path | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    completed_results: dict[str, TaskResult] = {}
    for task_id in STAGE_TASK_IDS:
        result = state.task_results.get(task_id)
        if result is None or result.status != "completed":
            raise StageBundleError(f"cannot export incomplete deterministic stage: {task_id}")
        validate_result_artifacts(task_id, result)
        completed_results[task_id] = result
    transient_paths = transient_stage_artifact_paths(completed_results.values())
    stage_results = {
        task_id: compact_stage_task_result(
            task_id,
            result,
            transient_paths=transient_paths,
        )
        for task_id, result in completed_results.items()
    }
    return {
        "schema_version": STAGE_BUNDLE_SCHEMA,
        "artifact_retention": STAGE_CHECKPOINT_RETENTION,
        "bundle_id": required_text(bundle_id, "bundle_id"),
        "created_at_utc": utc_now(),
        "source": {"raw_log": file_fingerprint(raw_log_path)},
        "parameters": normalize_stage_parameters(parameters),
        "deterministic_source_digest": deterministic_source_digest(harness_root),
        "stage_task_results": stage_results,
        "provenance": dict(provenance or {}),
    }


def compact_stage_task_result(
    task_id: str,
    result: TaskResult,
    *,
    transient_paths: set[str] | None = None,
) -> dict[str, Any]:
    """Convert a completed stage result into its small reusable checkpoint."""
    retained_names = STAGE_CHECKPOINT_ARTIFACTS.get(task_id)
    if retained_names is None:
        raise StageBundleError(f"unknown deterministic stage task: {task_id}")
    artifacts = {
        name: ref.to_dict()
        for name, ref in result.artifacts.items()
        if name in retained_names
    }
    if not artifacts:
        raise StageBundleError(f"stage checkpoint has no retained artifact: {task_id}")
    retained_ids = {str(ref["artifact_id"]) for ref in artifacts.values()}
    transient_paths = set(transient_paths or ())
    transient_paths.update(
        str(ref.path)
        for name, ref in result.artifacts.items()
        if name not in retained_names
    )
    facts = []
    for fact in result.facts:
        serialized = fact.to_dict()
        serialized["artifact_ids"] = [
            artifact_id
            for artifact_id in serialized.get("artifact_ids") or []
            if artifact_id in retained_ids
        ]
        serialized["data"] = drop_transient_paths(serialized.get("data") or {}, transient_paths)
        facts.append(serialized)
    return {
        "task_id": result.task_id,
        "status": result.status,
        "artifacts": artifacts,
        "facts": facts,
        "diagnostics": drop_transient_paths(dict(result.diagnostics), transient_paths),
        "error": result.error,
    }


def transient_stage_artifact_paths(results: Iterable[TaskResult]) -> set[str]:
    """Return all stage artifact paths that the checkpoint policy deliberately drops."""
    paths: set[str] = set()
    for result in results:
        retained_names = STAGE_CHECKPOINT_ARTIFACTS.get(result.task_id)
        if retained_names is None:
            raise StageBundleError(f"unknown deterministic stage task: {result.task_id}")
        paths.update(
            str(ref.path)
            for name, ref in result.artifacts.items()
            if name not in retained_names
        )
    return paths


def drop_transient_paths(value: Any, transient_paths: set[str]) -> Any:
    """Remove stale path fields from compact checkpoint metadata and facts."""
    if isinstance(value, dict):
        return {
            str(key): drop_transient_paths(item, transient_paths)
            for key, item in value.items()
            if not (isinstance(item, str) and item in transient_paths)
        }
    if isinstance(value, list):
        return [
            drop_transient_paths(item, transient_paths)
            for item in value
            if not (isinstance(item, str) and item in transient_paths)
        ]
    return value


def is_checkpoint_stage_bundle(payload: dict[str, Any]) -> bool:
    """Return whether a bundle uses the compact artifact-retention contract."""
    return payload.get("artifact_retention") == STAGE_CHECKPOINT_RETENTION


def compact_exported_stage_state(
    state: AnalysisSessionState,
    payload: dict[str, Any],
) -> tuple[Path, ...]:
    """Replace in-memory stage results with bundle checkpoints and delete only transient files.

    This is used by the dedicated stage-asset builder after export. Generic
    session exports may retain their full local work directory for debugging.
    """
    validate_stage_bundle_structure(payload)
    compact_results: dict[str, TaskResult] = {}
    removable_paths: list[Path] = []
    for task_id in STAGE_TASK_IDS:
        original = state.task_results.get(task_id)
        if original is None or original.status != "completed":
            raise StageBundleError(f"cannot compact incomplete stage result: {task_id}")
        compact = task_result_from_dict(payload["stage_task_results"][task_id])
        retained_ids = {ref.artifact_id for ref in compact.artifacts.values()}
        removable_paths.extend(
            Path(ref.path)
            for ref in original.artifacts.values()
            if ref.artifact_id not in retained_ids
        )
        compact_results[task_id] = compact

    for task_id, compact in compact_results.items():
        original = state.task_results[task_id]
        for ref in original.artifacts.values():
            if ref.artifact_id not in {item.artifact_id for item in compact.artifacts.values()}:
                state.artifacts.pop(ref.artifact_id, None)
        for ref in compact.artifacts.values():
            state.artifacts[ref.artifact_id] = ref
        state.task_results[task_id] = compact

    replacement_facts = {task_id: result.facts for task_id, result in compact_results.items()}
    rewritten_facts: list[SessionFact] = []
    emitted: set[str] = set()
    for fact in state.facts:
        task_id = fact.source_task_id
        if task_id not in replacement_facts:
            rewritten_facts.append(fact)
            continue
        if task_id not in emitted:
            rewritten_facts.extend(replacement_facts[task_id])
            emitted.add(task_id)
    for task_id in STAGE_TASK_IDS:
        if task_id not in emitted:
            rewritten_facts.extend(replacement_facts[task_id])
    state.facts = rewritten_facts

    removed = []
    for path in dict.fromkeys(removable_paths):
        if path.is_file():
            path.unlink()
            removed.append(path)
    return tuple(removed)


def write_stage_bundle(path: str | Path, payload: dict[str, Any]) -> Path:
    target = Path(path)
    validate_stage_bundle_structure(payload)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(target)
    return target


def load_stage_bundle(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageBundleError(f"could not read stage bundle {source}: {exc}") from exc
    validate_stage_bundle_structure(payload)
    return payload


def validate_stage_bundle(
    payload: dict[str, Any],
    *,
    raw_log_path: str | Path,
    parameters: dict[str, Any],
    harness_root: str | Path | None = None,
) -> None:
    validate_stage_bundle_structure(payload)
    expected_source = file_fingerprint(raw_log_path)
    bundle_source = dict(payload["source"]["raw_log"])
    for key in ("size_bytes", "mtime_ns"):
        if bundle_source.get(key) != expected_source.get(key):
            raise StageBundleError(
                f"stage bundle raw-log fingerprint mismatch for {key}: "
                f"{bundle_source.get(key)!r} != {expected_source.get(key)!r}"
            )
    if normalize_stage_parameters(payload["parameters"]) != normalize_stage_parameters(parameters):
        raise StageBundleError("stage bundle parameters do not match the requested deterministic stages")
    current_digest = deterministic_source_digest(harness_root)
    if payload.get("deterministic_source_digest") != current_digest:
        raise StageBundleError("stage bundle deterministic source digest is not current")
    for task_id, raw_result in payload["stage_task_results"].items():
        validate_result_artifacts(task_id, task_result_from_dict(raw_result))


def hydrate_stage_bundle(state: AnalysisSessionState, payload: dict[str, Any]) -> tuple[str, ...]:
    validate_stage_bundle_structure(payload)
    hydrated = []
    for task_id in STAGE_TASK_IDS:
        if task_id in state.task_results:
            raise StageBundleError(f"session already has a result for staged task {task_id}")
        result = task_result_from_dict(payload["stage_task_results"][task_id])
        validate_result_artifacts(task_id, result)
        state.commit(result)
        hydrated.append(task_id)
    return tuple(hydrated)


def bundle_summary(payload: dict[str, Any], path: str | Path) -> dict[str, Any]:
    return {
        "bundle_id": str(payload["bundle_id"]),
        "bundle_path": str(Path(path).resolve()),
        "deterministic_source_digest": str(payload["deterministic_source_digest"]),
        "artifact_retention": str(payload.get("artifact_retention") or "legacy_full"),
        "stage_task_ids": list(STAGE_TASK_IDS),
        "raw_log": dict(payload["source"]["raw_log"]),
        "parameters": normalize_stage_parameters(payload["parameters"]),
    }


def stage_bundle_from_session_payload(
    *,
    bundle_id: str,
    session_state: dict[str, Any],
    input_manifest: dict[str, Any],
    config_snapshot: dict[str, Any],
    harness_root: str | Path | None = None,
    adopt_current_source: bool = False,
) -> dict[str, Any]:
    stage_results = {
        task_id: dict((session_state.get("task_results") or {}).get(task_id) or {})
        for task_id in STAGE_TASK_IDS
    }
    parsed_stage_results: dict[str, TaskResult] = {}
    for task_id, raw_result in stage_results.items():
        if not raw_result:
            raise StageBundleError(f"session state lacks staged task result: {task_id}")
        result = task_result_from_dict(raw_result)
        if result.status != "completed":
            raise StageBundleError(f"session staged task is not complete: {task_id}")
        validate_result_artifacts(task_id, result)
        parsed_stage_results[task_id] = result
    specs = [
        task_spec_from_dict(item)
        for item in (config_snapshot.get("task_specs") or [])
        if isinstance(item, dict) and str(item.get("task_id") or "") in STAGE_TASK_IDS
    ]
    parameters = stage_parameters_from_specs(specs)
    raw_log_path = str(input_manifest.get("raw_log_path") or "")
    if not raw_log_path:
        raise StageBundleError("input manifest lacks raw_log_path")
    source_digest = deterministic_source_digest(harness_root) if adopt_current_source else "legacy-unverified"
    transient_paths = transient_stage_artifact_paths(parsed_stage_results.values())
    compact_stage_results = {
        task_id: compact_stage_task_result(
            task_id,
            result,
            transient_paths=transient_paths,
        )
        for task_id, result in parsed_stage_results.items()
    }
    return {
        "schema_version": STAGE_BUNDLE_SCHEMA,
        "artifact_retention": STAGE_CHECKPOINT_RETENTION,
        "bundle_id": required_text(bundle_id, "bundle_id"),
        "created_at_utc": utc_now(),
        "source": {"raw_log": file_fingerprint(raw_log_path)},
        "parameters": parameters,
        "deterministic_source_digest": source_digest,
        "stage_task_results": compact_stage_results,
        "provenance": {
            "migration_mode": "adopt_current_source" if adopt_current_source else "legacy_unverified",
            "source_session_dir": str(session_state.get("work_dir") or ""),
        },
    }


def validate_stage_bundle_structure(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise StageBundleError("stage bundle must be a JSON object")
    if payload.get("schema_version") != STAGE_BUNDLE_SCHEMA:
        raise StageBundleError(f"unsupported stage bundle schema: {payload.get('schema_version')!r}")
    required_text(payload.get("bundle_id"), "bundle_id")
    source = payload.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("raw_log"), dict):
        raise StageBundleError("stage bundle lacks source.raw_log")
    parameters = payload.get("parameters")
    if not isinstance(parameters, dict):
        raise StageBundleError("stage bundle lacks deterministic parameters")
    normalize_stage_parameters(parameters)
    if not isinstance(payload.get("deterministic_source_digest"), str):
        raise StageBundleError("stage bundle lacks deterministic_source_digest")
    task_results = payload.get("stage_task_results")
    if not isinstance(task_results, dict):
        raise StageBundleError("stage bundle lacks stage_task_results")
    missing = [task_id for task_id in STAGE_TASK_IDS if task_id not in task_results]
    if missing:
        raise StageBundleError(f"stage bundle lacks task results: {missing}")


def normalize_stage_parameters(value: dict[str, Any]) -> dict[str, Any]:
    return build_stage_parameters(
        sample_hint=str(value.get("sample_hint") or ""),
        slice_size=int(value.get("slice_size") or 250),
        root_pid=optional_int(value.get("root_pid")),
        grace_seconds=float(value.get("grace_seconds") if value.get("grace_seconds") is not None else 0.5),
        write_events=bool(value.get("write_events", True)),
        behavior_parameters=dict(value.get("behavior") or {}),
    )


def validate_result_artifacts(task_id: str, result: TaskResult) -> None:
    if result.status != "completed":
        raise StageBundleError(f"staged task {task_id} is not completed")
    if not result.artifacts:
        raise StageBundleError(f"staged task {task_id} has no artifacts")
    missing = [
        ref.artifact_id
        for ref in result.artifacts.values()
        if not ref.path or not Path(ref.path).is_file()
    ]
    if missing:
        raise StageBundleError(f"staged task {task_id} references missing artifacts: {missing}")


def artifact_ref_from_dict(value: dict[str, Any]) -> ArtifactRef:
    return ArtifactRef(
        artifact_id=str(value.get("artifact_id") or ""),
        kind=str(value.get("kind") or ""),
        path=str(value.get("path") or ""),
        producer_task_id=str(value.get("producer_task_id") or ""),
        metadata=dict(value.get("metadata") or {}),
    )


def session_fact_from_dict(value: dict[str, Any]) -> SessionFact:
    return SessionFact(
        fact_id=str(value.get("fact_id") or ""),
        kind=str(value.get("kind") or ""),
        data=dict(value.get("data") or {}),
        source_task_id=str(value.get("source_task_id") or ""),
        artifact_ids=tuple(str(item) for item in value.get("artifact_ids") or ()),
    )


def task_result_from_dict(value: dict[str, Any]) -> TaskResult:
    artifacts = {
        str(name): artifact_ref_from_dict(ref)
        for name, ref in dict(value.get("artifacts") or {}).items()
        if isinstance(ref, dict)
    }
    facts = tuple(
        session_fact_from_dict(item)
        for item in value.get("facts") or ()
        if isinstance(item, dict)
    )
    return TaskResult(
        task_id=str(value.get("task_id") or ""),
        status=str(value.get("status") or "failed"),
        artifacts=artifacts,
        facts=facts,
        diagnostics=dict(value.get("diagnostics") or {}),
        error=str(value.get("error") or ""),
    )


def task_spec_from_dict(value: dict[str, Any]) -> TaskSpec:
    return TaskSpec(
        task_id=str(value.get("task_id") or ""),
        task_type=str(value.get("task_type") or ""),
        profile=str(value.get("profile") or "deterministic"),
        dependencies=tuple(str(item) for item in value.get("dependencies") or ()),
        input_artifacts=dict(value.get("input_artifacts") or {}),
        parameters=dict(value.get("parameters") or {}),
        output_names=tuple(str(item) for item in value.get("output_names") or ()),
        allowed_tools=tuple(str(item) for item in value.get("allowed_tools") or ()),
        context_policy=dict(value.get("context_policy") or {}),
        budget=dict(value.get("budget") or {}),
        acceptance_criteria=tuple(str(item) for item in value.get("acceptance_criteria") or ()),
    )


def optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def required_text(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise StageBundleError(f"{field_name} must be non-empty")
    return text


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

"""Session-level orchestration for config-driven harness runs."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.behavior.llm_loop import JSONChatClient
from harness.monitor import HarnessMonitor
from harness.pipeline_config import PipelineInputConfig
from harness.role_profile import load_role_profile
from harness.session_layout import SessionOutputLayout, create_output_layout

from .stage_store import (
    build_stage_bundle_payload,
    compact_exported_stage_state,
    bundle_summary,
    hydrate_stage_bundle,
    load_stage_bundle,
    stage_parameters_from_specs,
    validate_stage_bundle,
    write_stage_bundle,
)
from .tasks.behavior import behavior_task_handlers, build_behavior_task_specs
from .tasks.coarse import build_coarse_task_specs, coarse_task_handlers
from .tasks.evidence import build_evidence_profile_task_spec, evidence_task_handlers
from .tasks.models import AnalysisSessionState, TaskResult, TaskSpec
from .tasks.runner import TaskRunner
from .tasks.static import build_static_strong_task_spec, static_task_handlers
from .tasks.verdict import build_verdict_task_spec, verdict_task_handlers
from .tasks.verdict_review import (
    build_sample_decision_task_spec,
    build_verdict_pre_review_task_spec,
    build_verdict_review_task_spec,
    verdict_finalization_task_handlers,
    verdict_pre_review_task_handlers,
    verdict_review_task_handlers,
)

DEFAULT_EVIDENCE_AGENT_IDS = (
    "file_discovery",
    "file_transformation",
    "ransom_note",
    "registry",
    "process",
    "recovery",
    "anti_analysis",
)


@dataclass(frozen=True)
class AnalysisSession:
    state: AnalysisSessionState
    layout: SessionOutputLayout
    monitor: HarnessMonitor | None = None
    stage_bundle: dict[str, Any] | None = None


def initialize_analysis_session(
    sample_id: str,
    raw_log_path: str | Path | None,
    sample_hint: str = "",
    static_sample_path: str | Path | None = None,
    harness_root: str | Path | None = None,
    layout_config_path: str | Path | None = None,
    stage_bundle_path: str | Path | None = None,
    input_metadata: dict[str, Any] | None = None,
) -> AnalysisSession:
    layout = create_output_layout(sample_id, harness_root=harness_root, config_path=layout_config_path)
    raw_log_text = str(raw_log_path or "").strip()
    raw_log = Path(raw_log_text) if raw_log_text else None
    input_manifest = {
        "schema_version": "harness-input-manifest-v1",
        "sample_id": sample_id,
        "sample_hint": sample_hint,
        "raw_log_path": raw_log_text,
        "raw_log_exists": bool(raw_log is not None and raw_log.exists()),
        "raw_log_file": file_metadata(raw_log),
        "stage_bundle_path": str(Path(stage_bundle_path).resolve()) if stage_bundle_path else "",
        "static_sample_path": str(static_sample_path or ""),
        "static_sample_file": file_metadata(Path(static_sample_path)) if static_sample_path else None,
        "metadata": input_metadata or {},
    }
    write_json(layout.file("input_manifest"), input_manifest)
    state = AnalysisSessionState(
        sample_id=sample_id,
        work_dir=layout.session_dir,
        task_directories=dict(layout.config.task_stage_map),
    )
    if raw_log is not None:
        state.register_input_artifact(
            "raw_log",
            "raw_log",
            raw_log,
            {"sample_hint": sample_hint, "input_manifest": str(layout.file("input_manifest"))},
        )
    if static_sample_path:
        static_path = Path(static_sample_path)
        state.register_input_artifact(
            "static_sample",
            "static_sample",
            static_path,
            {"sample_hint": sample_hint, "input_manifest": str(layout.file("input_manifest"))},
        )
    return AnalysisSession(state=state, layout=layout)


def run_analysis_pipeline(
    raw_log_path: str | Path,
    sample_id: str,
    sample_hint: str = "",
    static_sample_path: str | Path | None = None,
    trace_id: str = "trace",
    slice_size: int = 250,
    root_pid: int | None = None,
    grace_seconds: float = 0.5,
    write_events: bool = True,
    harness_root: str | Path | None = None,
    layout_config_path: str | Path | None = None,
    role_profile_path: str | Path | None = None,
    client: JSONChatClient | None = None,
    evidence_agent_ids: tuple[str, ...] | None = None,
    run_verdict: bool | None = None,
    stage_bundle_path: str | Path | None = None,
    export_stage_bundle_path: str | Path | None = None,
    export_stage_bundle_id: str = "",
    compact_exported_stage_artifacts: bool = False,
    input_metadata: dict[str, Any] | None = None,
    resume: bool = False,
) -> AnalysisSession:
    initialized = initialize_analysis_session(
        sample_id=sample_id,
        raw_log_path=raw_log_path,
        sample_hint=sample_hint,
        static_sample_path=static_sample_path,
        harness_root=harness_root,
        layout_config_path=layout_config_path,
        stage_bundle_path=stage_bundle_path,
        input_metadata=input_metadata,
    )
    monitor = HarnessMonitor(initialized.layout.directory("audit"), initialized.state.sample_id)
    session = AnalysisSession(state=initialized.state, layout=initialized.layout, monitor=monitor)
    role_profile = load_role_profile(role_profile_path)
    if client is not None and role_profile.unified_references:
        from .unified_references import UnifiedReferenceClient
        client = UnifiedReferenceClient(client,initialized.layout.directory('audit'))
    specs = list(build_coarse_task_specs(
        raw_log_artifact_id="raw_log",
        sample_hint=sample_hint,
        trace_id=trace_id,
        slice_size=slice_size,
        root_pid=root_pid,
        grace_seconds=grace_seconds,
        write_events=write_events,
    ))
    specs.extend(build_behavior_task_specs())
    stage_parameters = stage_parameters_from_specs(specs)
    stage_bundle_info: dict[str, Any] | None = None
    if stage_bundle_path:
        source_bundle_path = Path(stage_bundle_path).resolve()
        stage_bundle = load_stage_bundle(source_bundle_path)
        validate_stage_bundle(
            stage_bundle,
            raw_log_path=raw_log_path,
            parameters=stage_parameters,
            harness_root=harness_root,
        )
        hydrated_task_ids = hydrate_stage_bundle(initialized.state, stage_bundle)
        stage_bundle_info = {
            "mode": "reused",
            **bundle_summary(stage_bundle, source_bundle_path),
            "hydrated_task_ids": list(hydrated_task_ids),
        }
        session = AnalysisSession(
            state=initialized.state,
            layout=initialized.layout,
            monitor=monitor,
            stage_bundle=stage_bundle_info,
        )

    handlers: dict[str, Any] = {}
    handlers.update(coarse_task_handlers())
    handlers.update(behavior_task_handlers())

    static_specs: list[TaskSpec] = []
    if static_sample_path and role_profile.profile_id != 'dev-v036-final-static-ransom':
        handlers.update(static_task_handlers())
        static_specs.append(build_static_strong_task_spec())
        specs.extend(static_specs)

    selected_agents = evidence_agent_ids if evidence_agent_ids is not None else (() if client is None else DEFAULT_EVIDENCE_AGENT_IDS)
    should_run_verdict = bool(client is not None if run_verdict is None else run_verdict)
    if (selected_agents or should_run_verdict) and client is None:
        raise ValueError("client is required for evidence agents or verdict synthesis")
    review_specs: list[TaskSpec] = []
    if client is not None:
        handlers.update(evidence_task_handlers(
            client, agent_prompts=role_profile.resolve_agent_prompts(),
            analysis_protocol=role_profile.analysis_protocol,
        ))
        handlers.update(verdict_task_handlers(client))
        handlers.update(verdict_pre_review_task_handlers())
        handlers.update(verdict_review_task_handlers(client))
        handlers.update(verdict_finalization_task_handlers())
        if role_profile.analysis_protocol == "evidence-reasoning-v1":
            from .tasks.reasoning import reasoning_task_handlers
            handlers.update(reasoning_task_handlers(client))
        elif role_profile.analysis_protocol == "evidence-reasoning-v2":
            from .tasks.reasoning_v2 import reasoning_task_handlers
            handlers.update(reasoning_task_handlers(client))
        elif role_profile.analysis_protocol == "evidence-binary-v1":
            from .tasks.binary_adjudication import binary_task_handlers
            handlers.update(binary_task_handlers(client,
                investigation_closure=role_profile.investigation_closure,
                claim_linking=role_profile.claim_linking, symmetric_review=role_profile.symmetric_review,
                strict_json_schema=role_profile.strict_json_schema))
        evidence_specs = [build_evidence_profile_task_spec(agent_id, budget=role_profile.evidence_budget())
                          for agent_id in selected_agents]
        specs.extend(evidence_specs)
        if should_run_verdict:
            verdict_deps = tuple(spec.task_id for spec in evidence_specs + static_specs)
            specs.append(build_verdict_task_spec(dependencies=verdict_deps, analysis_protocol=role_profile.analysis_protocol))
            review_specs = [
                build_verdict_pre_review_task_spec(evidence_audit_path=monitor.evidence_audit_path),
                build_verdict_review_task_spec(evidence_audit_path=monitor.evidence_audit_path, analysis_protocol=role_profile.analysis_protocol),
                build_sample_decision_task_spec(evidence_audit_path=monitor.evidence_audit_path),
            ]

    monitor.write_config_snapshot(build_config_snapshot(session, specs, raw_log_path, {
        "sample_hint": sample_hint,
        "static_sample_path": str(static_sample_path or ""),
        "trace_id": trace_id,
        "slice_size": slice_size,
        "root_pid": root_pid,
        "grace_seconds": grace_seconds,
        "write_events": write_events,
        "evidence_agent_ids": list(selected_agents),
        "run_verdict": should_run_verdict,
        "resume": resume,
        "stage_bundle": stage_bundle_info or {"mode": "not_used"},
        "export_stage_bundle_path": str(Path(export_stage_bundle_path).resolve()) if export_stage_bundle_path else "",
        "compact_exported_stage_artifacts": compact_exported_stage_artifacts,
        "role_profile": role_profile.snapshot(),
        "input_metadata": input_metadata or {},
    }, task_specs=specs + review_specs))
    results = TaskRunner(
        handlers,
        session.state,
        monitor=monitor,
        resume=resume or stage_bundle_info is not None,
    ).run_all(specs)
    if export_stage_bundle_path:
        target_bundle_path = Path(export_stage_bundle_path).resolve()
        exported_bundle = build_stage_bundle_payload(
            bundle_id=export_stage_bundle_id or target_bundle_path.stem,
            state=session.state,
            raw_log_path=raw_log_path,
            parameters=stage_parameters,
            harness_root=harness_root,
            provenance={
                "source_session_dir": str(session.layout.session_dir),
                "exported_from_session": True,
            },
        )
        write_stage_bundle(target_bundle_path, exported_bundle)
        removed_paths = ()
        if compact_exported_stage_artifacts:
            removed_paths = compact_exported_stage_state(session.state, exported_bundle)
        exported_summary = bundle_summary(exported_bundle, target_bundle_path)
        if removed_paths:
            exported_summary["removed_transient_artifact_count"] = len(removed_paths)
        stage_bundle_info = (
            {
                "mode": "reused_and_exported",
                "source": stage_bundle_info,
                "exported": exported_summary,
            }
            if stage_bundle_info is not None
            else {"mode": "materialized", **exported_summary}
        )
        session = AnalysisSession(
            state=session.state,
            layout=session.layout,
            monitor=monitor,
            stage_bundle=stage_bundle_info,
        )
    artifact_audit = monitor.audit_artifacts(session.state)
    evidence_audit = monitor.audit_evidence(session.state)
    verdict_pre_review = None
    verdict_review = None
    sample_decision = None
    if review_specs and "synthesize_sample_verdict:sample_verdict" in session.state.artifacts:
        review_runner = TaskRunner(handlers, session.state, monitor=monitor, resume=resume)
        if role_profile.analysis_protocol in {"evidence-reasoning-v2", "evidence-binary-v1"}:
            review_results = review_runner.run_all(review_specs[:-1])
            evidence_audit = monitor.audit_evidence(session.state)
            review_results.extend(review_runner.run_all(review_specs[-1:]))
        else:
            review_results = review_runner.run_all(review_specs)
        specs.extend(review_specs)
        results.extend(review_results)
        verdict_pre_review = load_json(monitor.audit_dir / "verdict_pre_review.json", default=None)
        verdict_review = load_json(monitor.audit_dir / "verdict_review.json", default=None)
        decision_ref = session.state.artifact("finalize_sample_decision:sample_decision")
        sample_decision = load_json(Path(decision_ref.path), default=None)
        artifact_audit = monitor.audit_artifacts(session.state)
    write_session_outputs(
        session,
        specs,
        results,
        artifact_audit=artifact_audit,
        evidence_audit=evidence_audit,
        verdict_pre_review=verdict_pre_review,
        verdict_review=verdict_review,
        sample_decision=sample_decision,
        stage_bundle=stage_bundle_info,
    )
    return session


def run_analysis_pipeline_from_input(
    input_config: PipelineInputConfig,
    harness_root: str | Path | None = None,
    layout_config_path: str | Path | None = None,
    client: JSONChatClient | None = None,
    role_profile_path: str | Path | None = None,
    run_verdict: bool | None = None,
    export_stage_bundle_path: str | Path | None = None,
    export_stage_bundle_id: str = "",
    compact_exported_stage_artifacts: bool = False,
    resume: bool = False,
) -> AnalysisSession:
    kwargs = input_config.to_pipeline_kwargs()
    if run_verdict is not None:
        kwargs["run_verdict"] = run_verdict
    if kwargs.get("behavior_snapshot_path"):
        from .snapshot_pipeline import run_analysis_pipeline_from_behavior_snapshot

        return run_analysis_pipeline_from_behavior_snapshot(
            **kwargs,
            harness_root=harness_root,
            layout_config_path=layout_config_path,
            client=client,
            role_profile_path=role_profile_path,
            export_stage_bundle_path=export_stage_bundle_path,
            export_stage_bundle_id=export_stage_bundle_id,
            compact_exported_stage_artifacts=compact_exported_stage_artifacts,
            resume=resume,
        )
    kwargs.pop("behavior_snapshot_path", None)
    kwargs.pop("behavior_sample_key", None)
    return run_analysis_pipeline(
        **kwargs,
        harness_root=harness_root,
        layout_config_path=layout_config_path,
        client=client,
        role_profile_path=role_profile_path,
        export_stage_bundle_path=export_stage_bundle_path,
        export_stage_bundle_id=export_stage_bundle_id,
        compact_exported_stage_artifacts=compact_exported_stage_artifacts,
        resume=resume,
    )


def write_session_outputs(
    session: AnalysisSession,
    specs: list[TaskSpec],
    results: list[TaskResult],
    artifact_audit: dict[str, Any] | None = None,
    evidence_audit: dict[str, Any] | None = None,
    verdict_pre_review: dict[str, Any] | None = None,
    verdict_review: dict[str, Any] | None = None,
    sample_decision: dict[str, Any] | None = None,
    stage_bundle: dict[str, Any] | None = None,
) -> None:
    state = session.state
    write_json(session.layout.file("session_state"), state.to_dict())
    monitor_paths = monitor_output_paths(session.monitor) if session.monitor is not None else {}
    summary = {
        "schema_version": "harness-session-summary-v1",
        "sample_id": state.sample_id,
        "status": "completed" if all(result.status == "completed" for result in results) else "incomplete",
        "layout": session.layout.to_dict(),
        "task_order": [spec.task_id for spec in specs],
        "task_statuses": {result.task_id: result.status for result in results},
        "artifact_count": len(state.artifacts),
        "fact_count": len(state.facts),
        "stage_bundle": stage_bundle or {"mode": "not_used"},
        "monitor": monitor_paths,
        "artifact_audit_status": {
            "missing_artifact_count": (artifact_audit or {}).get("missing_artifact_count", 0),
        },
        "evidence_audit_status": {
            "status": (evidence_audit or {}).get("status", "not_run"),
            "issue_count": (evidence_audit or {}).get("issue_count", 0),
        },
        "verdict_pre_review_status": {
            "status": (verdict_pre_review or {}).get("status", "not_run"),
            "issue_count": (verdict_pre_review or {}).get("issue_count", 0),
        },
        "verdict_review_status": {
            "status": (verdict_review or {}).get(
                "classification_status", (verdict_review or {}).get("status", "not_run")
            ),
            "report_status": (verdict_review or {}).get("status", "not_run"),
            "issue_count": len((verdict_review or {}).get("evidence_issues", [])),
        },
        "sample_decision": {
            "status": (sample_decision or {}).get("status", "not_run"),
            "verdict": (sample_decision or {}).get("verdict"),
            "candidate_verdict": (sample_decision or {}).get("candidate_verdict", ""),
            "reason_codes": list((sample_decision or {}).get("reason_codes") or []),
        },
    }
    write_json(session.layout.file("summary"), summary)


def build_config_snapshot(
    session: AnalysisSession,
    specs: list[TaskSpec],
    raw_log_path: str | Path | None,
    parameters: dict[str, Any],
    task_specs: list[TaskSpec] | None = None,
) -> dict[str, Any]:
    snapshot_specs = task_specs if task_specs is not None else specs
    return {
        "layout": session.layout.to_dict(),
        "raw_log_file": file_metadata(
            Path(str(raw_log_path).strip()) if str(raw_log_path or "").strip() else None
        ),
        "parameters": parameters,
        "task_specs": [spec.to_dict() for spec in snapshot_specs],
    }


def monitor_output_paths(monitor: HarnessMonitor) -> dict[str, str]:
    return {
        "audit_dir": str(monitor.audit_dir),
        "run_events": str(monitor.events_path),
        "task_status": str(monitor.task_status_path),
        "task_metrics": str(monitor.task_metrics_path),
        "failures": str(monitor.failures_path),
        "config_snapshot": str(monitor.config_snapshot_path),
        "artifact_audit": str(monitor.artifact_audit_path),
        "evidence_audit": str(monitor.evidence_audit_path),
        "verdict_pre_review": str(monitor.audit_dir / "verdict_pre_review.json"),
        "verdict_review": str(monitor.audit_dir / "verdict_review.json"),
    }


def file_metadata(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {
            "path": str(path) if path is not None else "",
            "exists": False,
            "size_bytes": None,
            "mtime_ns": None,
        }
    stat = path.stat()
    return {
        "path": str(path),
        "exists": True,
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

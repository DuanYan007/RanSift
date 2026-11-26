"""Session orchestration that starts from a sealed behavior snapshot."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from harness.behavior.llm_loop import JSONChatClient
from harness.monitor import HarnessMonitor
from harness.role_profile import load_role_profile

from .behavior_snapshot import BehaviorSnapshotSample, hydrate_behavior_snapshot, load_behavior_snapshot_sample
from .session import (
    AnalysisSession,
    DEFAULT_EVIDENCE_AGENT_IDS,
    build_config_snapshot,
    initialize_analysis_session,
    load_json,
    write_session_outputs,
)
from .tasks.evidence import build_evidence_profile_task_spec, evidence_task_handlers
from .tasks.models import TaskSpec
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


def run_analysis_pipeline_from_behavior_snapshot(
    *,
    raw_log_path: str | Path | None,
    sample_id: str,
    behavior_snapshot_path: str | Path,
    behavior_sample_key: str,
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
    prepared_snapshot: BehaviorSnapshotSample | None = None,
) -> AnalysisSession:
    """Run evidence agents without replaying deterministic preprocessing."""

    if stage_bundle_path:
        raise ValueError("behavior snapshot reuse cannot be combined with a legacy stage bundle")
    if export_stage_bundle_path or export_stage_bundle_id or compact_exported_stage_artifacts:
        raise ValueError("behavior snapshot runs cannot export a legacy deterministic stage bundle")
    if not str(behavior_sample_key or "").strip():
        raise ValueError("behavior_sample_key is required with behavior_snapshot_path")

    snapshot = prepared_snapshot if prepared_snapshot is not None else load_behavior_snapshot_sample(behavior_snapshot_path, behavior_sample_key)
    snapshot_info = {
        **snapshot.provenance(),
        "hydrated_task_ids": [
            "normalize_behavior_trace",
            "build_behavior_index",
            "build_behavior_blocks",
        ],
    }
    metadata = dict(input_metadata or {})
    metadata["behavior_snapshot"] = snapshot_info
    initialized = initialize_analysis_session(
        sample_id=sample_id,
        raw_log_path=raw_log_path,
        sample_hint=sample_hint,
        static_sample_path=static_sample_path,
        harness_root=harness_root,
        layout_config_path=layout_config_path,
        input_metadata=metadata,
    )
    monitor = HarnessMonitor(initialized.layout.directory("audit"), initialized.state.sample_id)
    hydrated_task_ids = hydrate_behavior_snapshot(initialized.state, snapshot)
    snapshot_info["hydrated_task_ids"] = list(hydrated_task_ids)
    monitor.record_event("behavior_snapshot_hydrated", snapshot_info)
    session = AnalysisSession(
        state=initialized.state,
        layout=initialized.layout,
        monitor=monitor,
        stage_bundle={"mode": "sealed_behavior_snapshot", **snapshot_info},
    )
    role_profile = load_role_profile(role_profile_path)
    if client is not None and role_profile.unified_references:
        from .unified_references import UnifiedReferenceClient
        client = UnifiedReferenceClient(client,initialized.layout.directory('audit'))

    handlers: dict[str, Any] = {}
    specs: list[TaskSpec] = []
    static_specs: list[TaskSpec] = []
    if static_sample_path and role_profile.profile_id != 'dev-v036-final-static-ransom':
        handlers.update(static_task_handlers())
        static_specs.append(build_static_strong_task_spec())
        specs.extend(static_specs)

    selected_agents = (
        evidence_agent_ids
        if evidence_agent_ids is not None
        else (() if client is None else DEFAULT_EVIDENCE_AGENT_IDS)
    )
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
        "behavior_snapshot": snapshot_info,
        "role_profile": role_profile.snapshot(),
        "input_metadata": metadata,
    }, task_specs=specs + review_specs))
    results = TaskRunner(handlers, session.state, monitor=monitor, resume=resume).run_all(specs)
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
        stage_bundle=session.stage_bundle,
    )
    return session

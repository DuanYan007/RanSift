"""Runtime monitor and deterministic audit checks for harness sessions."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from harness.behavior.coverage import is_sufficient_analysis_coverage
from harness.tasks.models import AnalysisSessionState, TaskResult, TaskSpec


CLAIM_BEHAVIOR_CLASSES = {
    "malicious_only",
    "risk_relevant",
    "dual_use",
    "absent",
    "uncertain",
    "static_strong",
    "unclassified",
}


@dataclass
class TaskTiming:
    task_id: str
    started_monotonic: float
    started_at: str
    task_type: str
    profile: str


@dataclass
class EvidenceAuditIssue:
    severity: str
    category: str
    subject: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "subject": self.subject,
            "message": self.message,
            "details": self.details,
        }


class HarnessMonitor:
    """Side-channel monitor for task execution and evidence-contract checks.

    The monitor does not make malware-risk decisions. It records runtime state,
    task failures, artifact integrity, and deterministic evidence invariants so
    the harness can be resumed or reviewed without conflating monitoring with
    evidence-agent or verdict-agent responsibilities.
    """

    def __init__(self, audit_dir: str | Path, sample_id: str) -> None:
        self.audit_dir = Path(audit_dir)
        self.sample_id = sample_id
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.audit_dir / "run_events.jsonl"
        self.failures_path = self.audit_dir / "failures.jsonl"
        self.task_status_path = self.audit_dir / "task_status.json"
        self.task_metrics_path = self.audit_dir / "task_metrics.json"
        self.config_snapshot_path = self.audit_dir / "config_snapshot.json"
        self.evidence_audit_path = self.audit_dir / "evidence_audit.json"
        self.artifact_audit_path = self.audit_dir / "artifact_audit.json"
        self._sequence = 0
        self._active: dict[str, TaskTiming] = {}
        self._statuses: dict[str, dict[str, Any]] = {}
        self._metrics: dict[str, dict[str, Any]] = {}
        self.events_path.touch(exist_ok=True)
        self.failures_path.touch(exist_ok=True)

    def write_config_snapshot(self, payload: dict[str, Any]) -> None:
        if self.config_snapshot_path.exists():
            previous = load_json_safely(self.config_snapshot_path, default={})
            old_protocol = previous.get("parameters", {}).get("role_profile", {}).get("analysis_protocol", "legacy-v1")
            new_protocol = payload.get("parameters", {}).get("role_profile", {}).get("analysis_protocol", "legacy-v1")
            if old_protocol != new_protocol:
                raise ValueError("analysis protocol changed; use a new session directory instead of mixing protocol artifacts")
        snapshot = {
            "schema_version": "harness-config-snapshot-v1",
            "sample_id": self.sample_id,
            "captured_at": utc_now(),
            **payload,
        }
        write_json(self.config_snapshot_path, snapshot)
        self.record_event("config_snapshot", {"path": str(self.config_snapshot_path)})

    def task_started(self, spec: TaskSpec) -> None:
        timing = TaskTiming(
            task_id=spec.task_id,
            task_type=spec.task_type,
            profile=spec.profile,
            started_monotonic=time.monotonic(),
            started_at=utc_now(),
        )
        self._active[spec.task_id] = timing
        self._statuses[spec.task_id] = {
            "task_id": spec.task_id,
            "task_type": spec.task_type,
            "profile": spec.profile,
            "status": "running",
            "started_at": timing.started_at,
            "dependencies": list(spec.dependencies),
        }
        self._flush_status()
        self.record_event("task_started", {"task": spec.to_dict()})

    def task_finished(self, spec: TaskSpec, result: TaskResult, state: AnalysisSessionState) -> None:
        timing = self._active.pop(spec.task_id, None)
        duration = max(0.0, time.monotonic() - timing.started_monotonic) if timing else None
        status_record = {
            "task_id": spec.task_id,
            "task_type": spec.task_type,
            "profile": spec.profile,
            "status": result.status,
            "started_at": timing.started_at if timing else "",
            "finished_at": utc_now(),
            "duration_seconds": duration,
            "dependencies": list(spec.dependencies),
            "error": result.error,
        }
        self._statuses[spec.task_id] = status_record
        self._metrics[spec.task_id] = task_metric_record(spec, result, duration, state)
        self._flush_status()
        self._flush_metrics()
        payload = {"task_id": spec.task_id, "status": result.status, "diagnostics": result.diagnostics}
        self.record_event("task_finished", payload)
        if result.status != "completed":
            self.record_failure(spec, result)

    def task_skipped(self, spec: TaskSpec, reason: str) -> None:
        record = {
            "task_id": spec.task_id,
            "task_type": spec.task_type,
            "profile": spec.profile,
            "status": "skipped",
            "started_at": "",
            "finished_at": utc_now(),
            "duration_seconds": 0.0,
            "dependencies": list(spec.dependencies),
            "reason": reason,
        }
        self._statuses[spec.task_id] = record
        self._metrics[spec.task_id] = {
            "task_id": spec.task_id,
            "status": "skipped",
            "duration_seconds": 0.0,
            "artifact_count": 0,
            "fact_count": 0,
            "reason": reason,
        }
        self._flush_status()
        self._flush_metrics()
        self.record_event("task_skipped", record)

    def record_failure(self, spec: TaskSpec, result: TaskResult) -> None:
        payload = {
            "schema_version": "harness-task-failure-v1",
            "sample_id": self.sample_id,
            "task_id": spec.task_id,
            "task_type": spec.task_type,
            "profile": spec.profile,
            "status": result.status,
            "error": result.error,
            "diagnostics": result.diagnostics,
            "recorded_at": utc_now(),
        }
        append_jsonl(self.failures_path, payload)

    def record_event(self, event_type: str, payload: dict[str, Any]) -> None:
        self._sequence += 1
        append_jsonl(self.events_path, {
            "schema_version": "harness-run-event-v1",
            "sequence": self._sequence,
            "sample_id": self.sample_id,
            "event_type": event_type,
            "timestamp": utc_now(),
            **payload,
        })

    def audit_artifacts(self, state: AnalysisSessionState) -> dict[str, Any]:
        records = []
        missing = []
        for artifact_id, ref in sorted(state.artifacts.items()):
            path = Path(ref.path)
            exists = path.exists()
            record = {
                "artifact_id": artifact_id,
                "kind": ref.kind,
                "producer_task_id": ref.producer_task_id,
                "path": str(path),
                "exists": exists,
                "size_bytes": path.stat().st_size if exists and path.is_file() else None,
            }
            records.append(record)
            if not exists:
                missing.append(artifact_id)
        report = {
            "schema_version": "harness-artifact-audit-v1",
            "sample_id": state.sample_id,
            "artifact_count": len(records),
            "missing_artifact_count": len(missing),
            "missing_artifact_ids": missing,
            "artifacts": records,
        }
        write_json(self.artifact_audit_path, report)
        return report

    def audit_evidence(self, state: AnalysisSessionState) -> dict[str, Any]:
        issues = EvidenceAudit(state).run()
        severity_rank = {"error": 2, "warning": 1, "info": 0}
        worst = max((severity_rank.get(issue.severity, 0) for issue in issues), default=0)
        status = "fail" if worst >= 2 else "warn" if worst == 1 else "pass"
        claim_facts = state.facts_by_kind("candidate_claim")
        verdict_facts = state.facts_by_kind("sample_verdict")
        report = {
            "schema_version": "harness-evidence-audit-v1",
            "sample_id": state.sample_id,
            "status": status,
            "claim_count": len(claim_facts),
            "verdict_count": len(verdict_facts),
            "issue_count": len(issues),
            "issues": [issue.to_dict() for issue in issues],
        }
        write_json(self.evidence_audit_path, report)
        self.record_event("evidence_audit", {"status": status, "issue_count": len(issues)})
        return report

    def _flush_status(self) -> None:
        write_json(self.task_status_path, {
            "schema_version": "harness-task-status-v1",
            "sample_id": self.sample_id,
            "tasks": dict(sorted(self._statuses.items())),
        })

    def _flush_metrics(self) -> None:
        write_json(self.task_metrics_path, {
            "schema_version": "harness-task-metrics-v1",
            "sample_id": self.sample_id,
            "tasks": dict(sorted(self._metrics.items())),
        })


class EvidenceAudit:
    def __init__(self, state: AnalysisSessionState) -> None:
        self.state = state
        self.issues: list[EvidenceAuditIssue] = []

    def run(self) -> list[EvidenceAuditIssue]:
        self.audit_candidate_claims()
        self.audit_verdict()
        return self.issues

    def audit_candidate_claims(self) -> None:
        for fact in self.state.facts_by_kind("candidate_claim"):
            claim = fact.data
            subject = f"{fact.source_task_id}:{claim.get('claim_id', '')}"
            refs = string_list(claim.get("evidence_ref_ids"))
            claim_type = str(claim.get("claim_type") or "")
            self.audit_claim_semantics(subject, claim)
            if not refs and not is_absent_or_uncertain(claim_type):
                self.add("error", "claim_evidence", subject, "risk-bearing claim has no evidence_ref_ids")
            memory_refs, block_ids = self.memory_refs_for_task(fact.source_task_id)
            unknown_refs = sorted(set(refs) - memory_refs)
            if unknown_refs:
                self.add(
                    "error",
                    "claim_evidence",
                    subject,
                    "claim cites refs not returned by its local tool loop",
                    {"unknown_evidence_ref_ids": unknown_refs},
                )
            requested_blocks = set(string_list(claim.get("supporting_block_ids")))
            unknown_blocks = sorted(requested_blocks - block_ids)
            if unknown_blocks:
                self.add(
                    "warning",
                    "claim_block",
                    subject,
                    "claim cites block ids not present in local memory",
                    {"unknown_block_ids": unknown_blocks},
                )

    def audit_verdict(self) -> None:
        verdict_ref = artifact_ref_or_none(self.state, "synthesize_sample_verdict:sample_verdict")
        reviewed_ref = artifact_ref_or_none(self.state, "review_sample_verdict:reviewed_sample_verdict")
        if reviewed_ref is not None:
            verdict_ref = reviewed_ref
        claims_ref = artifact_ref_or_none(self.state, "synthesize_sample_verdict:verdict_input_claims")
        if reviewed_ref is not None:
            late_claims = artifact_ref_or_none(self.state, "review_sample_verdict:adjudication_input_claims")
            if late_claims is not None:
                claims_ref = late_claims
        coverage_ref = artifact_ref_or_none(self.state, "synthesize_sample_verdict:verdict_input_coverage")
        if verdict_ref is None:
            return
        verdict = load_json_safely(Path(verdict_ref.path), default={})
        input_claims = load_json_safely(Path(claims_ref.path), default=[]) if claims_ref is not None else []
        analysis_coverage = load_json_safely(Path(coverage_ref.path), default={}) if coverage_ref is not None else {}
        if not isinstance(verdict, dict) or not isinstance(input_claims, list):
            self.add("error", "verdict_schema", "synthesize_sample_verdict", "verdict or input-claim artifact is malformed")
            return
        if verdict.get("verdict") == "no_risk" and not is_sufficient_analysis_coverage(analysis_coverage):
            self.add(
                "error",
                "negative_coverage",
                "synthesize_sample_verdict",
                "no_risk verdict lacks sufficient bounded role coverage",
                {
                    "coverage_status": str(analysis_coverage.get("status") or "not_available")
                    if isinstance(analysis_coverage, dict)
                    else "not_available",
                },
            )
        known_claim_ids = {str(claim.get("claim_id")) for claim in input_claims if isinstance(claim, dict)}
        refs_by_claim = {
            str(claim.get("claim_id")): set(string_list(claim.get("evidence_ref_ids")))
            for claim in input_claims if isinstance(claim, dict)
        }
        supporting = string_list(verdict.get("supporting_claim_ids"))
        unknown_supporting = sorted(set(supporting) - known_claim_ids)
        if unknown_supporting:
            self.add(
                "error",
                "verdict_claim",
                "synthesize_sample_verdict",
                "verdict cites supporting claim ids not supplied to the verdict task",
                {"unknown_claim_ids": unknown_supporting},
            )
        for index, step in enumerate(list_or_empty(verdict.get("attack_story")), start=1):
            if not isinstance(step, dict):
                self.add("error", "story_schema", f"attack_story[{index}]", "story step is not an object")
                continue
            step_claims = string_list(step.get("supporting_claim_ids"))
            step_unknown_claims = sorted(set(step_claims) - known_claim_ids)
            if step_unknown_claims:
                self.add(
                    "error",
                    "story_claim",
                    f"attack_story[{index}]",
                    "story step cites claim ids not supplied to the verdict task",
                    {"unknown_claim_ids": step_unknown_claims},
                )
            allowed_refs = set()
            for claim_id in step_claims:
                allowed_refs.update(refs_by_claim.get(claim_id, set()))
            step_refs = set(string_list(step.get("evidence_ref_ids")))
            unknown_refs = sorted(step_refs - allowed_refs) if allowed_refs else sorted(step_refs)
            if unknown_refs:
                self.add(
                    "error",
                    "story_evidence",
                    f"attack_story[{index}]",
                    "story step cites evidence refs not owned by its supporting claims",
                    {"unknown_evidence_ref_ids": unknown_refs},
                )

    def audit_claim_semantics(self, subject: str, claim: dict[str, Any]) -> None:
        if claim.get("schema_version") == "harness-reasoned-claim-v1":
            from harness.behavior.reasoning import LEGACY_FIELDS, text, texts
            try:
                if set(claim) & LEGACY_FIELDS:
                    raise ValueError("reasoned claim contains legacy decision-control fields")
                text(claim.get("behavior_interpretation"), "behavior_interpretation")
                texts(claim.get("observed_operations"), "observed_operations", required=True)
            except ValueError as exc:
                self.add("error", "claim_schema", subject, str(exc))
            return
        behavior_class = str(claim.get("behavior_class") or "")
        risk_primitives = string_list(claim.get("risk_primitives") or claim.get("risk_primitive"))
        dual_use_primitives = string_list(claim.get("dual_use_primitives") or claim.get("dual_use_primitive"))
        if behavior_class not in CLAIM_BEHAVIOR_CLASSES:
            self.add(
                "error",
                "claim_semantics",
                subject,
                "candidate claim is missing a valid behavior_class",
                {"behavior_class": behavior_class},
            )
            return
        if behavior_class in {"malicious_only", "static_strong"} and not risk_primitives:
            self.add(
                "error",
                "claim_semantics",
                subject,
                "risk-bearing behavior_class must include risk_primitives",
                {"behavior_class": behavior_class},
            )
        if behavior_class == "dual_use" and not dual_use_primitives:
            self.add(
                "warning",
                "claim_semantics",
                subject,
                "dual-use behavior_class should include dual_use_primitives",
            )

    def memory_refs_for_task(self, task_id: str) -> tuple[set[str], set[str]]:
        result = self.state.task_results.get(task_id)
        if result is None or "local_memory" not in result.artifacts:
            return set(), set()
        memory = load_json_safely(Path(result.artifacts["local_memory"].path), default={})
        refs: set[str] = set()
        blocks: set[str] = set()
        for fact in list_or_empty(memory.get("facts") if isinstance(memory, dict) else None):
            if not isinstance(fact, dict):
                continue
            refs.update(string_list(fact.get("evidence_ref_ids")))
            blocks.update(string_list(fact.get("block_ids")))
        return refs, blocks

    def add(self, severity: str, category: str, subject: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.issues.append(EvidenceAuditIssue(severity, category, subject, message, details or {}))


def task_metric_record(
    spec: TaskSpec,
    result: TaskResult,
    duration_seconds: float | None,
    state: AnalysisSessionState,
) -> dict[str, Any]:
    missing_expected = [
        name for name in spec.output_names
        if result.status == "completed" and name not in result.artifacts
    ]
    missing_artifacts = [
        ref.artifact_id for ref in result.artifacts.values()
        if not Path(ref.path).exists()
    ]
    return {
        "task_id": spec.task_id,
        "task_type": spec.task_type,
        "profile": spec.profile,
        "status": result.status,
        "duration_seconds": duration_seconds,
        "artifact_count": len(result.artifacts),
        "fact_count": len(result.facts),
        "state_artifact_count": len(state.artifacts),
        "state_fact_count": len(state.facts),
        "missing_expected_outputs": missing_expected,
        "missing_artifact_ids": missing_artifacts,
    }


def artifact_ref_or_none(state: AnalysisSessionState, artifact_id: str):
    try:
        return state.artifact(artifact_id)
    except KeyError:
        return None


def is_absent_or_uncertain(claim_type: str) -> bool:
    value = claim_type.casefold()
    return value.endswith("_absent") or value.endswith("_uncertain") or "absent" in value or "uncertain" in value


def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None and str(item) != ""]
    return [str(value)]


def list_or_empty(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def load_json_safely(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

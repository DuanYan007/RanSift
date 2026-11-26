"""Two-stage semantic review for sample-level verdict artifacts."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from harness.behavior.llm_loop import JSONChatClient

from harness.behavior.coverage import aggregate_analysis_coverage, is_sufficient_analysis_coverage
from .models import SessionFact, TaskContext, TaskHandler, TaskResult, TaskSpec
from harness.behavior.classification import (
    MALICIOUS_POLICY_PRIMITIVES,
    annotate_claim_semantics,
    OBSERVATION_BOUNDARY_POLICY,
    claim_dual_use_primitives,
    claim_policy_primitives,
    cross_claim_policy_primitives,
    has_only_dual_use_or_absent_claims,
    is_risk_relevant_claim,
    is_static_claim_like as is_static_claim,
    is_uncertain_or_absent_claim_like as is_uncertain_or_absent_claim,
)

from .verdict import TASK_SYNTHESIZE_SAMPLE_VERDICT, VERDICT_LABELS, string_list

TASK_PRE_REVIEW_SAMPLE_VERDICT = "pre_review_sample_verdict"
TASK_REVIEW_SAMPLE_VERDICT = "review_sample_verdict"
TASK_FINALIZE_SAMPLE_DECISION = "finalize_sample_decision"
VERDICT_PRE_REVIEW_OUTPUTS = ("verdict_pre_review",)
VERDICT_REVIEW_OUTPUTS = ("verdict_review", "verdict_review_input", "verdict_review_model_response")
SAMPLE_DECISION_OUTPUTS = ("sample_decision",)
STATIC_RUNTIME_VERBS = re.compile(
    r"\b(executed|execute|launched|launch|ran|run|started|start|wrote|write|created|create|"
    r"deleted|delete|stopped|stop|modified|modify|dropped|drop|removed|remove)\b",
    flags=re.IGNORECASE,
)
STATIC_QUALIFIERS = re.compile(r"\b(static|statically|embedded|contains|contained|template|string|command)\b", flags=re.IGNORECASE)


@dataclass(frozen=True)
class VerdictReviewIssue:
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


def verdict_pre_review_task_handlers() -> dict[str, TaskHandler]:
    return {TASK_PRE_REVIEW_SAMPLE_VERDICT: pre_review_sample_verdict_task}


def verdict_review_task_handlers(client: JSONChatClient) -> dict[str, TaskHandler]:
    return {TASK_REVIEW_SAMPLE_VERDICT: lambda context: review_sample_verdict_task(context, client)}


def verdict_finalization_task_handlers() -> dict[str, TaskHandler]:
    return {TASK_FINALIZE_SAMPLE_DECISION: finalize_sample_decision_task}




def build_verdict_pre_review_task_spec(
    task_id: str = TASK_PRE_REVIEW_SAMPLE_VERDICT,
    dependencies: tuple[str, ...] = (TASK_SYNTHESIZE_SAMPLE_VERDICT,),
    evidence_audit_path: str | Path | None = None,
) -> TaskSpec:
    parameters: dict[str, Any] = {}
    if evidence_audit_path is not None:
        parameters["evidence_audit_path"] = str(evidence_audit_path)
    return TaskSpec(
        task_id=task_id,
        task_type=TASK_PRE_REVIEW_SAMPLE_VERDICT,
        profile="deterministic_verdict_pre_review",
        dependencies=dependencies,
        parameters=parameters,
        output_names=VERDICT_PRE_REVIEW_OUTPUTS,
        acceptance_criteria=(
            "verdict label belongs to the allowed label set",
            "hard contradictions are surfaced before LLM review",
            "static-only evidence is not overstated as runtime execution",
            "claim uncertainty and benign alternatives remain visible",
        ),
    )


def build_verdict_review_task_spec(
    task_id: str = TASK_REVIEW_SAMPLE_VERDICT,
    dependencies: tuple[str, ...] = (TASK_PRE_REVIEW_SAMPLE_VERDICT,),
    evidence_audit_path: str | Path | None = None,
    analysis_protocol: str = "legacy-v1",
) -> TaskSpec:
    parameters: dict[str, Any] = {}
    if evidence_audit_path is not None:
        parameters["evidence_audit_path"] = str(evidence_audit_path)
    return TaskSpec(
        task_id=task_id,
        task_type=TASK_REVIEW_SAMPLE_VERDICT,
        profile="llm_verdict_reviewer",
        dependencies=dependencies,
        parameters=parameters,
        output_names=VERDICT_REVIEW_OUTPUTS + (
            ("reviewed_sample_verdict", "reviewed_pre_review", "verdict_revision_history") if analysis_protocol == "evidence-reasoning-v2"
            else ("reviewed_sample_verdict", "reviewed_pre_review", "adjudication_history", "adjudication_model_response") if analysis_protocol == "evidence-binary-v1"
            else ()
        ),
        acceptance_criteria=(
            "LLM reviewer consumes only verdict, claims, bounded coverage, evidence audit, and pre-review artifacts",
            "reviewer does not query logs, call evidence tools, or create new claims",
            "reviewer assesses semantic support, story fidelity, static/dynamic boundaries, and uncertainty",
            "hard pre-review failures cannot be downgraded to pass by the LLM reviewer",
        ),
    )

def build_sample_decision_task_spec(
    task_id: str = TASK_FINALIZE_SAMPLE_DECISION,
    dependencies: tuple[str, ...] = (TASK_REVIEW_SAMPLE_VERDICT,),
    evidence_audit_path: str | Path | None = None,
) -> TaskSpec:
    parameters: dict[str, Any] = {}
    if evidence_audit_path is not None:
        parameters["evidence_audit_path"] = str(evidence_audit_path)
    return TaskSpec(
        task_id=task_id,
        task_type=TASK_FINALIZE_SAMPLE_DECISION,
        profile="deterministic_sample_decision",
        dependencies=dependencies,
        parameters=parameters,
        output_names=SAMPLE_DECISION_OUTPUTS,
        acceptance_criteria=(
            "candidate verdict is retained for audit while the exported decision records finality",
            "no_risk is accepted only after sufficient bounded role coverage and passing audit gates",
            "coverage gaps withhold classification rather than converting absence into suspicious behavior",
            "review failures withhold the candidate label from the final decision",
        ),
    )



def load_verdict_input_coverage(context: TaskContext) -> dict[str, Any]:
    try:
        coverage_ref = context.state.artifact(f"{TASK_SYNTHESIZE_SAMPLE_VERDICT}:verdict_input_coverage")
    except KeyError:
        return aggregate_analysis_coverage([])
    coverage = load_json(Path(coverage_ref.path), default={})
    return coverage if isinstance(coverage, dict) else aggregate_analysis_coverage([])


def pre_review_sample_verdict_task(context: TaskContext) -> TaskResult:
    verdict_ref = context.state.artifact(f"{TASK_SYNTHESIZE_SAMPLE_VERDICT}:sample_verdict")
    claims_ref = context.state.artifact(f"{TASK_SYNTHESIZE_SAMPLE_VERDICT}:verdict_input_claims")
    verdict = load_json(Path(verdict_ref.path), default={})
    claims = load_json(Path(claims_ref.path), default=[])
    analysis_coverage = load_verdict_input_coverage(context)
    evidence_audit = load_optional_json(context.spec.parameters.get("evidence_audit_path"))
    report = pre_review_sample_verdict(context.state.sample_id, verdict, claims, evidence_audit, analysis_coverage)
    path = context.store.path_for(context.spec.task_id, "verdict_pre_review.json")
    write_json(path, report)
    artifacts = {
        "verdict_pre_review": context.store.artifact_ref(
            context.spec.task_id,
            "verdict_pre_review",
            "verdict_pre_review",
            path,
            {"status": report["status"], "issue_count": report["issue_count"]},
        )
    }
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:pre_review",
        kind="verdict_pre_review",
        data=report,
        source_task_id=context.spec.task_id,
        artifact_ids=(artifacts["verdict_pre_review"].artifact_id,),
    )
    diagnostics = {
        "schema_version": "verdict-pre-review-task-v1",
        "sample_id": context.state.sample_id,
        "status": report["status"],
        "issue_count": report["issue_count"],
        "verdict": report["verdict"],
        "claim_count": report["claim_profile"]["claim_count"],
    }
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=diagnostics)


def review_sample_verdict_task(context: TaskContext, client: JSONChatClient) -> TaskResult:
    verdict_ref = context.state.artifact(f"{TASK_SYNTHESIZE_SAMPLE_VERDICT}:sample_verdict")
    claims_ref = context.state.artifact(f"{TASK_SYNTHESIZE_SAMPLE_VERDICT}:verdict_input_claims")
    pre_review_ref = context.state.artifact(f"{TASK_PRE_REVIEW_SAMPLE_VERDICT}:verdict_pre_review")
    verdict = load_json(Path(verdict_ref.path), default={})
    claims = load_json(Path(claims_ref.path), default=[])
    analysis_coverage = load_verdict_input_coverage(context)
    pre_review = load_json(Path(pre_review_ref.path), default={})
    evidence_audit = load_optional_json(context.spec.parameters.get("evidence_audit_path"))
    payload = build_llm_review_request(
        context.state.sample_id, verdict, claims, analysis_coverage, evidence_audit, pre_review
    )
    response = client.complete_json((
        {"role": "system", "content": verdict_reviewer_system_prompt()},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=True, sort_keys=True)},
    ))
    report, model_response = normalize_llm_review_response(context.state.sample_id, response, pre_review, verdict)
    artifacts = materialize_llm_review_artifacts(context, payload, report, model_response)
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:review",
        kind="verdict_review",
        data=report,
        source_task_id=context.spec.task_id,
        artifact_ids=(artifacts["verdict_review"].artifact_id,),
    )
    diagnostics = {
        "schema_version": "verdict-review-task-v1",
        "sample_id": context.state.sample_id,
        "status": report["status"],
        "llm_status": report["llm_status"],
        "pre_review_status": report["pre_review_status"],
        "classification_status": report["classification_status"],
        "review_decision": report["review_decision"],
        "issue_count": len(report.get("evidence_issues", [])),
    }
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=diagnostics)


def finalize_sample_decision_task(context: TaskContext) -> TaskResult:
    verdict_ref = context.state.artifact(f"{TASK_SYNTHESIZE_SAMPLE_VERDICT}:sample_verdict")
    pre_review_ref = context.state.artifact(f"{TASK_PRE_REVIEW_SAMPLE_VERDICT}:verdict_pre_review")
    review_ref = context.state.artifact(f"{TASK_REVIEW_SAMPLE_VERDICT}:verdict_review")
    verdict = load_json(Path(verdict_ref.path), default={})
    pre_review = load_json(Path(pre_review_ref.path), default={})
    review = load_json(Path(review_ref.path), default={})
    coverage = load_verdict_input_coverage(context)
    evidence_audit = load_optional_json(context.spec.parameters.get("evidence_audit_path"))
    decision = finalize_sample_decision(verdict, coverage, evidence_audit, pre_review, review)
    path = context.store.path_for(context.spec.task_id, "sample_decision.json")
    write_json(path, decision)
    artifacts = {
        "sample_decision": context.store.artifact_ref(
            context.spec.task_id,
            "sample_decision",
            "sample_decision",
            path,
            {
                "status": decision["status"],
                "verdict": decision.get("verdict"),
                "candidate_verdict": decision.get("candidate_verdict"),
            },
        )
    }
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:decision",
        kind="sample_decision",
        data=decision,
        source_task_id=context.spec.task_id,
        artifact_ids=(artifacts["sample_decision"].artifact_id,),
    )
    diagnostics = {
        "schema_version": "sample-decision-task-v1",
        "sample_id": context.state.sample_id,
        "status": decision["status"],
        "verdict": decision.get("verdict"),
        "candidate_verdict": decision.get("candidate_verdict"),
        "reason_count": len(decision.get("reason_codes") or []),
    }
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=diagnostics)


def finalize_sample_decision(
    verdict: dict[str, Any] | None,
    analysis_coverage: dict[str, Any] | None,
    evidence_audit: dict[str, Any] | None,
    pre_review: dict[str, Any] | None,
    verdict_review: dict[str, Any] | None,
) -> dict[str, Any]:
    candidate = verdict if isinstance(verdict, dict) else {}
    coverage = analysis_coverage if isinstance(analysis_coverage, dict) else aggregate_analysis_coverage([])
    evidence = evidence_audit if isinstance(evidence_audit, dict) else {}
    pre = pre_review if isinstance(pre_review, dict) else {}
    review = verdict_review if isinstance(verdict_review, dict) else {}
    candidate_verdict = str(candidate.get("verdict") or "").strip()
    candidate_confidence = str(candidate.get("confidence") or "").strip()
    evidence_status = str(evidence.get("status") or "not_available")
    pre_status = str(pre.get("status") or "not_available")
    review_report_status = str(review.get("status") or "not_available")
    review_status = str(review.get("classification_status") or review_report_status)
    reason_codes: list[str] = []

    if candidate_verdict not in VERDICT_LABELS:
        reason_codes.append("candidate_verdict_invalid")
    if candidate_verdict == "no_risk" and not is_sufficient_analysis_coverage(coverage):
        reason_codes.append("analysis_coverage_insufficient")
    if candidate_verdict == "no_risk" and str(coverage.get("execution_observation_status") or "") == "insufficient":
        reason_codes.append("execution_observation_insufficient")
    if evidence_status != "pass":
        reason_codes.append("evidence_audit_not_pass")
    if pre_status != "pass":
        reason_codes.append("verdict_pre_review_not_pass")
    if review_status != "pass":
        reason_codes.append("verdict_review_not_pass")

    if candidate_verdict == "no_risk" and (
        not is_sufficient_analysis_coverage(coverage)
        or str(coverage.get("execution_observation_status") or "") == "insufficient"
    ):
        status = "analysis_incomplete"
    elif reason_codes:
        status = "review_required"
    else:
        status = "accepted"

    accepted_verdict = candidate_verdict if status == "accepted" else None
    summary = (
        f"Accepted final verdict: {accepted_verdict}."
        if accepted_verdict
        else "No final classification was issued; the candidate verdict is retained only for audit."
    )
    return {
        "schema_version": "harness-sample-decision-v1",
        "status": status,
        "verdict": accepted_verdict,
        "confidence": candidate_confidence if accepted_verdict else "",
        "candidate_verdict": candidate_verdict,
        "candidate_confidence": candidate_confidence,
        "reason_codes": reason_codes,
        "analysis_coverage_status": str(coverage.get("status") or "not_available"),
        "evidence_audit_status": evidence_status,
        "verdict_pre_review_status": pre_status,
        "verdict_review_status": review_status,
        "verdict_review_report_status": review_report_status,
        "summary": summary,
    }


def pre_review_sample_verdict(
    sample_id: str,
    verdict: dict[str, Any],
    claims: list[dict[str, Any]],
    evidence_audit: dict[str, Any] | None = None,
    analysis_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reviewer = VerdictPreReviewer(
        sample_id,
        verdict if isinstance(verdict, dict) else {},
        claims,
        evidence_audit,
        analysis_coverage,
    )
    return reviewer.run()


class VerdictPreReviewer:
    def __init__(
        self,
        sample_id: str,
        verdict: dict[str, Any],
        claims: list[dict[str, Any]],
        evidence_audit: dict[str, Any] | None,
        analysis_coverage: dict[str, Any] | None,
    ) -> None:
        self.sample_id = sample_id
        self.verdict = verdict
        self.claims = [claim for claim in claims if isinstance(claim, dict)]
        self.evidence_audit = evidence_audit if isinstance(evidence_audit, dict) else None
        self.analysis_coverage = analysis_coverage if isinstance(analysis_coverage, dict) else aggregate_analysis_coverage([])
        self.issues: list[VerdictReviewIssue] = []

    def run(self) -> dict[str, Any]:
        label = str(self.verdict.get("verdict") or "")
        self.review_schema(label)
        self.review_evidence_audit()
        self.review_label_support(label)
        self.review_attack_story()
        self.review_uncertainty_preservation()
        profile = build_claim_profile(self.claims)
        status = status_from_issues(self.issues)
        return {
            "schema_version": "harness-verdict-pre-review-v1",
            "sample_id": self.sample_id,
            "status": status,
            "verdict": label,
            "confidence": str(self.verdict.get("confidence") or ""),
            "issue_count": len(self.issues),
            "issues": [issue.to_dict() for issue in self.issues],
            "claim_profile": profile,
            "analysis_coverage": self.analysis_coverage,
            "evidence_audit_status": (self.evidence_audit or {}).get("status", "not_available"),
            "review_policy": {
                "decision_boundary": "deterministic hard guard before LLM verdict review",
                "does_not_query_logs": True,
                "does_not_create_evidence": True,
                "malicious_accepts_dynamic_or_strong_static_risk": True,
                "static_strong_supports_malicious_without_runtime_execution_claims": True,
                "cross_claim_malicious_primitives_are_enforced": True,
                "dual_use_behavior_does_not_contradict_no_risk": True,
                "no_risk_requires_bounded_role_coverage": True,
            },
        }

    def review_schema(self, label: str) -> None:
        if label not in VERDICT_LABELS:
            self.add("error", "verdict_schema", "sample_verdict", "verdict label is outside the allowed label set")
        if not isinstance(self.verdict.get("attack_story", []), list):
            self.add("error", "verdict_schema", "attack_story", "attack_story must be a list")

    def review_evidence_audit(self) -> None:
        if self.evidence_audit is None:
            self.add("warning", "audit_dependency", "evidence_audit", "evidence audit artifact was not available")
            return
        status = str(self.evidence_audit.get("status") or "")
        if status == "fail":
            self.add("error", "audit_dependency", "evidence_audit", "evidence audit failed before verdict review")
        elif status == "warn":
            self.add("warning", "audit_dependency", "evidence_audit", "evidence audit contains warnings")

    def review_label_support(self, label: str) -> None:
        profile = build_claim_profile(self.claims)
        dynamic_risk = profile["dynamic_risk_claim_ids"]
        static_risk = profile["static_risk_claim_ids"]
        uncertain_or_absent = profile["uncertain_or_absent_claim_ids"]
        dual_use = profile["dual_use_claim_ids"]
        strong_malicious = profile.get("strong_malicious_primitive_claim_ids", [])
        if label == "malicious":
            if not strong_malicious:
                self.add(
                    "error",
                    "verdict_support",
                    "sample_verdict",
                    "malicious verdict lacks a malicious-only policy primitive",
                    {
                        "dynamic_risk_claim_ids": dynamic_risk,
                        "static_risk_claim_ids": static_risk,
                        "uncertain_or_absent_claim_ids": uncertain_or_absent,
                    },
                )
            if not self.verdict.get("attack_story"):
                self.add("error", "story_support", "attack_story", "malicious verdict has no attack story")
        elif label == "suspicious":
            strong_malicious = profile.get("strong_malicious_primitive_claim_ids", [])
            if strong_malicious:
                self.add(
                    "error",
                    "verdict_support",
                    "sample_verdict",
                    "suspicious verdict understates supplied high-confidence destructive dynamic behavior",
                    {"strong_malicious_primitive_claim_ids": strong_malicious},
                )
            if not (dynamic_risk or static_risk or uncertain_or_absent or dual_use):
                self.add("error", "verdict_support", "sample_verdict", "suspicious verdict has no supplied risk-relevant, dual-use, or uncertainty claim")
            elif not (dynamic_risk or static_risk) and dual_use and has_only_dual_use_or_absent_claims(self.claims):
                self.add(
                    "warning",
                    "verdict_boundary",
                    "sample_verdict",
                    "suspicious verdict overstates evidence limited to dual-use or absent behavior",
                    {"dual_use_claim_ids": dual_use, "uncertain_or_absent_claim_ids": uncertain_or_absent},
                )
        elif label == "no_risk":
            contradiction = sorted(set(dynamic_risk + static_risk + profile.get("strong_malicious_primitive_claim_ids", [])))
            if contradiction:
                self.add(
                    "error",
                    "verdict_support",
                    "sample_verdict",
                    "no_risk verdict contradicts supplied strong risk claims",
                    {"contradicting_claim_ids": contradiction},
                )
            if not is_sufficient_analysis_coverage(self.analysis_coverage):
                self.add(
                    "error",
                    "negative_coverage",
                    "sample_verdict",
                    "no_risk verdict lacks sufficient bounded role coverage",
                    {
                        "coverage_status": str(self.analysis_coverage.get("status") or "not_available"),
                        "incomplete_agent_ids": list(self.analysis_coverage.get("incomplete_agent_ids") or []),
                    },
                )

    def review_attack_story(self) -> None:
        claim_by_id = {str(claim.get("claim_id")): claim for claim in self.claims}
        story = self.verdict.get("attack_story")
        if not isinstance(story, list):
            return
        if self.verdict.get("verdict") == "no_risk" and story:
            self.add(
                "error",
                "story_support",
                "attack_story",
                "no_risk verdict must not contain an attack story; use observed_behavior for dual-use or absent behavior",
            )

        for index, step in enumerate(story, start=1):
            if not isinstance(step, dict):
                continue
            claim_ids = [claim_id for claim_id in string_list(step.get("supporting_claim_ids")) if claim_id in claim_by_id]
            if not claim_ids:
                continue
            step_claims = [claim_by_id[claim_id] for claim_id in claim_ids]
            static_claims = [claim for claim in step_claims if is_static_claim(claim)]
            dynamic_claims = [claim for claim in step_claims if not is_static_claim(claim)]
            if static_claims and not dynamic_claims and static_step_overstates_runtime(step):
                self.add(
                    "error",
                    "static_overstatement",
                    f"attack_story[{index}]",
                    "static-only story step describes runtime execution",
                    {"supporting_claim_ids": claim_ids},
                )
            if static_claims and dynamic_claims and static_step_overstates_runtime(step):
                self.add(
                    "warning",
                    "static_dynamic_mixing",
                    f"attack_story[{index}]",
                    "story step mixes static and dynamic claims without clearly bounding static evidence",
                    {"supporting_claim_ids": claim_ids},
                )

    def review_uncertainty_preservation(self) -> None:
        claim_uncertainties = [
            claim for claim in self.claims
            if string_list(claim.get("uncertainty")) or string_list(claim.get("alternative_explanations")) or claim.get("confidence") == "low"
        ]
        if not claim_uncertainties:
            return
        verdict_uncertainty = (
            string_list(self.verdict.get("uncertainties"))
            + string_list(self.verdict.get("benign_alternatives"))
            + string_list(self.verdict.get("missing_links"))
            + [str(item) for item in self.verdict.get("uncertain_observations", []) if item]
        )
        if not verdict_uncertainty:
            self.add(
                "warning",
                "uncertainty_preservation",
                "sample_verdict",
                "verdict omits uncertainty despite uncertain claims or benign alternatives",
                {"claim_ids": [str(claim.get("claim_id")) for claim in claim_uncertainties]},
            )

    def add(self, severity: str, category: str, subject: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.issues.append(VerdictReviewIssue(severity, category, subject, message, details or {}))


def build_llm_review_request(
    sample_id: str,
    verdict: dict[str, Any],
    claims: list[dict[str, Any]],
    analysis_coverage: dict[str, Any],
    evidence_audit: dict[str, Any] | None,
    pre_review: dict[str, Any],
) -> dict[str, Any]:
    return {
        "review_task": "semantic_verdict_review",
        "observation_boundary_policy": OBSERVATION_BOUNDARY_POLICY,
        "sample_id": sample_id,
        "review_boundary": {
            "allowed_inputs": ["sample_verdict", "verdict_input_claims", "verdict_input_coverage", "evidence_audit", "verdict_pre_review"],
            "forbidden_actions": ["read_raw_logs", "call_evidence_tools", "create_new_evidence_claims"],
        },
        "review_questions": [
            "Is the final verdict semantically supported by supplied claims?",
            "Does the attack story faithfully organize the cited claims without overstating causality or runtime execution?",
            "For a no_risk verdict, is analysis_coverage sufficient, is attack_story empty, and are dual-use, absent, or uncertain claims represented in observed_behavior without implying malicious behavior?",
            "Are static evidence, dynamic evidence, benign alternatives, and uncertainty kept distinct?",
            "If high-confidence dynamic claims show sample-attributed destructive behavior, strong static claims expose ransomware-specific templates, commands, or capability symbols, or a declared cross-claim malicious primitive has all of its cited claims, is malicious accepted while preserving evidence scope?",
            "What concrete revision is required if the verdict or story is not supportable?",
        ],
        "label_policy": {
            "malicious": "A sample-attributed destructive action, strong static ransomware evidence, or a declared cross-claim malicious primitive whose constituent claims are all supplied supports malicious. Missing later ransomware stages affect completeness and uncertainty, not the malicious label.",
            "suspicious": "Use suspicious for weak, ambiguous, unattributed, or incomplete ransomware-relevant indicators that do not meet malicious-only dynamic, strong static, or declared cross-claim malicious-primitive thresholds.",
            "no_risk": "Use no_risk when no ransomware-specific primitive is supported and bounded analysis_coverage is sufficient. An empty claim set can be valid only when role coverage proves the checked scope.",
            "dual_use_boundary": "Dual-use behavior appears in both benign and malicious software and must not be treated as malicious without a ransomware-specific primitive or harmful effect.",
        },
        "verdict": verdict if isinstance(verdict, dict) else {},
        "claims": [compact_claim_for_review(claim) for claim in claims if isinstance(claim, dict)],
        "analysis_coverage": analysis_coverage if isinstance(analysis_coverage, dict) else aggregate_analysis_coverage([]),
        "evidence_audit": compact_evidence_audit(evidence_audit),
        "pre_review": pre_review if isinstance(pre_review, dict) else {},
        "output_schema": {
            "review_decision": "accept|revise|reject",
            "severity": "pass|warn|fail",
            "recommended_verdict": "malicious|suspicious|no_risk|unchanged",
            "summary": "short paragraph",
            "verdict_assessment": "short paragraph",
            "story_assessment": "short paragraph",
            "static_boundary_assessment": "short paragraph",
            "uncertainty_assessment": "short paragraph",
            "evidence_issues": [
                {
                    "severity": "warning|error",
                    "category": "verdict_support|story_fidelity|static_boundary|uncertainty|benign_alternative|other",
                    "claim_ids": ["str"],
                    "evidence_ref_ids": ["str"],
                    "description": "str",
                    "recommended_fix": "str",
                }
            ],
            "required_revisions": ["str"],
        },
        "instruction": (
            "Return exactly one JSON object. Do not introduce evidence that is not present in the supplied claims. "
            "Use evidence_issues and required_revisions only for defects in the supplied verdict, attack story, or observed_behavior. "
            "A warning must identify a concrete unsatisfied property and an actionable revision; do not report a boundary that the supplied record already preserves. "
            "If the verdict should be preserved, put policy reminders in assessment fields, not in evidence_issues. "
            "For no_risk, first verify sufficient bounded analysis_coverage. An empty attack_story is expected; review observed_behavior instead and do not request an attack story. "
            "If pre_review has status fail, preserve the hard failure in your assessment. "
            "Treat strong static claims as malicious embedded-code evidence, but do not describe them as runtime execution unless dynamic claims support execution. "
            "Do not treat dual-use startup, dependency discovery, ordinary registry interaction, or absent anti-analysis findings as malicious-only behavior. "
            "Do not recommend downgrading a malicious verdict solely because the trace lacks encryption, ransom notes, or proof that a destructive recovery-inhibition command completed."
        ),
    }


def verdict_reviewer_system_prompt() -> str:
    return (
        "You are the semantic verdict reviewer for a harness-constrained ransomware sample analysis system. "
        "You do not inspect raw logs, request tools, or create new evidence. "
        "You review whether the final verdict and attack story faithfully follow supplied claims, "
        "pre-review constraints, and uncertainty. Return JSON only."
    )


def normalize_llm_review_response(
    sample_id: str,
    response: dict[str, Any],
    pre_review: dict[str, Any],
    verdict: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    model_response = json.loads(json.dumps(response, ensure_ascii=False))
    usage = response.get("_usage") if isinstance(response.get("_usage"), dict) else None
    payload = dict(response)
    payload.pop("_usage", None)

    evidence_issues = normalize_review_issues(payload.get("evidence_issues"))
    required_revisions = string_list(payload.get("required_revisions"))
    recommended_verdict = normalize_recommended_verdict(str(payload.get("recommended_verdict") or "unchanged"))
    decision = normalize_decision(str(payload.get("review_decision") or "revise"))
    declared_status = normalize_review_status(str(payload.get("severity") or payload.get("status") or status_from_decision(decision)))
    evidence_issues, required_revisions, reminder_adjustments = suppress_satisfied_no_risk_reminders(
        evidence_issues, required_revisions, verdict, pre_review
    )
    evidence_issues, required_revisions, story_reminder_adjustments = suppress_satisfied_story_policy_reminders(
        evidence_issues, required_revisions, verdict, pre_review
    )
    reminder_adjustments.extend(story_reminder_adjustments)
    decision_adjustments: list[str] = list(reminder_adjustments)
    if (
        decision == "accept"
        and declared_status == "warn"
        and recommended_verdict == "unchanged"
        and not evidence_issues
        and not required_revisions
        and reminder_adjustments
        and is_pre_review_supported_candidate(verdict, pre_review)
    ):
        declared_status = "pass"
        decision_adjustments.append("normalized_satisfied_reviewer_reminders_to_accept")
    if decision == "accept" and declared_status != "pass":
        decision = "revise"
        decision_adjustments.append("accept_changed_to_revise_due_to_declared_status")
    if decision == "accept" and (evidence_issues or required_revisions):
        decision = "revise"
        decision_adjustments.append("accept_changed_to_revise_due_to_issues_or_required_revisions")
    if (
        decision == "revise"
        and declared_status == "warn"
        and recommended_verdict == "unchanged"
        and not evidence_issues
        and not required_revisions
        and reminder_adjustments
        and str((verdict or {}).get("verdict") or pre_review.get("verdict") or "") != "no_risk"
        and is_pre_review_supported_candidate(verdict, pre_review)
    ):
        decision = "accept"
        declared_status = "pass"
        decision_adjustments.append("normalized_satisfied_candidate_revise_to_accept")
    if (
        decision == "revise"
        and declared_status == "warn"
        and recommended_verdict in {"unchanged", "no_risk"}
        and not evidence_issues
        and not required_revisions
        and is_pre_review_supported_no_risk(verdict, pre_review)
    ):
        decision = "accept"
        declared_status = "pass"
        decision_adjustments.append("normalized_satisfied_no_risk_revise_to_accept")


    llm_status = declared_status
    if decision == "reject":
        llm_status = max_status(llm_status, "fail")
    elif decision == "revise":
        llm_status = max_status(llm_status, "warn")

    issue_status = status_from_normalized_issues(evidence_issues)
    llm_status = max_status(llm_status, issue_status)
    pre_status = normalize_review_status(str(pre_review.get("status") or "not_available"))
    final_status = max_status(llm_status, pre_status)
    candidate_verdict = str(
        (verdict or {}).get("verdict") or pre_review.get("verdict") or ""
    ).strip()
    classification_status = classification_review_status(
        decision, recommended_verdict, candidate_verdict, pre_status
    )
    normalized = {
        "schema_version": "harness-verdict-llm-review-v1",
        "sample_id": sample_id,
        "status": final_status,
        "report_status": final_status,
        "classification_status": classification_status,
        "llm_status": llm_status,
        "pre_review_status": pre_status,
        "review_decision": decision,
        "recommended_verdict": recommended_verdict,
        "summary": str(payload.get("summary") or ""),
        "verdict_assessment": str(payload.get("verdict_assessment") or ""),
        "story_assessment": str(payload.get("story_assessment") or ""),
        "static_boundary_assessment": str(payload.get("static_boundary_assessment") or ""),
        "uncertainty_assessment": str(payload.get("uncertainty_assessment") or ""),
        "evidence_issues": evidence_issues,
        "required_revisions": required_revisions,
        "decision_adjustments": decision_adjustments,
        "pre_review_issue_count": int(pre_review.get("issue_count") or 0) if isinstance(pre_review, dict) else 0,
        "review_policy": {
            "decision_boundary": "LLM semantic reviewer after deterministic pre-review",
            "does_not_query_logs": True,
            "does_not_call_tools": True,
            "does_not_create_evidence": True,
            "pre_review_failures_are_hard_guards": True,
            "classification_gate_uses_recommended_verdict": True,
            "report_revisions_do_not_withhold_supported_label": True,
            "report_accept_requires_no_issues_or_required_revisions": True,
        },
    }
    if usage:
        normalized["model_usage"] = usage
    return normalized, model_response


def suppress_satisfied_story_policy_reminders(
    issues: list[dict[str, Any]],
    required_revisions: list[str],
    verdict: dict[str, Any] | None,
    pre_review: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    if not is_pre_review_supported_candidate(verdict, pre_review):
        return issues, required_revisions, []
    verdict_data = verdict if isinstance(verdict, dict) else {}
    pre_review_data = pre_review if isinstance(pre_review, dict) else {}
    kept_issues = [
        issue
        for issue in issues
        if not story_policy_reminder_is_satisfied(issue, verdict_data, pre_review_data)
    ]
    kept_revisions = [
        revision
        for revision in required_revisions
        if not story_policy_revision_is_satisfied(revision, verdict_data)
    ]
    adjustments: list[str] = []
    if len(kept_issues) != len(issues):
        adjustments.append("suppressed_satisfied_story_policy_reminder_issues")
    if len(kept_revisions) != len(required_revisions):
        adjustments.append("suppressed_satisfied_story_policy_reminder_revisions")
    return kept_issues, kept_revisions, adjustments


def is_pre_review_supported_candidate(
    verdict: dict[str, Any] | None,
    pre_review: dict[str, Any],
) -> bool:
    verdict_data = verdict if isinstance(verdict, dict) else {}
    pre_review_data = pre_review if isinstance(pre_review, dict) else {}
    label = str(verdict_data.get("verdict") or "")
    if (
        label not in VERDICT_LABELS
        or str(pre_review_data.get("status") or "") != "pass"
        or str(pre_review_data.get("verdict") or "") != label
    ):
        return False
    return label != "no_risk" or is_pre_review_supported_no_risk(verdict_data, pre_review_data)


def suppress_satisfied_no_risk_reminders(
    issues: list[dict[str, Any]],
    required_revisions: list[str],
    verdict: dict[str, Any] | None,
    pre_review: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    if not is_pre_review_supported_no_risk(verdict, pre_review):
        return issues, required_revisions, []
    verdict_data = verdict if isinstance(verdict, dict) else {}
    kept_issues = [issue for issue in issues if not no_risk_issue_is_satisfied_reminder(issue, verdict_data)]
    kept_revisions = [item for item in required_revisions if not no_risk_revision_is_satisfied_reminder(item, verdict_data)]
    adjustments: list[str] = []
    if len(kept_issues) != len(issues):
        adjustments.append("suppressed_no_risk_policy_reminder_issues")
    if len(kept_revisions) != len(required_revisions):
        adjustments.append("suppressed_no_risk_policy_reminder_revisions")
    return kept_issues, kept_revisions, adjustments


def is_pre_review_supported_no_risk(verdict: dict[str, Any] | None, pre_review: dict[str, Any]) -> bool:
    verdict_data = verdict if isinstance(verdict, dict) else {}
    pre_review_data = pre_review if isinstance(pre_review, dict) else {}
    label = str(verdict_data.get("verdict") or pre_review_data.get("verdict") or "")
    profile = pre_review_data.get("claim_profile") if isinstance(pre_review_data.get("claim_profile"), dict) else {}
    coverage = pre_review_data.get("analysis_coverage") if isinstance(pre_review_data.get("analysis_coverage"), dict) else {}
    if (
        label != "no_risk"
        or str(pre_review_data.get("status") or "") != "pass"
        or not is_sufficient_analysis_coverage(coverage)
    ):
        return False
    return all(
        int(profile.get(key) or 0) == 0
        for key in (
            "dynamic_risk_claim_count",
            "static_risk_claim_count",
            "strong_malicious_primitive_claim_count",
        )
    )


def story_policy_reminder_is_satisfied(
    issue: dict[str, Any],
    verdict: dict[str, Any],
    pre_review: dict[str, Any],
) -> bool:
    if str(issue.get("severity") or "") != "warning":
        return False
    category = str(issue.get("category") or "").casefold()
    claim_ids = set(string_list(issue.get("claim_ids")))
    if (
        claim_ids
        and review_item_requests_autostart_execution_boundary(issue)
        and all_story_steps_match(verdict, claim_ids, story_step_bounds_autostart_execution)
    ):
        return True
    if not is_preservation_only_reminder(issue):
        return False
    if category == "story_fidelity":
        dual_use_ids = set(
            string_list(
                (pre_review.get("claim_profile") or {}).get("dual_use_claim_ids")
                if isinstance(pre_review.get("claim_profile"), dict)
                else []
            )
        )
        if (
            bool(claim_ids)
            and claim_ids.issubset(dual_use_ids)
            and all_story_steps_match(verdict, claim_ids, story_step_explicitly_bounds_dual_use)
        ):
            return True
        return bool(claim_ids) and all_story_steps_match(
            verdict, claim_ids, story_step_preserves_uncertainty
        )
    if category in {"uncertainty", "verdict_support"}:
        return bool(claim_ids) and all_story_steps_match(
            verdict, claim_ids, story_step_preserves_uncertainty
        )
    return False


def is_preservation_only_reminder(issue: dict[str, Any]) -> bool:
    recommended_fix = str(issue.get("recommended_fix") or "").casefold()
    if contains_actionable_recommended_change(recommended_fix):
        return False
    text = review_item_text(issue)
    return any(
        term in text
        for term in (
            "preserve",
            "retain",
            "keep",
            "leave",
            "avoid upgrading",
            "do not upgrade",
            "not directly prove",
            "does not directly prove",
        )
    )


def story_policy_revision_is_satisfied(revision: str, verdict: dict[str, Any]) -> bool:
    text = str(revision).casefold()
    if review_item_requests_autostart_execution_boundary(text) and verdict_has_bounded_autostart_execution(verdict):
        return True
    return (
        not contains_actionable_recommended_change(text)
        and "suspicious" in text
        and any(term in text for term in ("run key", "run-key", "runonce", "run once", "autostart"))
        and any(term in text for term in ("preserve", "retain", "keep"))
        and any(term in text for term in ("do not downgrade", "not no_risk", "not `no_risk`"))
    )


def contains_actionable_recommended_change(text: str) -> bool:
    return any(
        term in text
        for term in (
            "add ",
            "remove ",
            "replace ",
            "missing ",
            "omits ",
            "omitted ",
            "not included",
            "revise",
            "fix",
            "correct",
            "rewrite",
            "change ",
        )
    )


def all_story_steps_match(
    verdict: dict[str, Any],
    claim_ids: set[str],
    predicate: Callable[[dict[str, Any]], bool],
) -> bool:
    covered_claim_ids: set[str] = set()
    for step in verdict.get("attack_story") or []:
        if not isinstance(step, dict):
            continue
        step_claim_ids = set(string_list(step.get("supporting_claim_ids")))
        matching_ids = claim_ids & step_claim_ids
        if not matching_ids:
            continue
        if not predicate(step):
            return False
        covered_claim_ids.update(matching_ids)
    return covered_claim_ids == claim_ids


def story_step_explicitly_bounds_dual_use(step: dict[str, Any]) -> bool:
    text = review_item_text(step)
    return (
        "dual-use" in text or "dual use" in text
    ) and any(
        term in text
        for term in (
            "not enough",
            "not sufficient",
            "does not establish",
            "does not prove",
            "not malicious",
        )
    )


def story_step_preserves_uncertainty(step: dict[str, Any]) -> bool:
    if not string_list(step.get("uncertainty")):
        return False
    text = review_item_text(step)
    return any(
        term in text
        for term in (
            "does not prove",
            "not by itself prove",
            "does not by itself prove",
            "does not establish",
            "does not demonstrate",
            "inconclusive",
            "uncertain",
            "no subsequent",
            "no later",
            "not observed",
            "not confirmed",
            "not shown",
            "not established",
            "not an autostart",
            "not a startup",
            "no separate observation",
        )
    )


def review_item_requests_autostart_execution_boundary(item: dict[str, Any] | str) -> bool:
    text = review_item_text(item)
    mentions_binding = any(
        term in text
        for term in ("run key", "run-key", "runonce", "run once", "autostart")
    )
    mentions_execution = any(
        term in text
        for term in ("execution", "execute", "executed", "logon", "reboot", "startup")
    )
    return mentions_binding and mentions_execution


def story_step_bounds_autostart_execution(step: dict[str, Any]) -> bool:
    text = review_item_text(step)
    if not any(term in text for term in ("run key", "run-key", "runonce", "run once", "autostart")):
        return False
    if not story_step_preserves_uncertainty(step):
        return False
    return not any(
        term in text
        for term in (
            "established registry-based autostart persistence",
            "established persistence",
            "creating a persistence mechanism",
            "created a persistence mechanism",
            "will execute",
            "will run",
            "executes at logon",
        )
    )


def verdict_has_bounded_autostart_execution(verdict: dict[str, Any]) -> bool:
    return any(
        isinstance(step, dict) and story_step_bounds_autostart_execution(step)
        for step in verdict.get("attack_story") or []
    )


def no_risk_issue_is_satisfied_reminder(issue: dict[str, Any], verdict: dict[str, Any]) -> bool:
    text = review_item_text(issue)
    if preserves_existing_no_risk(text):
        return True
    category = str(issue.get("category") or "").casefold()
    if category == "story_fidelity" and not verdict.get("attack_story"):
        if mentions_anti_analysis(text) and observed_behavior_bounds_topic(verdict, "anti"):
            return True
    return False


def no_risk_revision_is_satisfied_reminder(item: str, verdict: dict[str, Any]) -> bool:
    text = str(item).casefold()
    if preserves_existing_no_risk(text):
        return True
    if "attack story" in text and not verdict.get("attack_story") and any(term in text for term in ("not overstate", "does not overstate", "unsupported", "uncertain")):
        return True
    if "dual-use" in text and "malware inference" in text and observed_behavior_has_class(verdict, "dual_use"):
        return True
    return False


def preserves_existing_no_risk(text: str) -> bool:
    return (
        "no_risk" in text
        and not contains_actionable_change_request(text)
        and any(
            term in text
            for term in (
                "keep",
                "preserve",
                "consistent with",
                "right verdict",
                "supported as",
                "not with malicious",
            )
        )
    )


def contains_actionable_change_request(text: str) -> bool:
    return any(
        term in text
        for term in (
            "add observed",
            "add an observed",
            "observed_behavior is empty",
            "missing observed",
            "replace",
            "remove",
            "revise",
            "fix",
            "omits",
            "missing uncertainty",
        )
    )


def observed_behavior_bounds_topic(verdict: dict[str, Any], topic: str) -> bool:
    for item in verdict.get("observed_behavior", []):
        if not isinstance(item, dict):
            continue
        text = review_item_text(item)
        if topic not in text:
            continue
        if any(term in text for term in ("does not establish", "does not prove", "inconclusive", "uncertain", "unsupported", "not demonstrate")):
            return True
    return False


def observed_behavior_has_class(verdict: dict[str, Any], behavior_class: str) -> bool:
    for item in verdict.get("observed_behavior", []):
        if isinstance(item, dict) and str(item.get("behavior_class") or "").casefold() == behavior_class:
            return True
    return False


def mentions_anti_analysis(text: str) -> bool:
    return "anti-analysis" in text or "anti_analysis" in text


def review_item_text(item: dict[str, Any] | str) -> str:
    if isinstance(item, str):
        return item.casefold()
    parts: list[str] = []
    for value in item.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(element) for element in value)
    return " ".join(parts).casefold()

def materialize_llm_review_artifacts(
    context: TaskContext,
    review_input: dict[str, Any],
    report: dict[str, Any],
    model_response: dict[str, Any],
) -> dict[str, Any]:
    payloads = {
        "verdict_review": report,
        "verdict_review_input": review_input,
        "verdict_review_model_response": model_response,
    }
    filenames = {
        "verdict_review": "verdict_review.json",
        "verdict_review_input": "verdict_review_input.json",
        "verdict_review_model_response": "verdict_review_model_response.json",
    }
    artifacts = {}
    for name, payload in payloads.items():
        path = context.store.path_for(context.spec.task_id, filenames[name])
        write_json(path, payload)
        metadata = {"status": payload.get("status"), "decision": payload.get("review_decision")} if name == "verdict_review" else {}
        artifacts[name] = context.store.artifact_ref(context.spec.task_id, name, name, path, metadata)
    return artifacts


def compact_claim_for_review(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": str(claim.get("claim_id") or ""),
        "agent_id": str(claim.get("agent_id") or ""),
        "source": str(claim.get("source") or ""),
        "claim_type": str(claim.get("claim_type") or ""),
        "statement": str(claim.get("statement") or ""),
        "confidence": str(claim.get("confidence") or ""),
        "status": str(claim.get("status") or ""),
        "evidence_ref_ids": string_list(claim.get("evidence_ref_ids"))[:12],
        "supporting_block_ids": string_list(claim.get("supporting_block_ids"))[:12],
        "supporting_rule_ids": string_list(claim.get("supporting_rule_ids"))[:12],
        "alternative_explanations": string_list(claim.get("alternative_explanations"))[:8],
        "uncertainty": string_list(claim.get("uncertainty"))[:8],
        "behavior_class": str(claim.get("behavior_class") or ""),
        "risk_primitives": string_list(claim.get("risk_primitives") or claim.get("risk_primitive"))[:12],
        "policy_primitives": claim_policy_primitives(claim),
        "dual_use_primitives": claim_dual_use_primitives(claim),
        "evidence_scope": "static" if is_static_claim(claim) else "dynamic",
    }


def compact_evidence_audit(evidence_audit: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(evidence_audit, dict):
        return {"status": "not_available", "issue_count": 0, "issues": []}
    return {
        "status": evidence_audit.get("status", "not_available"),
        "issue_count": evidence_audit.get("issue_count", 0),
        "issues": evidence_audit.get("issues", [])[:20] if isinstance(evidence_audit.get("issues"), list) else [],
    }


def build_claim_profile(claims: list[dict[str, Any]]) -> dict[str, Any]:
    normalized_claims = [
        annotate_claim_semantics(dict(claim))
        for claim in claims
        if isinstance(claim, dict)
    ]
    dynamic_risk: list[str] = []
    static_risk: list[str] = []
    uncertain_or_absent: list[str] = []
    dual_use: list[str] = []
    strong_malicious: list[str] = []
    for claim in normalized_claims:
        claim_id = str(claim.get("claim_id") or "")
        if not claim_id:
            continue
        if is_uncertain_or_absent_claim(claim):
            uncertain_or_absent.append(claim_id)
            continue
        malicious_primitives = claim_policy_primitives(claim)
        if malicious_primitives:
            strong_malicious.append(claim_id)
            if is_static_claim(claim):
                static_risk.append(claim_id)
            else:
                dynamic_risk.append(claim_id)
            continue
        if claim_dual_use_primitives(claim):
            dual_use.append(claim_id)
            continue
        behavior_class = str(claim.get("behavior_class") or "").casefold()
        if behavior_class in {"malicious_only", "risk_relevant", "static_strong"}:
            if is_static_claim(claim):
                static_risk.append(claim_id)
            else:
                dynamic_risk.append(claim_id)
            continue
        if not is_risk_relevant_claim(claim):
            continue
        if is_static_claim(claim):
            static_risk.append(claim_id)
        else:
            dynamic_risk.append(claim_id)
    cross_claim_malicious_primitives: list[dict[str, Any]] = []
    for fusion in cross_claim_policy_primitives(normalized_claims):
        primitive = str(fusion.get("primitive") or "")
        claim_ids = [claim_id for claim_id in string_list(fusion.get("claim_ids")) if claim_id]
        if primitive not in MALICIOUS_POLICY_PRIMITIVES or len(claim_ids) < 2:
            continue
        cross_claim_malicious_primitives.append({
            "primitive": primitive,
            "claim_ids": claim_ids,
        })
        strong_malicious.extend(claim_ids)
    strong_malicious = list(dict.fromkeys(strong_malicious))
    return {
        "claim_count": len(normalized_claims),
        "dynamic_risk_claim_count": len(dynamic_risk),
        "static_risk_claim_count": len(static_risk),
        "uncertain_or_absent_claim_count": len(uncertain_or_absent),
        "dual_use_claim_count": len(dual_use),
        "strong_malicious_primitive_claim_count": len(strong_malicious),
        "dynamic_risk_claim_ids": dynamic_risk,
        "static_risk_claim_ids": static_risk,
        "uncertain_or_absent_claim_ids": uncertain_or_absent,
        "dual_use_claim_ids": dual_use,
        "strong_malicious_primitive_claim_ids": strong_malicious,
        "cross_claim_malicious_primitive_count": len(cross_claim_malicious_primitives),
        "cross_claim_malicious_primitives": cross_claim_malicious_primitives,
        "only_dual_use_or_absent": has_only_dual_use_or_absent_claims(normalized_claims),
    }

def static_step_overstates_runtime(step: dict[str, Any]) -> bool:
    text = " ".join(str(step.get(field) or "") for field in ("step", "action", "effect", "target"))
    return bool(STATIC_RUNTIME_VERBS.search(text)) and not bool(STATIC_QUALIFIERS.search(text))


def normalize_review_issues(value: Any) -> list[dict[str, Any]]:
    issues = []
    if not isinstance(value, list):
        return issues
    for item in value:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "warning")
        if severity not in {"warning", "error"}:
            severity = "warning"
        issues.append({
            "severity": severity,
            "category": str(item.get("category") or "other"),
            "claim_ids": string_list(item.get("claim_ids")),
            "evidence_ref_ids": string_list(item.get("evidence_ref_ids")),
            "description": str(item.get("description") or ""),
            "recommended_fix": str(item.get("recommended_fix") or ""),
        })
    return issues


def classification_review_status(
    decision: str,
    recommended_verdict: str,
    candidate_verdict: str,
    pre_review_status: str,
) -> str:
    """Return the publication gate for the label, independent of report edits."""
    if normalize_review_status(pre_review_status) != "pass":
        return normalize_review_status(pre_review_status)
    if candidate_verdict not in VERDICT_LABELS:
        return "fail"
    if decision == "reject":
        return "fail"
    if recommended_verdict not in {"unchanged", candidate_verdict}:
        return "fail"
    return "pass"


def normalize_decision(value: str) -> str:
    text = value.strip().casefold()
    return text if text in {"accept", "revise", "reject"} else "revise"


def normalize_recommended_verdict(value: str) -> str:
    text = value.strip().casefold()
    return text if text in set(VERDICT_LABELS) | {"unchanged"} else "unchanged"


def normalize_review_status(value: str) -> str:
    text = value.strip().casefold()
    return text if text in {"pass", "warn", "fail"} else "warn"


def status_from_decision(decision: str) -> str:
    if decision == "accept":
        return "pass"
    if decision == "reject":
        return "fail"
    return "warn"


def status_from_issues(issues: list[VerdictReviewIssue]) -> str:
    if any(issue.severity == "error" for issue in issues):
        return "fail"
    if any(issue.severity == "warning" for issue in issues):
        return "warn"
    return "pass"


def max_status(*statuses: str) -> str:
    rank = {"pass": 0, "warn": 1, "fail": 2}
    normalized = [normalize_review_status(status) for status in statuses]
    return max(normalized, key=lambda status: rank[status])


def status_from_normalized_issues(issues: list[dict[str, Any]]) -> str:
    if any(issue.get("severity") == "error" for issue in issues):
        return "fail"
    if any(issue.get("severity") == "warning" for issue in issues):
        return "warn"
    return "pass"


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def load_optional_json(value: Any) -> dict[str, Any] | None:
    if not value:
        return None
    data = load_json(Path(str(value)), default=None)
    return data if isinstance(data, dict) else None


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

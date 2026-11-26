"""Task handler for sample-level verdict synthesis from evidence claims."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness.behavior.llm_loop import JSONChatClient
from harness.behavior.classification import (
    DUAL_USE_POLICY_PRIMITIVES,
    MALICIOUS_POLICY_PRIMITIVES,
    OBSERVATION_BOUNDARY_POLICY,
    annotate_claim_semantics,
    claim_dual_use_primitives,
    claim_policy_primitives,
    cross_claim_policy_primitives,
    has_deterministic_run_key_executable_binding,
    has_only_dual_use_or_absent_claims,
    no_risk_blocking_claim_ids,
    is_risk_relevant_claim,
    is_uncertain_or_absent_claim_like,
)

from harness.behavior.coverage import aggregate_analysis_coverage, is_sufficient_analysis_coverage
from .models import SessionFact, TaskContext, TaskHandler, TaskResult, TaskSpec

TASK_SYNTHESIZE_SAMPLE_VERDICT = "synthesize_sample_verdict"
VERDICT_LABELS = ("malicious", "suspicious", "no_risk")
CONFIDENCE_LEVELS = ("low", "medium", "high")
VERDICT_OUTPUTS = ("sample_verdict", "verdict_input_claims", "verdict_input_coverage", "verdict_model_response")
def verdict_task_handlers(client: JSONChatClient) -> dict[str, TaskHandler]:
    return {TASK_SYNTHESIZE_SAMPLE_VERDICT: lambda context: synthesize_sample_verdict_task(context, client)}


def build_verdict_task_spec(
    task_id: str = "synthesize_sample_verdict",
    dependencies: tuple[str, ...] = (),
    input_artifacts: dict[str, str] | None = None,
    task_prompt: str | None = None,
    analysis_protocol: str = "legacy-v1",
) -> TaskSpec:
    parameters: dict[str, Any] = {}
    if task_prompt:
        parameters["task_prompt"] = task_prompt
    return TaskSpec(
        task_id=task_id,
        task_type=TASK_SYNTHESIZE_SAMPLE_VERDICT,
        profile="sample_verdict",
        dependencies=dependencies,
        input_artifacts=input_artifacts or {},
        parameters=parameters,
        output_names=VERDICT_OUTPUTS + (("verdict_input_observations",) if analysis_protocol in {"evidence-reasoning-v1", "evidence-reasoning-v2", "evidence-binary-v1"} else ()),
        acceptance_criteria=(
            "verdict uses only committed or declared candidate-claim artifacts",
            "no-risk conclusions consume bounded role coverage separately from positive claims",
            "supporting_claim_ids cite supplied claim ids",
            "attack-story steps cite supplied claim ids and claim-owned evidence refs",
            "uncertainty and benign alternatives are preserved",
        ),
    )


def synthesize_sample_verdict_task(context: TaskContext, client: JSONChatClient) -> TaskResult:
    claims = collect_candidate_claims(context)
    analysis_coverage = collect_analysis_coverage(context)
    payload = build_verdict_request(context, claims, analysis_coverage)
    response = client.complete_json((
        {"role": "system", "content": verdict_system_prompt()},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=True, sort_keys=True)},
    ))
    verdict, model_response = normalize_verdict_response(response, claims, analysis_coverage)
    artifacts = materialize_verdict_artifacts(context, claims, analysis_coverage, verdict, model_response)
    fact = SessionFact(
        fact_id=f"{context.spec.task_id}:verdict",
        kind="sample_verdict",
        data=verdict,
        source_task_id=context.spec.task_id,
        artifact_ids=(artifacts["sample_verdict"].artifact_id,),
    )
    diagnostics = {
        "schema_version": "sample-verdict-task-v1",
        "sample_id": context.state.sample_id,
        "claim_count": len(claims),
        "analysis_coverage_status": analysis_coverage["status"],
        "verdict": verdict["verdict"],
        "confidence": verdict["confidence"],
        "supporting_claim_count": len(verdict.get("supporting_claim_ids", [])),
        "story_step_count": len(verdict.get("attack_story", [])),
    }
    return TaskResult.completed(context.spec.task_id, artifacts=artifacts, facts=(fact,), diagnostics=diagnostics)


def collect_candidate_claims(context: TaskContext) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for fact in context.state.facts_by_kind("candidate_claim"):
        claims.append(normalize_claim(fact.data, source=fact.source_task_id, artifact_id=next(iter(fact.artifact_ids), "")))
    for name, artifact_id in sorted(context.spec.input_artifacts.items()):
        ref = context.state.artifact(artifact_id)
        claims.extend(load_claim_artifact(Path(ref.path), source=name, artifact_id=ref.artifact_id))
    return sorted(claims, key=lambda item: (str(item.get("agent_id") or ""), str(item.get("claim_id") or "")))


def collect_analysis_coverage(context: TaskContext) -> dict[str, Any]:
    records = [dict(fact.data) for fact in context.state.facts_by_kind("role_coverage")]
    return aggregate_analysis_coverage(records)


def load_claim_artifact(path: Path, source: str, artifact_id: str) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        records = data.get("claims") if isinstance(data.get("claims"), list) else [data]
    elif isinstance(data, list):
        records = data
    else:
        records = []
    return [normalize_claim(record, source=source, artifact_id=artifact_id) for record in records if isinstance(record, dict)]


def normalize_claim(claim: dict[str, Any], source: str, artifact_id: str) -> dict[str, Any]:
    original_claim_id = str(claim.get("claim_id") or "claim")
    agent_id = str(claim.get("agent_id") or source)
    qualified_claim_id = f"{source}:{original_claim_id}"
    normalized = {
        "claim_id": qualified_claim_id,
        "original_claim_id": original_claim_id,
        "source": source,
        "source_artifact_id": artifact_id,
        "agent_id": agent_id,
        "claim_type": str(claim.get("claim_type") or "behavior_observation"),
        "statement": str(claim.get("statement") or ""),
        "confidence": normalize_confidence(str(claim.get("confidence") or "medium")),
        "status": str(claim.get("status") or "candidate"),
        "evidence_ref_ids": string_list(claim.get("evidence_ref_ids")),
        "supporting_block_ids": string_list(claim.get("supporting_block_ids")),
        "supporting_rule_ids": string_list(claim.get("supporting_rule_ids")),
        "alternative_explanations": string_list(claim.get("alternative_explanations")),
        "uncertainty": string_list(claim.get("uncertainty")),
        "behavior_primitives": string_list(claim.get("behavior_primitives") or claim.get("behavior_primitive")),
        "behavior_class": str(claim.get("behavior_class") or ""),
        "risk_primitives": string_list(claim.get("risk_primitives") or claim.get("risk_primitive")),
        "dual_use_primitives": string_list(claim.get("dual_use_primitives") or claim.get("dual_use_primitive")),
    }
    return annotate_claim_semantics(normalized)


def build_verdict_request(
    context: TaskContext,
    claims: list[dict[str, Any]],
    analysis_coverage: dict[str, Any],
) -> dict[str, Any]:
    return {
        "task": {
            "task_id": context.spec.task_id,
            "sample_id": context.state.sample_id,
            "question": "Does the submitted sample exhibit ransomware risk based on the supplied evidence claims?",
            "task_prompt": context.spec.parameters.get("task_prompt") or "Synthesize a sample-level ransomware-risk verdict.",
        },
        "allowed_verdicts": list(VERDICT_LABELS),
        "analysis_coverage": analysis_coverage,
        "decision_policy": {
            "observation_boundary": OBSERVATION_BOUNDARY_POLICY,
            "malicious": "Use when concrete sample-attributed behavior or strong static ransomware evidence demonstrates a malicious-only or strongly malicious primitive. A complete ransomware chain is not required once such behavior or strong static capability evidence is supported.",
            "suspicious": "Use when evidence is risk-relevant but weak, ambiguous, or incomplete, and no malicious-only dynamic primitive or strong static ransomware evidence is supported.",
            "no_risk": "Use when the supplied analysis_coverage has status sufficient and there are no positive claims, or every positive claim is explicitly bounded as dual-use or absent. A bounded completed_no_evidence role record is negative coverage, not a positive behavior claim.",
            "boundary": "Missing encryption, ransom-note evidence, or post-command success lowers completeness/confidence and belongs in missing_links or uncertainties; it does not downgrade a sample-attributed destructive recovery-inhibition command from malicious to suspicious.",
            "dual_use_boundary": "Startup, dependency loading, system DLL discovery, ordinary registry access, and failed registry access can appear in benign and malicious software. They must not be treated as malicious without a ransomware-specific primitive or harmful effect.",
        },
        "static_evidence_policy": {
            "scope": "Static strong claims indicate embedded ransomware-relevant templates, commands, or capability symbols; they do not prove runtime execution in the dynamic trace.",
            "use": "Use static strong claims as malicious evidence when they expose ransomware-specific behavior or capability. Preserve the static/dynamic boundary in the story.",
            "limit": "Do not state that a static command, capability, or note was executed unless a dynamic claim supports that execution."
        },
        "claims": claims,
        "story_policy": {
            "purpose": "Organize supplied claims into a chronological, reviewable attack story for malicious or suspicious verdicts. Do not perform new analysis.",
            "step_requirements": (
                "Each attack_story item must cite at least one supplied claim_id.",
                "Each attack_story item must cite only evidence_ref_ids already present in its supporting claims.",
                "Use phases from discovery, execution, persistence, recovery_inhibition, ransom_note, file_transformation, anti_analysis, impact, or other.",
                "Order attack_story by the earliest cited event evidence, not by phase order, when event references are available.",
                "Place weak or incomplete claims in uncertain_observations instead of the main chain when they do not advance the story.",
                "Use missing_links for absent causal links, such as command launched but effect not observed.",
                "For recovery-inhibition commands, describe execution, attempted impact, or targeted recovery artifacts unless supplied claims explicitly prove the destructive effect completed.",
                "For no_risk verdicts, leave attack_story empty and place dual-use or absent behavior in observed_behavior.",
            ),
        },
        "output_schema": {
            "verdict": "malicious|suspicious|no_risk",
            "confidence": "low|medium|high",
            "risk_summary": "short paragraph",
            "attack_story": [
                {
                    "step_id": "step_001",
                    "phase": "discovery|execution|persistence|recovery_inhibition|ransom_note|file_transformation|anti_analysis|impact|other",
                    "actor": "process or component from supplied claim text",
                    "action": "concrete behavior summarized from supplied claims",
                    "target": "affected target if present in supplied claims",
                    "effect": "security-relevant attempted or observed effect without overstating completion or intent",
                    "supporting_claim_ids": ["str"],
                    "evidence_ref_ids": ["str"],
                    "confidence": "low|medium|high",
                    "uncertainty": ["str"],
                }
            ],
            "observed_behavior": [
                {
                    "observation_id": "obs_001",
                    "behavior_class": "dual_use|absent|uncertain",
                    "summary": "non-attack behavior or absent finding summarized from supplied claims",
                    "supporting_claim_ids": ["str"],
                    "evidence_ref_ids": ["str"],
                    "confidence": "low|medium|high",
                    "interpretation": "why this does not establish ransomware risk",
                }
            ],
            "uncertain_observations": [
                {"claim_id": "str", "reason": "str", "evidence_ref_ids": ["str"]}
            ],
            "missing_links": ["str"],
            "supporting_claim_ids": ["str"],
            "benign_alternatives": ["str"],
            "uncertainties": ["str"],
            "recommended_follow_up": ["str"],
        },
        "instruction": (
            "Return exactly one JSON object. Use only supplied claim_id values in supporting_claim_ids. "
            "Attack-story evidence_ref_ids must come from the cited supporting claims. "
            "Order attack_story chronologically by cited event evidence; phase order is not chronology. "
            "Do not cite raw logs or claims that are not supplied. Preserve uncertainty instead of overstating intent. "
            "If a high-confidence dynamic claim shows sample-attributed destructive recovery inhibition, use malicious even when other ransomware stages are not observed. "
            "If a high-confidence static_strong claim exposes ransomware-specific templates, commands, or capability symbols, use malicious while preserving that execution was not dynamically proven. "
            "Treat a sufficient analysis_coverage record as bounded proof that configured roles completed their checks without a risk claim; do not require a positive benign claim for no_risk. "
            "Use no_risk only when every positive claim is explicitly bounded as dual-use or absent; an uncertain or unclassified observation remains suspicious until that boundary is established. "
            "For no_risk, leave attack_story empty and summarize the cited benign-compatible observations in observed_behavior. "
            "For destructive commands whose outcome is not observed, state that the sample executed or attempted the action, not that the destructive effect completed."
        ),
    }


def verdict_system_prompt() -> str:
    return (
        "You are the final verdict and attack-story organizer for a harness-constrained malware analysis system. "
        "You do not inspect raw logs and you do not discover new evidence. "
        "You combine supplied evidence claims into one sample-level risk verdict and a cited, chronological attack story. "
        "Every story step must be grounded in supplied claim ids and their evidence refs. Return JSON only."
    )


def normalize_verdict_response(
    response: dict[str, Any],
    claims: list[dict[str, Any]],
    analysis_coverage: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    claims = [annotate_claim_semantics(dict(claim)) for claim in claims]
    coverage = analysis_coverage if isinstance(analysis_coverage, dict) else aggregate_analysis_coverage([])
    model_response = json.loads(json.dumps(response, ensure_ascii=False))
    usage = response.get("_usage") if isinstance(response.get("_usage"), dict) else None
    payload = dict(response)
    payload.pop("_usage", None)
    known_claim_ids = {str(claim["claim_id"]) for claim in claims}
    evidence_refs_by_claim = {
        str(claim["claim_id"]): set(string_list(claim.get("evidence_ref_ids")))
        for claim in claims
    }
    all_known_evidence_refs = {ref for refs in evidence_refs_by_claim.values() for ref in refs}
    verdict = str(payload.get("verdict") or "suspicious")
    if verdict not in VERDICT_LABELS:
        verdict = "suspicious"
    verdict, policy_adjustments, policy_evidence = enforce_verdict_policy(verdict, claims)
    supporting_claim_ids = [item for item in string_list(payload.get("supporting_claim_ids")) if item in known_claim_ids]
    supporting_claim_ids = ordered_claim_ids(
        supporting_claim_ids + policy_evidence_claim_ids(policy_evidence)
    )
    attack_story = normalize_attack_story(
        payload.get("attack_story"),
        claims,
        known_claim_ids,
        evidence_refs_by_claim,
        all_known_evidence_refs,
    )
    observed_behavior: list[dict[str, Any]] = []
    if verdict == "no_risk":
        attack_story = []
        observed_behavior = default_observed_behavior(claims)
    else:
        if not attack_story:
            attack_story = default_attack_story(claims)
        attack_story = normalize_deterministic_autostart_story(attack_story, claims)
        attack_story = normalize_policy_fusion_story(attack_story, claims, policy_evidence)
    if not supporting_claim_ids:
        supporting_claim_ids = infer_supporting_claim_ids(claims, verdict)
    normalized = {
        "schema_version": "sample-verdict-v1",
        "verdict": verdict,
        "confidence": normalize_confidence(str(payload.get("confidence") or "medium")),
        "risk_summary": policy_adjusted_risk_summary(
            verdict,
            claims,
            policy_evidence,
            coverage,
            str(payload.get("risk_summary") or default_risk_summary(verdict, claims)),
        ),
        "attack_story": attack_story,
        "observed_behavior": observed_behavior,
        "uncertain_observations": normalize_uncertain_observations(payload.get("uncertain_observations"), claims),
        "missing_links": string_list(payload.get("missing_links")),
        "supporting_claim_ids": supporting_claim_ids,
        "benign_alternatives": string_list(payload.get("benign_alternatives")),
        "uncertainties": string_list(payload.get("uncertainties")),
        "recommended_follow_up": string_list(payload.get("recommended_follow_up")),
        "claim_count": len(claims),
        "analysis_coverage": coverage,
    }
    if policy_evidence:
        normalized["policy_evidence"] = policy_evidence
    if policy_adjustments:
        normalized["policy_adjustments"] = policy_adjustments
    if usage:
        normalized["model_usage"] = usage
    return normalized, model_response


def enforce_verdict_policy(verdict: str, claims: list[dict[str, Any]]) -> tuple[str, list[str], dict[str, Any]]:
    policy_evidence = build_policy_evidence(claims)
    malicious_items = policy_evidence["malicious_primitives"]
    malicious_claim_ids = policy_item_claim_ids(malicious_items)
    if verdict != "malicious" and malicious_claim_ids:
        static_claim_ids = policy_item_claim_ids([
            item for item in malicious_items
            if str(item.get("primitive") or "").startswith("embedded_")
        ])
        dynamic_claim_ids = sorted(set(malicious_claim_ids) - set(static_claim_ids))
        reason = "upgraded_to_malicious_due_to_malicious_policy_primitives"
        if static_claim_ids and not dynamic_claim_ids:
            reason = "upgraded_to_malicious_due_to_strong_static_ransomware_evidence"
        elif dynamic_claim_ids and not static_claim_ids:
            reason = "upgraded_to_malicious_due_to_sample_attributed_destructive_behavior"
        return "malicious", [
            reason,
            "supporting_claim_ids=" + ",".join(malicious_claim_ids),
        ], policy_evidence
    if verdict == "malicious" and not malicious_claim_ids:
        if has_only_dual_use_or_absent_claims(claims):
            dual_use_claim_ids = sorted({item["claim_id"] for item in policy_evidence["dual_use_primitives"]})
            return "no_risk", [
                "downgraded_to_no_risk_due_to_only_dual_use_or_absent_behavior",
                "supporting_claim_ids=" + ",".join(dual_use_claim_ids),
            ], policy_evidence
        risk_claim_ids = risk_relevant_claim_ids(claims)
        return "suspicious", [
            "downgraded_to_suspicious_due_to_no_malicious_policy_primitive",
            "supporting_claim_ids=" + ",".join(risk_claim_ids),
        ], policy_evidence
    if verdict == "no_risk":
        risk_claim_ids = risk_relevant_claim_ids(claims)
        if risk_claim_ids:
            return "suspicious", [
                "set_to_suspicious_due_to_risk_relevant_claims",
                "supporting_claim_ids=" + ",".join(risk_claim_ids),
            ], policy_evidence
        blocking_claim_ids = no_risk_blocking_claim_ids(claims)
        if blocking_claim_ids:
            return "suspicious", [
                "set_to_suspicious_due_to_non_benign_compatible_claims",
                "supporting_claim_ids=" + ",".join(blocking_claim_ids),
            ], policy_evidence
    if verdict == "suspicious" and has_only_dual_use_or_absent_claims(claims):
        dual_use_claim_ids = sorted({item["claim_id"] for item in policy_evidence["dual_use_primitives"]})
        return "no_risk", [
            "set_to_no_risk_due_to_only_dual_use_or_absent_behavior",
            "supporting_claim_ids=" + ",".join(dual_use_claim_ids),
        ], policy_evidence
    return verdict, [], policy_evidence


def risk_relevant_claim_ids(claims: list[dict[str, Any]]) -> list[str]:
    claim_ids: list[str] = []
    for claim in claims:
        claim_id = str(claim.get("claim_id") or "")
        if not claim_id or is_uncertain_or_absent_claim_like(claim):
            continue
        if claim_dual_use_primitives(claim):
            continue
        behavior_class = str(claim.get("behavior_class") or "").casefold()
        if behavior_class in {"malicious_only", "risk_relevant", "static_strong"}:
            claim_ids.append(claim_id)
            continue
        if claim_policy_primitives(claim) or is_risk_relevant_claim(claim):
            claim_ids.append(claim_id)
    return sorted(set(claim_ids))


def build_policy_evidence(claims: list[dict[str, Any]]) -> dict[str, Any]:
    malicious = []
    dual_use = []
    for claim in claims:
        for primitive in claim_policy_primitives(claim):
            if primitive in MALICIOUS_POLICY_PRIMITIVES:
                malicious.append({
                    "claim_id": str(claim.get("claim_id") or ""),
                    "primitive": primitive,
                    "definition": MALICIOUS_POLICY_PRIMITIVES[primitive],
                })
        for primitive in claim_dual_use_primitives(claim):
            if primitive in DUAL_USE_POLICY_PRIMITIVES:
                dual_use.append({
                    "claim_id": str(claim.get("claim_id") or ""),
                    "primitive": primitive,
                    "definition": DUAL_USE_POLICY_PRIMITIVES[primitive],
                })
    for fusion in cross_claim_policy_primitives(claims):
        primitive = str(fusion.get("primitive") or "")
        claim_ids = ordered_claim_ids(string_list(fusion.get("claim_ids")))
        if primitive not in MALICIOUS_POLICY_PRIMITIVES or len(claim_ids) < 2:
            continue
        malicious.append({
            "claim_id": claim_ids[0],
            "claim_ids": claim_ids,
            "primitive": primitive,
            "definition": MALICIOUS_POLICY_PRIMITIVES[primitive],
        })
    return {
        "malicious_primitives": [item for item in malicious if item["claim_id"]],
        "dual_use_primitives": [item for item in dual_use if item["claim_id"]],
    }


def policy_item_claim_ids(items: list[dict[str, Any]]) -> list[str]:
    claim_ids: list[str] = []
    for item in items:
        values = string_list(item.get("claim_ids")) or string_list(item.get("claim_id"))
        claim_ids.extend(values)
    return ordered_claim_ids(claim_ids)


def policy_evidence_claim_ids(policy_evidence: dict[str, Any]) -> list[str]:
    items = policy_evidence.get("malicious_primitives") if isinstance(policy_evidence, dict) else []
    return policy_item_claim_ids(items if isinstance(items, list) else [])


def ordered_claim_ids(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        claim_id = str(value or "")
        if claim_id and claim_id not in seen:
            seen.add(claim_id)
            out.append(claim_id)
    return out


def normalize_attack_story(
    value: Any,
    claims: list[dict[str, Any]],
    known_claim_ids: set[str],
    evidence_refs_by_claim: dict[str, set[str]],
    all_known_evidence_refs: set[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    story = []
    for index, item in enumerate(value, start=1):
        if isinstance(item, str):
            item = {"step": item}
        if not isinstance(item, dict):
            continue
        supporting_claim_ids = [claim_id for claim_id in string_list(item.get("supporting_claim_ids")) if claim_id in known_claim_ids]
        raw_refs = string_list(item.get("evidence_ref_ids"))
        allowed_refs = refs_for_supporting_claims(supporting_claim_ids, evidence_refs_by_claim)
        if not allowed_refs:
            allowed_refs = all_known_evidence_refs
        evidence_ref_ids = [ref for ref in raw_refs if ref in allowed_refs]
        if not supporting_claim_ids and evidence_ref_ids:
            supporting_claim_ids = infer_claims_from_refs(evidence_ref_ids, evidence_refs_by_claim)
            allowed_refs = refs_for_supporting_claims(supporting_claim_ids, evidence_refs_by_claim)
            evidence_ref_ids = [ref for ref in evidence_ref_ids if ref in allowed_refs]
        if supporting_claim_ids and not evidence_ref_ids:
            evidence_ref_ids = first_refs_for_claims(supporting_claim_ids, evidence_refs_by_claim, limit=8)
        if not supporting_claim_ids or not evidence_ref_ids:
            continue
        phase = normalize_phase(str(item.get("phase") or infer_phase_from_claims(supporting_claim_ids, claims)))
        step_text = str(item.get("step") or item.get("summary") or item.get("action") or "").strip()
        story.append({
            "step_id": str(item.get("step_id") or f"step_{index:03d}"),
            "phase": phase,
            "actor": str(item.get("actor") or "").strip(),
            "action": str(item.get("action") or step_text or "supported behavior").strip(),
            "target": str(item.get("target") or "").strip(),
            "effect": str(item.get("effect") or "").strip(),
            "step": step_text or synthesize_story_step(phase, supporting_claim_ids, claims),
            "supporting_claim_ids": supporting_claim_ids,
            "evidence_ref_ids": evidence_ref_ids,
            "confidence": normalize_confidence(str(item.get("confidence") or confidence_from_claims(supporting_claim_ids, claims))),
            "uncertainty": string_list(item.get("uncertainty")),
        })
    return sort_attack_story(story)


def default_observed_behavior(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations = []
    for index, claim in enumerate(claims, start=1):
        claim_id = str(claim.get("claim_id") or "")
        if not claim_id:
            continue
        behavior_class = observed_behavior_class(claim)
        if not behavior_class:
            continue
        observations.append({
            "observation_id": f"obs_{len(observations) + 1:03d}",
            "behavior_class": behavior_class,
            "summary": str(claim.get("statement") or claim.get("claim_type") or "observed behavior"),
            "supporting_claim_ids": [claim_id],
            "evidence_ref_ids": string_list(claim.get("evidence_ref_ids"))[:10],
            "confidence": normalize_confidence(str(claim.get("confidence") or "medium")),
            "interpretation": observed_behavior_interpretation(claim, behavior_class),
        })
    return observations


def observed_behavior_class(claim: dict[str, Any]) -> str:
    behavior_class = str(claim.get("behavior_class") or "").casefold()
    if behavior_class in {"dual_use", "absent", "uncertain"}:
        return behavior_class
    if is_uncertain_or_absent_claim_like(claim):
        claim_type = str(claim.get("claim_type") or "").casefold()
        status = str(claim.get("status") or "").casefold()
        return "absent" if claim_type.endswith("absent") or status == "absent" else "uncertain"
    if claim_dual_use_primitives(claim):
        return "dual_use"
    return ""


def observed_behavior_interpretation(claim: dict[str, Any], behavior_class: str) -> str:
    if behavior_class == "dual_use":
        primitives = claim_dual_use_primitives(claim)
        primitive_text = ", ".join(primitives) if primitives else "dual-use behavior"
        return f"This claim supports {primitive_text}, which can occur in benign software and does not establish ransomware behavior by itself."
    if behavior_class == "absent":
        return "The cited claim records an absent ransomware-relevant behavior rather than a positive attack step."
    return "The cited claim is uncertain and does not establish a ransomware-specific primitive."


def normalize_uncertain_observations(value: Any, claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    known_claims = {claim["claim_id"]: claim for claim in claims}
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                out.append({"claim_id": "", "reason": item, "evidence_ref_ids": []})
                continue
            if not isinstance(item, dict):
                continue
            claim_id = str(item.get("claim_id") or "")
            claim = known_claims.get(claim_id)
            refs = string_list(item.get("evidence_ref_ids"))
            if claim is not None:
                allowed = set(string_list(claim.get("evidence_ref_ids")))
                refs = [ref for ref in refs if ref in allowed] or string_list(claim.get("evidence_ref_ids"))[:5]
            out.append({"claim_id": claim_id if claim_id in known_claims else "", "reason": str(item.get("reason") or ""), "evidence_ref_ids": refs})
    if out:
        return out
    for claim in claims:
        claim_type = str(claim.get("claim_type") or "")
        if claim_type.endswith("uncertain") or claim.get("confidence") == "low":
            out.append({
                "claim_id": claim["claim_id"],
                "reason": claim.get("statement") or claim_type,
                "evidence_ref_ids": string_list(claim.get("evidence_ref_ids"))[:5],
            })
    return out


def normalize_deterministic_autostart_story(
    story: list[dict[str, Any]],
    claims: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep deterministic Run/RunOnce evidence at configuration, not execution, scope."""
    replacements: list[dict[str, Any]] = []
    binding_claim_ids: set[str] = set()
    for claim in claims:
        claim_id = str(claim.get("claim_id") or "")
        if not claim_id or not has_deterministic_run_key_executable_binding(claim):
            continue
        evidence_ref_ids = string_list(claim.get("evidence_ref_ids"))[:10]
        if not evidence_ref_ids:
            continue
        binding_claim_ids.add(claim_id)
        replacements.append({
            "step_id": f"step_{len(replacements) + 1:03d}",
            "phase": "persistence",
            "actor": "sample-attributed registry activity",
            "action": "wrote an executable Run or RunOnce autostart value",
            "target": "executable Run or RunOnce value",
            "effect": "Configured an executable autostart binding. No later logon or reboot execution was observed.",
            "step": (
                "The submitted sample wrote an executable Run or RunOnce autostart value. "
                "No subsequent logon or reboot execution was observed."
            ),
            "supporting_claim_ids": [claim_id],
            "evidence_ref_ids": evidence_ref_ids,
            "confidence": normalize_confidence(str(claim.get("confidence") or "medium")),
            "uncertainty": [
                "The observation establishes the autostart configuration, not subsequent logon or reboot execution."
            ],
        })
    if not replacements:
        return story
    retained = []
    for step in story:
        claim_ids = set(string_list(step.get("supporting_claim_ids")))
        if claim_ids and claim_ids.issubset(binding_claim_ids):
            continue
        retained.append(step)
    return sort_attack_story(retained + replacements)


def normalize_policy_fusion_story(
    story: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    policy_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    """Replace constituent story steps with their evidence-bounded policy fusion."""
    malicious = policy_evidence.get("malicious_primitives") if isinstance(policy_evidence, dict) else []
    fusion_steps, fusion_claim_ids = canonical_policy_fusion_story_steps(
        claims,
        malicious if isinstance(malicious, list) else [],
    )
    if not fusion_steps:
        return story
    retained = []
    for step in story:
        claim_ids = set(string_list(step.get("supporting_claim_ids")))
        if claim_ids and claim_ids.issubset(fusion_claim_ids):
            continue
        retained.append(step)
    return sort_attack_story(retained + fusion_steps)


def canonical_policy_fusion_story_steps(
    claims: list[dict[str, Any]],
    fusions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str]]:
    """Materialize cross-claim policy evidence without inferring unobserved execution."""
    claim_by_id = {str(claim.get("claim_id") or ""): claim for claim in claims}
    evidence_refs_by_claim = {
        claim_id: set(string_list(claim.get("evidence_ref_ids")))
        for claim_id, claim in claim_by_id.items()
        if claim_id
    }
    steps: list[dict[str, Any]] = []
    fused_claim_ids: set[str] = set()
    seen_pairs: set[tuple[str, ...]] = set()
    for fusion in fusions:
        if str(fusion.get("primitive") or "") != "dynamic_ransom_note_and_run_key_persistence":
            continue
        claim_ids = ordered_claim_ids(string_list(fusion.get("claim_ids")))
        if len(claim_ids) != 2 or any(claim_id not in claim_by_id for claim_id in claim_ids):
            continue
        pair = tuple(claim_ids)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        evidence_ref_ids = first_refs_for_claims(claim_ids, evidence_refs_by_claim, limit=10)
        if not evidence_ref_ids:
            continue
        fused_claim_ids.update(claim_ids)
        steps.append({
            "step_id": f"step_{len(steps) + 1:03d}",
            "phase": "persistence",
            "actor": "sample-attributed ransom-note and registry activity",
            "action": "created or wrote a recovery-oriented note artifact and configured an executable Run or RunOnce autostart value",
            "target": "recovery-oriented note artifact and executable Run or RunOnce value",
            "effect": "Corroborated note-artifact creation and executable autostart configuration. No later logon or reboot execution was observed.",
            "step": (
                "The submitted sample created or wrote a recovery-oriented note artifact and configured "
                "an executable Run or RunOnce autostart value. No subsequent logon or reboot execution was observed."
            ),
            "supporting_claim_ids": claim_ids,
            "evidence_ref_ids": evidence_ref_ids,
            "confidence": confidence_from_claims(claim_ids, claims),
            "uncertainty": [
                "The observations do not establish the note text, encryption, extortion impact, or subsequent logon or reboot execution."
            ],
        })
    return steps, fused_claim_ids


def default_attack_story(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    story, fused_claim_ids = canonical_policy_fusion_story_steps(
        claims,
        cross_claim_policy_primitives(claims),
    )
    risk_claims = [
        claim for claim in claims
        if not str(claim.get("claim_type") or "").endswith(("absent", "uncertain"))
        and str(claim.get("claim_id") or "") not in fused_claim_ids
    ]
    risk_claims.sort(key=lambda claim: (claim_evidence_order(claim), phase_rank(infer_phase_from_claim(claim)), str(claim.get("claim_id"))))
    for claim in risk_claims:
        phase = normalize_phase(infer_phase_from_claim(claim))
        evidence_ref_ids = string_list(claim.get("evidence_ref_ids"))[:10]
        if not evidence_ref_ids:
            continue
        story.append({
            "step_id": f"step_{len(story) + 1:03d}",
            "phase": phase,
            "actor": str(claim.get("agent_id") or ""),
            "action": str(claim.get("claim_type") or "behavior_observation"),
            "target": "",
            "effect": "",
            "step": str(claim.get("statement") or claim.get("claim_type") or "supported behavior"),
            "supporting_claim_ids": [claim["claim_id"]],
            "evidence_ref_ids": evidence_ref_ids,
            "confidence": normalize_confidence(str(claim.get("confidence") or "medium")),
            "uncertainty": string_list(claim.get("uncertainty")),
        })
    return sort_attack_story(story)


def sort_attack_story(story: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        enumerate(story),
        key=lambda item: (*earliest_evidence_order(string_list(item[1].get("evidence_ref_ids"))), item[0]),
    )
    normalized = []
    for index, (_, step) in enumerate(ordered, start=1):
        item = dict(step)
        item["step_id"] = f"step_{index:03d}"
        normalized.append(item)
    return normalized


def claim_evidence_order(claim: dict[str, Any]) -> tuple[int, int]:
    return earliest_evidence_order(string_list(claim.get("evidence_ref_ids")))


def earliest_evidence_order(refs: list[str]) -> tuple[int, int]:
    known = [evidence_ref_order(ref) for ref in refs]
    known = [item for item in known if item[0] < 2]
    return min(known) if known else (2, 1_000_000_000)


def evidence_ref_order(ref: str) -> tuple[int, int]:
    text = str(ref)
    if text.startswith("event:"):
        number = text.split(":", 1)[1]
        if number.isdigit():
            return (0, int(number))
    if text.startswith("block:"):
        number = text.rsplit("_", 1)[-1]
        if number.isdigit():
            return (1, int(number))
    return (2, 1_000_000_000)


def refs_for_supporting_claims(claim_ids: list[str], evidence_refs_by_claim: dict[str, set[str]]) -> set[str]:
    refs: set[str] = set()
    for claim_id in claim_ids:
        refs.update(evidence_refs_by_claim.get(claim_id, set()))
    return refs


def infer_claims_from_refs(refs: list[str], evidence_refs_by_claim: dict[str, set[str]]) -> list[str]:
    wanted = set(refs)
    return [claim_id for claim_id, claim_refs in evidence_refs_by_claim.items() if wanted & claim_refs]


def first_refs_for_claims(claim_ids: list[str], evidence_refs_by_claim: dict[str, set[str]], limit: int) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for claim_id in claim_ids:
        for ref in sorted(evidence_refs_by_claim.get(claim_id, set())):
            if ref not in seen:
                seen.add(ref)
                refs.append(ref)
            if len(refs) >= limit:
                return refs
    return refs


def infer_phase_from_claims(claim_ids: list[str], claims: list[dict[str, Any]]) -> str:
    claim_by_id = {claim["claim_id"]: claim for claim in claims}
    for claim_id in claim_ids:
        if claim_id in claim_by_id:
            return infer_phase_from_claim(claim_by_id[claim_id])
    return "other"


def infer_phase_from_claim(claim: dict[str, Any]) -> str:
    claim_type = str(claim.get("claim_type") or "").casefold()
    agent_id = str(claim.get("agent_id") or "").casefold()
    text = f"{agent_id} {claim_type} {claim.get('statement') or ''}".casefold()
    if "static_recovery_inhibition" in text or "recovery" in text or "shadow" in text or "vssadmin" in text:
        return "recovery_inhibition"
    if "static_service_disruption" in text or "taskkill" in text or "net stop" in text:
        return "impact"
    if "static_extortion" in text or "static_ransom_note" in text:
        return "ransom_note"
    if "registry" in text or "persistence" in text or "run key" in text:
        return "persistence"
    if "recovery" in text or "shadow" in text or "vssadmin" in text:
        return "recovery_inhibition"
    if "process" in text or "execution" in text or "cmd.exe" in text:
        return "execution"
    if "ransom_note" in text or "restore_my_files" in text or "ransom-note" in text or "note deployment" in text:
        return "ransom_note"
    if "file_transformation" in text or "rename" in text or "write" in text or "extension" in text:
        return "file_transformation"
    if "file_discovery" in text or "enumer" in text:
        return "discovery"
    if "anti_analysis" in text or "sandbox" in text or "debug" in text:
        return "anti_analysis"
    return "other"


def normalize_phase(value: str) -> str:
    phase = str(value or "").strip().casefold().replace("-", "_").replace(" ", "_")
    allowed = {"discovery", "execution", "persistence", "recovery_inhibition", "ransom_note", "file_transformation", "anti_analysis", "impact", "other"}
    return phase if phase in allowed else "other"


def phase_rank(phase: str) -> int:
    order = {
        "discovery": 0,
        "anti_analysis": 1,
        "persistence": 2,
        "execution": 3,
        "recovery_inhibition": 4,
        "ransom_note": 5,
        "file_transformation": 6,
        "impact": 7,
        "other": 8,
    }
    return order.get(normalize_phase(phase), 7)


def confidence_from_claims(claim_ids: list[str], claims: list[dict[str, Any]]) -> str:
    claim_by_id = {claim["claim_id"]: claim for claim in claims}
    values = [normalize_confidence(str(claim_by_id[claim_id].get("confidence") or "medium")) for claim_id in claim_ids if claim_id in claim_by_id]
    if "high" in values:
        return "high"
    if "medium" in values:
        return "medium"
    return values[0] if values else "medium"


def synthesize_story_step(phase: str, claim_ids: list[str], claims: list[dict[str, Any]]) -> str:
    claim_by_id = {claim["claim_id"]: claim for claim in claims}
    statements = [str(claim_by_id[claim_id].get("statement") or "") for claim_id in claim_ids if claim_id in claim_by_id]
    return statements[0] if statements else f"Supported {phase} behavior."

def infer_supporting_claim_ids(claims: list[dict[str, Any]], verdict: str) -> list[str]:
    if verdict == "no_risk":
        boundary_claims = [
            claim["claim_id"]
            for claim in claims
            if is_uncertain_or_absent_claim_like(claim) or claim_dual_use_primitives(claim)
        ]
        return boundary_claims or [claim["claim_id"] for claim in claims if claim.get("claim_type", "").endswith("absent")]
    risk_claims = [
        claim["claim_id"]
        for claim in claims
        if not str(claim.get("claim_type") or "").endswith(("absent", "uncertain"))
    ]
    return risk_claims or [claim["claim_id"] for claim in claims[:3]]


def policy_adjusted_risk_summary(
    verdict: str,
    claims: list[dict[str, Any]],
    policy_evidence: dict[str, Any],
    analysis_coverage: dict[str, Any],
    original_summary: str,
) -> str:
    if verdict == "no_risk" and not claims:
        if is_sufficient_analysis_coverage(analysis_coverage):
            return (
                "Configured evidence roles completed bounded checks and produced no claimable "
                "ransomware-risk behavior. This establishes no observed risk within the covered "
                "trace, not absence of behavior beyond its retained scope."
            )
        return (
            "No supplied claim establishes ransomware-risk behavior, but configured role coverage "
            "is incomplete, so the no-risk conclusion remains non-final."
        )
    if verdict == "no_risk" and has_only_dual_use_or_absent_claims(claims):
        primitives = sorted({item["primitive"] for item in policy_evidence.get("dual_use_primitives", [])})
        primitive_text = ", ".join(primitives) if primitives else "absent or uncertain observations"
        return (
            "The supplied claims are limited to dual-use or absent behavior "
            f"({primitive_text}). No sample-attributed ransomware-specific primitive, "
            "harmful effect, or malicious-only behavior is supported by the cited evidence."
        )
    fusion_ids = policy_item_claim_ids([
        item
        for item in policy_evidence.get("malicious_primitives", [])
        if str(item.get("primitive") or "") == "dynamic_ransom_note_and_run_key_persistence"
    ])
    if verdict == "malicious" and fusion_ids:
        return (
            "The supplied claims jointly establish a recovery-oriented note artifact and executable "
            "Run or RunOnce autostart configuration. They do not establish note content, encryption, "
            "extortion impact, or later logon or reboot execution. Their corroboration supports the malicious verdict."
        )
    if verdict == "malicious" and policy_evidence.get("malicious_primitives"):
        return (
            "The supplied claims include high-confidence dynamic evidence of a sample-attributed "
            "malicious primitive. Missing later ransomware stages affect completeness and uncertainty, "
            "not the malicious verdict."
        )
    if verdict == "suspicious" and risk_relevant_claim_ids(claims):
        return (
            "The supplied claims include risk-relevant behavior, but they do not establish a "
            "malicious-only ransomware primitive such as destructive recovery inhibition, ransom-note "
            "creation, or encryption. The supported conclusion is suspicious rather than no_risk."
        )
    if verdict == "suspicious" and no_risk_blocking_claim_ids(claims):
        return (
            "The supplied claims include positive observations that are not yet explicitly bounded "
            "as dual-use or absent. They do not establish a malicious-only ransomware primitive, "
            "but they prevent a final no_risk conclusion."
        )
    return original_summary


def default_risk_summary(verdict: str, claims: list[dict[str, Any]]) -> str:
    return f"Verdict {verdict} based on {len(claims)} supplied evidence claim(s)."


def materialize_verdict_artifacts(
    context: TaskContext,
    claims: list[dict[str, Any]],
    analysis_coverage: dict[str, Any],
    verdict: dict[str, Any],
    model_response: dict[str, Any],
):
    payloads = {
        "sample_verdict": verdict,
        "verdict_input_claims": claims,
        "verdict_input_coverage": analysis_coverage,
        "verdict_model_response": model_response,
    }
    filenames = {
        "sample_verdict": "sample_verdict.json",
        "verdict_input_claims": "verdict_input_claims.json",
        "verdict_input_coverage": "verdict_input_coverage.json",
        "verdict_model_response": "verdict_model_response.json",
    }
    artifacts = {}
    for name, payload in payloads.items():
        path = context.store.path_for(context.spec.task_id, filenames[name])
        write_json(path, payload)
        artifacts[name] = context.store.artifact_ref(
            context.spec.task_id,
            name,
            name,
            path,
            artifact_metadata(name, payload),
        )
    return artifacts


def artifact_metadata(name: str, payload: Any) -> dict[str, Any]:
    if name == "sample_verdict":
        return {"verdict": payload.get("verdict"), "confidence": payload.get("confidence")}
    if name == "verdict_input_claims":
        return {"claim_count": len(payload)}
    if name == "verdict_input_coverage":
        return {
            "status": str(payload.get("status") or ""),
            "role_count": int(payload.get("role_count") or 0),
        }
    return {}


def normalize_confidence(value: str) -> str:
    return value if value in CONFIDENCE_LEVELS else "medium"


def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None and str(item) != ""]
    return [str(value)]


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

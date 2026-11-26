"""Task handler for deterministic strong static evidence extraction."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness.static import scan_static_strong_evidence

from .models import SessionFact, TaskContext, TaskHandler, TaskResult, TaskSpec

TASK_EXTRACT_STATIC_STRONG_EVIDENCE = "extract_static_strong_evidence"
STATIC_STRONG_OUTPUTS = ("static_scan", "candidate_claims", "local_memory")


def static_task_handlers() -> dict[str, TaskHandler]:
    return {TASK_EXTRACT_STATIC_STRONG_EVIDENCE: extract_static_strong_evidence_task}


def build_static_strong_task_spec(
    static_sample_artifact_id: str = "static_sample",
    task_id: str = "extract_static_strong_evidence",
) -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        task_type=TASK_EXTRACT_STATIC_STRONG_EVIDENCE,
        profile="static_strong",
        input_artifacts={"static_sample": static_sample_artifact_id},
        output_names=STATIC_STRONG_OUTPUTS,
        acceptance_criteria=(
            "only strong static ransomware evidence rules are retained",
            "generic imports, crypto APIs, packer indicators, and weak keywords are not emitted as claims",
            "every static claim cites static refs materialized in local_memory",
        ),
    )


def extract_static_strong_evidence_task(context: TaskContext) -> TaskResult:
    sample_path = context.input_path("static_sample")
    scan = scan_static_strong_evidence(sample_path)
    scan_payload = scan.to_dict()
    claims = [claim.to_dict() for claim in scan.claims]
    local_memory = build_local_memory(scan_payload)

    payloads: dict[str, Any] = {
        "static_scan": scan_payload,
        "candidate_claims": claims,
        "local_memory": local_memory,
    }
    filenames = {
        "static_scan": "static_scan.json",
        "candidate_claims": "candidate_claims.json",
        "local_memory": "local_memory.json",
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

    facts: list[SessionFact] = [
        SessionFact(
            fact_id=f"{context.spec.task_id}:summary",
            kind="static_strong_summary",
            data={
                "schema_version": "static-strong-task-summary-v1",
                "sample_path": str(sample_path),
                "sha256": scan.sha256,
                "claim_count": len(claims),
                "matched_item_count": len(scan.matched_items),
                "rule_match_counts": scan.diagnostics.get("rule_match_counts", {}),
            },
            source_task_id=context.spec.task_id,
            artifact_ids=tuple(ref.artifact_id for ref in artifacts.values()),
        )
    ]
    for claim in claims:
        facts.append(SessionFact(
            fact_id=f"{context.spec.task_id}:claim:{claim['claim_id']}",
            kind="candidate_claim",
            data=claim,
            source_task_id=context.spec.task_id,
            artifact_ids=(artifacts["candidate_claims"].artifact_id,),
        ))
    return TaskResult.completed(
        context.spec.task_id,
        artifacts=artifacts,
        facts=tuple(facts),
        diagnostics={
            "schema_version": "static-strong-task-v1",
            "claim_count": len(claims),
            "matched_item_count": len(scan.matched_items),
            "rule_match_counts": scan.diagnostics.get("rule_match_counts", {}),
        },
    )


def build_local_memory(scan_payload: dict[str, Any]) -> dict[str, Any]:
    items = scan_payload.get("matched_items", []) if isinstance(scan_payload.get("matched_items"), list) else []
    facts = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        ref_id = str(item.get("ref_id") or "")
        if not ref_id:
            continue
        facts.append({
            "fact_id": f"static_fact_{index:06d}",
            "source_tool": "static_strong_rule_matcher",
            "query": {"rule_id": item.get("rule_id"), "pattern": item.get("pattern")},
            "summary": f"{item.get('rule_id')} matched static string evidence",
            "evidence_ref_ids": [ref_id],
            "block_ids": [],
            "event_offsets": [],
            "aggregate_digest": {"encoding": item.get("encoding"), "source": item.get("source")},
            "event_examples": [],
            "block_examples": [],
            "limitations": ["static evidence does not prove runtime execution"],
            "purpose": "strong static evidence extraction",
        })
    return {
        "facts": facts,
        "open_questions": [],
        "evidence_ref_count": len({ref for fact in facts for ref in fact["evidence_ref_ids"]}),
        "block_ref_count": 0,
        "truncated_fact_count": 0,
    }


def artifact_metadata(name: str, payload: Any) -> dict[str, Any]:
    if name == "candidate_claims":
        return {"claim_count": len(payload), "agent_id": "static_strong"}
    if name == "static_scan":
        return {
            "sha256": payload.get("sha256"),
            "matched_item_count": len(payload.get("matched_items", [])),
            "claim_count": len(payload.get("claims", [])),
        }
    if name == "local_memory":
        return {"fact_count": len(payload.get("facts", [])), "agent_id": "static_strong"}
    return {}


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

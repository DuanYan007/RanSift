"""Bounded role-coverage records distinct from positive evidence claims."""
from __future__ import annotations

from collections import Counter
from typing import Any


ROLE_COVERAGE_SCHEMA = "harness-role-coverage-v1"
ANALYSIS_COVERAGE_SCHEMA = "harness-analysis-coverage-v1"

_COVERED_ROLE_STATUSES = frozenset({"bounded_no_evidence", "covered_with_claims"})


def build_role_coverage_certificate(
    *,
    task_id: str,
    agent_id: str,
    loop_status: str,
    claim_count: int,
    tool_call_count: int,
    seed_tool_call_count: int,
    completion: dict[str, Any] | None,
    execution_observation: dict[str, Any] | None = None,
    source_artifact_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Describe what one role actually covered without turning absence into a claim."""

    completion_data = completion if isinstance(completion, dict) else {}
    execution_observation_data = normalize_execution_observation(execution_observation)
    checked_fact_ids = string_list(completion_data.get("checked_fact_ids"))
    scope = str(completion_data.get("scope") or "").strip()
    uncertainty = string_list(completion_data.get("uncertainty"))
    expected_tool_call_count = max(1, int(seed_tool_call_count or 0))
    no_evidence_contract = (
        loop_status == "completed_no_evidence"
        and int(claim_count or 0) == 0
        and str(completion_data.get("kind") or "") == "no_evidence"
        and bool(checked_fact_ids)
        and bool(scope)
        and int(tool_call_count or 0) >= expected_tool_call_count
    )
    if execution_observation_data["status"] == "insufficient":
        coverage_status = "incomplete"
    elif no_evidence_contract:
        coverage_status = "bounded_no_evidence"
    elif (
        loop_status == "completed"
        and int(claim_count or 0) > 0
        and int(tool_call_count or 0) >= expected_tool_call_count
    ):
        coverage_status = "covered_with_claims"
    else:
        coverage_status = "incomplete"

    return {
        "schema_version": ROLE_COVERAGE_SCHEMA,
        "coverage_id": f"{task_id}:coverage",
        "task_id": task_id,
        "agent_id": agent_id,
        "coverage_status": coverage_status,
        "execution_observation": execution_observation_data,
        "loop_status": loop_status,
        "claim_count": int(claim_count or 0),
        "tool_call_count": int(tool_call_count or 0),
        "seed_tool_call_count": int(seed_tool_call_count or 0),
        "checked_fact_ids": checked_fact_ids,
        "scope": scope,
        "uncertainty": uncertainty,
        "source_artifact_ids": sorted(set(string_list(source_artifact_ids))),
    }


def aggregate_analysis_coverage(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate configured role outcomes into a bounded analysis-coverage result."""

    normalized = [normalize_role_coverage(record) for record in records if isinstance(record, dict)]
    normalized.sort(key=lambda item: (item["agent_id"], item["task_id"]))
    if not normalized:
        # The aggregate has no process-observation record to evaluate.
        return {
            "schema_version": ANALYSIS_COVERAGE_SCHEMA,
            "status": "not_available",
            "role_count": 0,
            "covered_role_count": 0,
            "negative_coverage_role_count": 0,
            "claim_bearing_role_count": 0,
            "execution_observation_status": "not_assessed",
            "execution_observation_reason_codes": [],
            "incomplete_agent_ids": [],
            "coverage_ids": [],
            "roles": [],
        }

    agent_counts = Counter(item["agent_id"] for item in normalized)
    duplicate_agent_ids = {agent_id for agent_id, count in agent_counts.items() if count > 1}
    for record in normalized:
        if record["agent_id"] in duplicate_agent_ids:
            record["coverage_status"] = "incomplete"

    incomplete = [
        record["agent_id"]
        for record in normalized
        if record["coverage_status"] not in _COVERED_ROLE_STATUSES
    ]
    negative = [
        record for record in normalized if record["coverage_status"] == "bounded_no_evidence"
    ]
    claim_bearing = [
        record for record in normalized if record["coverage_status"] == "covered_with_claims"
    ]
    execution_observations = [record["execution_observation"] for record in normalized]
    insufficient_execution = [
        observation
        for observation in execution_observations
        if observation["status"] == "insufficient"
    ]
    execution_reason_codes = sorted({
        reason
        for observation in insufficient_execution
        for reason in observation["reason_codes"]
    })
    return {
        "schema_version": ANALYSIS_COVERAGE_SCHEMA,
        "status": "sufficient" if not incomplete else "insufficient",
        "role_count": len(normalized),
        "covered_role_count": len(normalized) - len(incomplete),
        "negative_coverage_role_count": len(negative),
        "claim_bearing_role_count": len(claim_bearing),
        "execution_observation_status": (
            "insufficient" if insufficient_execution
            else "adequate" if any(item["status"] == "adequate" for item in execution_observations)
            else "not_assessed"
        ),
        "execution_observation_reason_codes": execution_reason_codes,
        "incomplete_agent_ids": sorted(set(incomplete)),
        "coverage_ids": [record["coverage_id"] for record in normalized],
        "roles": normalized,
    }


def is_sufficient_analysis_coverage(value: dict[str, Any] | None) -> bool:
    if not isinstance(value, dict):
        return False
    return (
        value.get("schema_version") == ANALYSIS_COVERAGE_SCHEMA
        and value.get("status") == "sufficient"
        and int(value.get("role_count") or 0) > 0
        and int(value.get("covered_role_count") or 0) == int(value.get("role_count") or 0)
    )


def normalize_role_coverage(value: dict[str, Any]) -> dict[str, Any]:
    task_id = str(value.get("task_id") or "").strip()
    agent_id = str(value.get("agent_id") or "").strip()
    coverage_id = str(value.get("coverage_id") or "").strip()
    coverage_status = str(value.get("coverage_status") or "").strip()
    if not task_id or not agent_id or not coverage_id:
        coverage_status = "incomplete"
    if coverage_status not in _COVERED_ROLE_STATUSES | {"incomplete"}:
        coverage_status = "incomplete"
    execution_observation_data = normalize_execution_observation(value.get("execution_observation"))
    return {
        "schema_version": ROLE_COVERAGE_SCHEMA,
        "coverage_id": coverage_id or f"{task_id or 'unknown'}:coverage",
        "task_id": task_id,
        "agent_id": agent_id,
        "coverage_status": coverage_status,
        "execution_observation": execution_observation_data,
        "loop_status": str(value.get("loop_status") or ""),
        "claim_count": int(value.get("claim_count") or 0),
        "tool_call_count": int(value.get("tool_call_count") or 0),
        "seed_tool_call_count": int(value.get("seed_tool_call_count") or 0),
        "checked_fact_ids": string_list(value.get("checked_fact_ids")),
        "scope": str(value.get("scope") or ""),
        "uncertainty": string_list(value.get("uncertainty")),
        "source_artifact_ids": sorted(set(string_list(value.get("source_artifact_ids")))),
    }



def normalize_execution_observation(value: dict[str, Any] | None) -> dict[str, Any]:
    data = value if isinstance(value, dict) else {}
    status = str(data.get("status") or "not_assessed").strip()
    if status not in {"adequate", "insufficient", "not_assessed"}:
        status = "not_assessed"
    return {
        "schema_version": str(data.get("schema_version") or "harness-execution-observation-v1"),
        "status": status,
        "reason_codes": sorted(set(string_list(data.get("reason_codes")))),
        "evidence_ref_ids": sorted(set(string_list(data.get("evidence_ref_ids")))),
        "summary": str(data.get("summary") or ""),
    }

def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None and str(item) != ""]
    return [str(value)]

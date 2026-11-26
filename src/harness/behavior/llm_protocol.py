"""LLM output protocol for behavior-agent ReAct loops."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .classification import DUAL_USE_POLICY_PRIMITIVES, OBSERVATION_BOUNDARY_POLICY


OUTPUT_SCHEMA = {
    "one_of": ["tool_request", "claim_output", "no_evidence"],
    "tool_request": {"tool_name": "str", "arguments": "dict", "purpose": "str"},
    "claim_output": {
        "claim_type": "str",
        "behavior_class": "optional: dual_use|risk_relevant|uncertain",
        "statement": "str",
        "confidence": "low|medium|high",
        "evidence_ref_ids": "list[str]",
        "supporting_block_ids": "list[str]",
        "alternative_explanations": "list[str]",
        "uncertainty": "list[str]",
        "risk_primitives": "optional list[str]",
        "dual_use_primitives": "optional list[str]",
    },
    "no_evidence": {
        "checked_fact_ids": "list[str]",
        "scope": "str",
        "uncertainty": "list[str]",
    },
}


VALID_RESPONSE_EXAMPLES = (
    {
        "tool_request": {
            "tool_name": "get_block_events",
            "arguments": {"block_id": "macro_000001", "representative_only": True, "limit": 10},
            "purpose": "inspect block events before making a claim",
        }
    },
    {
        "claim_output": {
            "claim_type": "file_transformation_behavior",
            "statement": "sample-attributed events support a bounded behavior claim",
            "confidence": "medium",
            "evidence_ref_ids": ["block:macro_000001", "event:1"],
            "supporting_block_ids": ["macro_000001"],
            "alternative_explanations": ["legitimate bulk file processing"],
            "uncertainty": ["dynamic trace only"],
            "risk_primitives": [],
            "dual_use_primitives": [],
        }
    },
    {
        "no_evidence": {
            "checked_fact_ids": ["fact_000001", "fact_000002"],
            "scope": "No claimable evidence for the assigned behavior was returned by the checked observations.",
            "uncertainty": ["The conclusion is bounded to the cited tool observations."],
        }
    },
)


@dataclass(frozen=True)
class AgentAction:
    kind: str
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    purpose: str | None = None
    claims: tuple[dict[str, Any], ...] = ()
    checked_fact_ids: tuple[str, ...] = ()
    scope: str | None = None
    uncertainty: tuple[str, ...] = ()
    error: str | None = None


def context_to_messages(context: LLMContext) -> tuple[dict[str, str], ...]:
    payload = context.to_dict()
    state = payload["loop_state"]
    terminal = (
        int(state.get("round_index") or 0) + 1 >= int(state.get("max_rounds") or 1)
        or int(state.get("remaining_tool_calls") or 0) <= 0
    )
    user_payload = {
        "agent_prompt": payload["agent_prompt"],
        "task_prompt": payload["task_prompt"],
        "evidence_policy": payload["evidence_policy"],
        "available_tools": payload["available_tools"],
        "working_context": payload["working_context"],
        "loop_state": payload["loop_state"],
        "output_schema": payload["output_schema"],
        "valid_response_examples": VALID_RESPONSE_EXAMPLES,
        "dual_use_primitive_vocabulary": DUAL_USE_POLICY_PRIMITIVES,
        "observation_boundary_policy": OBSERVATION_BOUNDARY_POLICY,
        "instruction": (
            "Return exactly one JSON object and no prose. The first character must be '{'. "
            "Choose a top-level tool_request, claim_output, or no_evidence object. "
            "A claim_output cites only event:* or block:* values from fact.evidence_ref_ids. "
            "A fact_id is an observation identifier, never an evidence_ref_id. "
            "If checked observations contain no claimable evidence for the assigned behavior, return no_evidence with checked_fact_ids. "
            "For no_evidence, checked_fact_ids must be a non-empty subset of working_context.visible_fact_ids exactly. "
            "Session-context fact ids and artifact ids are context sources, not valid checked_fact_ids. "
            "Use canonical identifiers from dual_use_primitive_vocabulary for supported dual-use findings. "
            "Keep behavior_class and claim_type consistent: a supported dual_use observation uses "
            "the behavior claim_type, while an unresolved risk finding uses an uncertain claim_type. "
            "Unknown intent or file contents alone do not change an established dual-use operation "
            "into an uncertain risk finding; preserve such limits in the uncertainty field. "
            "Confidence in an observed operation does not establish harmful intent or effects. "
            "Do not return a bare tool_name object and do not append explanations outside JSON."
        ),
    }
    user_payload["terminal_response_required"] = terminal
    if terminal:
        user_payload["available_tools"] = []
        user_payload["output_schema"] = {**payload["output_schema"], "one_of": ["claim_output", "no_evidence"]}
        user_payload["instruction"] += (
            " This is the final response within the existing investigation budget. Do not request another tool. "
            "Submit a supported claim_output or a bounded no_evidence conclusion using the checked visible facts. "
            "Preserve unchecked scope and unresolved effects in uncertainty; do not invent completion of an unperformed check."
        )
    return (
        {"role": "system", "content": payload["system_prompt"]},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=True, sort_keys=True)},
    )


def parse_agent_response(response: dict[str, Any]) -> AgentAction:
    if not isinstance(response, dict):
        return AgentAction("invalid", error="model response is not a JSON object")
    if "no_evidence" in response:
        return parse_no_evidence(response["no_evidence"])
    if response.get("type") == "no_evidence" or response.get("kind") == "no_evidence":
        return parse_no_evidence(response)
    if "checked_fact_ids" in response and "scope" in response:
        return parse_no_evidence(response)


    if "tool_request" in response:
        request = response["tool_request"]
        return parse_tool_request(request)
    if response.get("type") == "tool_request" or response.get("kind") == "tool_request":
        return parse_tool_request(response)
    if "tool_name" in response or "name" in response:
        return parse_tool_request(response)
    if "claim_output" in response:
        return parse_claim_output(response["claim_output"])
    if response.get("type") == "claim_output" or response.get("kind") == "claim_output":
        return parse_claim_output(response)
    if "claim_type" in response or "claims" in response:
        return parse_claim_output(response)
    return AgentAction("invalid", error="response must contain tool_request, claim_output, or no_evidence")


def parse_tool_request(payload: Any) -> AgentAction:
    if not isinstance(payload, dict):
        return AgentAction("invalid", error="tool_request must be an object")
    tool_name = payload.get("tool_name") or payload.get("name")
    arguments = payload.get("arguments") or payload.get("kwargs") or {}
    if not isinstance(tool_name, str) or not tool_name:
        return AgentAction("invalid", error="tool_request.tool_name is required")
    if not isinstance(arguments, dict):
        return AgentAction("invalid", error="tool_request.arguments must be an object")
    purpose = payload.get("purpose")
    return AgentAction("tool_request", tool_name=tool_name, arguments=arguments, purpose=str(purpose) if purpose else None)


def parse_claim_output(payload: Any) -> AgentAction:
    if not isinstance(payload, dict):
        return AgentAction("invalid", error="claim_output must be an object")
    if isinstance(payload.get("claims"), list):
        claims = tuple(item for item in payload["claims"] if isinstance(item, dict))
    else:
        claims = (payload,)
    if not claims:
        return AgentAction("invalid", error="claim_output contains no claims")
    return AgentAction("claim_output", claims=claims)
def parse_no_evidence(payload: Any) -> AgentAction:
    if not isinstance(payload, dict):
        return AgentAction("invalid", error="no_evidence must be an object")
    raw_fact_ids = payload.get("checked_fact_ids")
    if not isinstance(raw_fact_ids, list):
        return AgentAction("invalid", error="no_evidence.checked_fact_ids must be a list")
    checked_fact_ids = tuple(dict.fromkeys(str(item).strip() for item in raw_fact_ids if str(item).strip()))
    if not checked_fact_ids:
        return AgentAction("invalid", error="no_evidence.checked_fact_ids must not be empty")
    scope = str(payload.get("scope") or "").strip()
    if not scope:
        return AgentAction("invalid", error="no_evidence.scope is required")
    raw_uncertainty = payload.get("uncertainty", [])
    if not isinstance(raw_uncertainty, list):
        return AgentAction("invalid", error="no_evidence.uncertainty must be a list")
    uncertainty = tuple(str(item).strip() for item in raw_uncertainty if str(item).strip())
    return AgentAction(
        "no_evidence", checked_fact_ids=checked_fact_ids, scope=scope, uncertainty=uncertainty
    )




def parse_json_object(content: str) -> dict[str, Any]:
    text = strip_markdown_fence(content.strip())
    if not text:
        raise ValueError("LLM response does not contain a JSON object")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = extract_first_json_object(text)
    if not isinstance(data, dict):
        raise ValueError("LLM response must be a JSON object")
    return data


def strip_markdown_fence(text: str) -> str:
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def extract_first_json_object(text: str) -> dict[str, Any]:
    start = text.find("{")
    if start < 0:
        raise ValueError("LLM response does not contain a JSON object")
    depth = 0
    in_string = False
    escape = False
    for pos in range(start, len(text)):
        ch = text[pos]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                data = json.loads(text[start:pos + 1])
                if not isinstance(data, dict):
                    raise ValueError("LLM response JSON is not an object")
                return data
    raise ValueError("LLM response contains an unterminated JSON object")


def compact_response(response: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(response, ensure_ascii=True))

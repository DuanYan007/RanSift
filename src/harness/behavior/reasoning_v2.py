"""Transport-compatible investigation protocol; evidence checks remain strict."""
from dataclasses import replace

from .llm_protocol import AgentAction, parse_agent_response
from .reasoning import (
    LEGACY_FIELDS, EvidenceReasoningRunner, ReasoningContextBuilder,
    reasoning_agent_prompts as original_prompts, reasoning_messages as original_messages,
)

PROTOCOL = "evidence-reasoning-v2"
RESPONSE_KINDS = {"tool_request", "claim_output", "no_evidence"}


def reasoning_agent_prompts():
    return {key: replace(prompt, exclusions=prompt.exclusions + (
        "Do not give self-rated confidence levels, probabilities, or scores; state the observed facts and specific evidentiary limitations.",
    )) for key, prompt in original_prompts().items()}


def normalize_envelope(response):
    """Normalize equivalent envelopes without guessing ambiguous model actions."""
    if not isinstance(response, dict):
        raise ValueError("response must be an object")
    payload = {key: value for key, value in response.items() if key != "_usage"}
    wrapped = set(payload) & RESPONSE_KINDS
    direct = set()
    if "tool_name" in payload or "name" in payload:
        direct.add("tool_request")
    if "claims" in payload or "claim_type" in payload:
        direct.add("claim_output")
    if "checked_fact_ids" in payload:
        direct.add("no_evidence")
    tags = {payload[key] for key in ("type", "kind") if key in payload and isinstance(payload[key], str)}
    if tags - RESPONSE_KINDS or len(tags) > 1:
        raise ValueError("unknown or conflicting response type")
    kinds = wrapped | direct | tags
    if len(kinds) != 1 or (wrapped and direct):
        raise ValueError("response must identify exactly one unambiguous action")
    kind = next(iter(kinds))
    if wrapped:
        if set(payload) - wrapped - {"type", "kind"}:
            raise ValueError("wrapped response contains extra action fields")
        body = payload[kind]
    else:
        body = {key: value for key, value in payload.items() if key not in {"type", "kind"}}
    if not isinstance(body, dict):
        raise ValueError("action body must be an object")
    if set(body) & LEGACY_FIELDS:
        raise ValueError("unsupported decision-control fields")
    if kind == "claim_output":
        claims = body.get("claims", [body])
        if not isinstance(claims, list) or not claims or any(not isinstance(item, dict) for item in claims):
            raise ValueError("claim_output requires a non-empty list of objects")
        if any(set(item) & LEGACY_FIELDS for item in claims):
            raise ValueError("unsupported decision-control fields in claim")
        body = {"claims": claims}
    return {kind: body}


class CompatibleContextBuilder(ReasoningContextBuilder):
    def build(self, *args, **kwargs):
        context = super().build(*args, **kwargs)
        return replace(context, evidence_policy=context.evidence_policy + (
            "Return canonical envelopes when possible. Equivalent direct or type-tagged actions are accepted; never combine actions.",
            "Never report self-rated confidence in findings; express specific unknown facts or effects instead.",
        ))


class CompatibleReasoningRunner(EvidenceReasoningRunner):
    def __init__(self, registry, client, config=None, agent_prompts=None):
        super().__init__(registry, client, config=config, agent_prompts=agent_prompts)
        self.context_builder = CompatibleContextBuilder(registry, agent_prompts or reasoning_agent_prompts())

    def parse_response(self, response):
        try:
            return parse_agent_response(normalize_envelope(response))
        except ValueError as exc:
            return AgentAction("invalid", error=str(exc))

    def messages_for_context(self, context):
        return original_messages(context)

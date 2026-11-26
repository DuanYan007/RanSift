"""Budget-aware investigation closure; leads are retrieval obligations, not risk rules."""
from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace

from .reasoning import evidence_view, text, texts, ReasonedClaimLedger, record_reasoned_claims
from .reasoning_v2 import CompatibleContextBuilder
from .submission_correction import SubmissionCorrectionRunner
from .llm_loop import no_evidence_completion

SCHEMA = "harness-investigation-closure-v029"
CLOSURE_SCHEMA = {
    "leads": [{"lead_id": "supplied lead id", "status": "investigated|not_relevant|unresolved",
               "explanation": "why the observations address the lead, or why it is irrelevant/unresolved",
               "supporting_fact_ids": ["fact_* query-result IDs, never event:*, block:* or lead IDs"],
               "next_step": "specific follow-up for an unresolved lead; otherwise empty"}],
    "limitations": ["remaining scope or effect limitations"],
}
PAGED_TOOLS = {"get_process_timeline", "list_events", "list_blocks", "search_events",
               "get_block_events", "find_command_invocations", "find_target_activity", "trace_process"}


def retrieval_coverage(fact, facts):
    """Count distinct returned query positions, not the sum of page lengths.

    A cursor is a position within one tool query. Exhausting representative
    offsets is not the same as retrieving every matching source event.
    """
    query = {k: v for k, v in fact.get("query", {}).items() if k not in {"cursor", "limit"}}
    total = fact.get("matched_count", 0)
    intervals = []
    for other in facts:
        other_query = {k: v for k, v in other.get("query", {}).items() if k not in {"cursor", "limit"}}
        if (other.get("source_tool") != fact.get("source_tool") or other_query != query
                or other.get("matched_count") != total):
            continue
        cursor = other.get("query", {}).get("cursor")
        if cursor is None:
            start = 0
        elif isinstance(cursor, str) and cursor.isdecimal():
            start = int(cursor)
        else:
            continue
        count = other.get("returned_count", 0)
        if type(count) is not int or count <= 0 or start + count > total:
            continue
        intervals.append((start, start + count, other["fact_id"]))
    covered = end = 0
    for lower, upper, _ in sorted(intervals):
        covered += max(0, upper - max(lower, end))
        end = max(end, upper)
    complete = total > 0 and covered == total
    return {"matched_count": total, "retrieved_count": covered,
            "complete": complete, "fact_ids": list(dict.fromkeys(fid for _, _, fid in sorted(intervals))),
            "scope": "returned query positions; not proof that every behavior was interpreted"}


def followup_leads(facts):
    """Expose concrete gaps in returned observations without assigning maliciousness."""
    leads = {}
    for fact in facts:
        fid = fact["fact_id"]
        if (fact.get("source_tool") in PAGED_TOOLS
                and fact.get("matched_count", 0) > fact.get("returned_count", 0)):
            lead_id = "page:" + fid
            coverage = retrieval_coverage(fact, facts)
            leads[lead_id] = {
                "lead_id": lead_id, "kind": "partial_retrieval", "source_fact_ids": [fid],
                "description": ("The matching query positions have been retrieved across the supplied pages. "
                                "This retrieval lead may be closed using those observations; behavior-fragment and child leads remain separate."
                                if coverage["complete"] else
                                "Only part of the matching behavior was retrieved. Assess whether omitted context could change the finding. "
                                "Without a next cursor, use a targeted source query or retain the unexamined scope; representative exhaustion is not full coverage."),
                "query": fact.get("query", {}), "next_cursor": fact.get("cursor"),
                "matched_count": fact["matched_count"], "returned_count": fact.get("returned_count", 0),
                "retrieval_coverage": coverage,
            }
        for event in fact.get("event_examples", []):
            parsed = event.get("parsed_detail", {})
            child = parsed.get("child_pid")
            if (event.get("operation", "").casefold() == "process create"
                    and event.get("result", "").casefold() == "success"
                    and type(child) is int and child > 0):
                lead_id = "child:" + str(event.get("offset"))
                leads.setdefault(lead_id, {
                    "lead_id": lead_id, "kind": "delegated_execution", "source_fact_ids": [fid],
                    "description": "A process created a child. Examine its subsequent activity where attribution and available tools permit; a start record alone does not explain its purpose.",
                    "child_pid": child, "parent_process": event.get("process", {}),
                    "event_ref_id": "event:" + str(event.get("offset")),
                })
        if fact.get("source_tool") in {"list_blocks", "summarize_blocks"}:
            for block in fact.get("block_examples", []):
                if (block.get("behavior_kind") not in {"file_transformation", "registry_modification", "process_execution"}
                        or not block.get("block_id")):
                    continue
                bid = block["block_id"]
                leads.setdefault("block:" + bid, {
                    "lead_id": "block:" + bid, "kind": "behavior_fragment", "source_fact_ids": [fid],
                    "description": "A returned fragment contains modification or execution activity. Expand relevant operations, or explain why the fragment does not affect this role's finding.",
                    "block_id": bid, "behavior_kind": block["behavior_kind"],
                })
    return list(leads.values())


def validate_closure(value, facts, *, can_follow_up):
    if not isinstance(value, dict) or set(value) != {"leads", "limitations"}:
        raise ValueError("investigation_closure must contain leads and limitations")
    expected = {lead["lead_id"]: lead for lead in followup_leads(facts)}
    known = {fact["fact_id"] for fact in facts}
    items = value["leads"]
    if not isinstance(items, list):
        raise ValueError("closure leads must be a list")
    normalized = []
    seen = set()
    errors = []
    for index, item in enumerate(items):
        try:
            record = validate_closure_lead(item, expected, known, can_follow_up=can_follow_up)
            if record['lead_id'] in seen:
                raise ValueError("closure cites an unknown or duplicate lead")
            normalized.append(record)
            seen.add(record['lead_id'])
        except ValueError as exc:
            errors.append(f"closure.leads[{index}]: {exc}")
    supplied = {item.get('lead_id') for item in items if isinstance(item, dict) and isinstance(item.get('lead_id'), str)}
    missing = sorted(set(expected) - supplied)
    if missing:
        errors.append("Every supplied follow-up lead requires an explicit disposition; missing lead_ids: " + str(missing))
    if errors:
        raise ValueError("; ".join(errors))
    return {"schema_version": SCHEMA, "leads": normalized,
            "limitations": texts(value["limitations"], "closure limitations"),
            "unresolved_count": sum(item["status"] == "unresolved" for item in normalized),
            "semantic_explanations_verified": False}


def validate_closure_lead(item, expected, known, *, can_follow_up):
    if not isinstance(item, dict) or set(item) != {"lead_id", "status", "explanation", "supporting_fact_ids", "next_step"}:
        raise ValueError("invalid closure lead fields")
    lid = item["lead_id"]
    if not isinstance(lid, str) or lid not in expected:
        raise ValueError("closure cites an unknown or duplicate lead")
    status = item["status"]
    if not isinstance(status, str) or status not in {"investigated", "not_relevant", "unresolved"}:
        raise ValueError("invalid closure lead status")
    refs = texts(item["supporting_fact_ids"], "supporting_fact_ids", required=True)
    if set(refs) - known:
        raise ValueError("closure cites an unknown fact; supporting_fact_ids accepts fact_* query-result IDs only: " + str(sorted(set(refs) - known)))
    explanation = text(item["explanation"], "closure explanation")
    next_step = item["next_step"]
    if not isinstance(next_step, str):
        raise ValueError("closure next_step must be a string")
    retrieval = expected[lid].get("retrieval_coverage")
    if status == "investigated" and retrieval and retrieval["complete"]:
        # Preserve the machine-checked page chain even when the model cites
        # only its terminal page. Never manufacture another observation.
        refs = list(dict.fromkeys(refs + retrieval["fact_ids"]))
    if (status == "investigated" and not (retrieval and retrieval["complete"])
            and not (set(refs) - set(expected[lid]["source_fact_ids"]))):
        raise ValueError("an investigated lead needs a follow-up observation, not only the original lead")
    if status == "unresolved":
        text(next_step, "unresolved lead next_step")
        if can_follow_up and not (retrieval and retrieval["complete"]):
            raise ValueError("Important leads remain unresolved while investigation budget is available; follow up with an allowed tool, or justify irrelevance")
    record = {"lead_id": lid, "status": status, "explanation": explanation,
              "supporting_fact_ids": refs, "next_step": next_step.strip()}
    if retrieval:
        record["retrieval_coverage"] = retrieval
    return record


class FollowupContextBuilder(CompatibleContextBuilder):
    def build(self, agent_id, memory, loop_state, *args, **kwargs):
        context = super().build(agent_id, memory, loop_state, *args, **kwargs)
        facts = [evidence_view(fact.to_dict()) for fact in memory.facts]
        return replace(context, working_context={**context.working_context,
                       "followup_leads": followup_leads(facts),
                       "investigation_fact_ids": [fact["fact_id"] for fact in facts],
                       "reference_contract": {
                           "closure_supporting_fact_ids": [fact["fact_id"] for fact in facts],
                           "supporting_block_ids": list(memory.block_ids()),
                           "rule": "Claim evidence_ref_ids uses returned event:* or block:*; closure supporting_fact_ids uses fact_* only.",
                       }},
                       output_schema={**deepcopy(context.output_schema), "investigation_closure": CLOSURE_SCHEMA})


class FollowupEvidenceRunner(SubmissionCorrectionRunner):
    def __init__(self, registry, client, config=None, agent_prompts=None):
        super().__init__(registry, client, config=config, agent_prompts=agent_prompts)
        self.context_builder = FollowupContextBuilder(registry, self.context_builder.agent_prompts)
        self._closure_value = None
        self._validated_closure = None

    def messages_for_context(self, context):
        messages = list(super().messages_for_context(context))
        payload = json.loads(messages[-1]["content"])
        payload["output_schema"]["investigation_closure"] = CLOSURE_SCHEMA
        payload["instruction"] += (
            " For a terminal claim_output or no_evidence, include investigation_closure beside the action envelope. "
            "Dispose of every supplied followup_lead. Prioritize relevant child activity, unexplained modification fragments "
            "and omitted timeline context within the existing budget. A complete retrieval_coverage closes only the pagination gap, "
            "not interpretation of the returned behavior. Do not request a nonexistent next page or cite an unrelated query as follow-up. "
            "Do not read every event merely to maximize coverage. A lead may be not_relevant with a specific, evidence-based "
            "explanation; this does not classify the sample. Use investigated only with a follow-up observation. "
            "supporting_fact_ids contains only fact_* query-result IDs from investigation_fact_ids; never event:*, "
            "block:* or child:* IDs. Include EVERY followup_lead exactly once, including at correction; "
            "do not replace the list by a representative subset. "
            "At the final budgeted response, retain unresolved leads and concrete next steps as limitations; never invent their resolution. "
            "Use process.process_key from an event or process_instance.key from a block for process_key arguments; "
            "node_id identifies a tree node and is not a process_key. When only a PID is known, omit process_key and state attribution limits. "
            "Prefer relevant block expansions and target-specific queries over successive pages of ordinary startup events. "
            "Local runtime initialization does not explain a child's complete purpose. No extra tools or rounds are granted."
        )
        if self.config.strict_json_schema:
            from harness.structured_output import agent_schema
            payload = agent_schema(payload,self.registry)
            self._last_strict_output_schema = deepcopy(payload['output_schema'])
        messages[-1] = {"role": "user", "content": json.dumps(payload, sort_keys=True)}
        return tuple(messages)

    def parse_response(self, response):
        self._closure_value = None
        if isinstance(response, dict):
            response = dict(response)
            self._closure_value = response.pop("investigation_closure", None)
        action = super().parse_response(response)
        if action.kind == "tool_request":
            try:
                self.registry.validate_arguments(action.tool_name, action.arguments)
            except ValueError as exc:
                from .llm_protocol import AgentAction
                return AgentAction("invalid", error=str(exc))
        return action

    def terminal_submission_error(self, action, memory, loop_state, *, correction=False):
        state = loop_state if isinstance(loop_state, dict) else loop_state.to_dict()
        can_follow_up = (not correction and state["round_index"] + 1 < state["max_rounds"]
                         and state["remaining_tool_calls"] > 0)
        errors = []
        # A bad closure must not hide claim errors until the sole correction
        # has already been spent. Neither preflight mutates the claim ledger.
        if action.kind == "claim_output":
            try:
                record_reasoned_claims("submission", ReasonedClaimLedger(), action.claims, memory)
            except ValueError as exc:
                errors.append(str(exc))
        elif action.kind == "no_evidence":
            try:
                no_evidence_completion(action, memory)
            except ValueError as exc:
                errors.append(str(exc))
        try:
            self._validated_closure = validate_closure(self._closure_value,
                                                     [evidence_view(fact.to_dict()) for fact in memory.facts],
                                                     can_follow_up=can_follow_up)
        except ValueError as exc:
            self._validated_closure = None
            errors.append(str(exc))
        return "; ".join(errors) if errors else None

    def run(self, *args, **kwargs):
        self._validated_closure = None
        self._last_strict_output_schema = None
        result = super().run(*args, **kwargs)
        diagnostics = {**result.diagnostics, "investigation_closure_policy": SCHEMA}
        if self.config.strict_json_schema:
            diagnostics['strict_json_schema'] = True
            if self._last_strict_output_schema is not None:
                result = replace(result,context=replace(result.context,output_schema=self._last_strict_output_schema))
        if result.status in {"completed", "completed_no_evidence"}:
            diagnostics["investigation_closure"] = self._validated_closure
        return replace(result, diagnostics=diagnostics)

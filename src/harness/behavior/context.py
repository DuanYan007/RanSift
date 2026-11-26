"""LLM-facing context, memory, and dry-run runner for behavior agents."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .classification import (
    DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE,
    DETERMINISTIC_DIRECT_USER_EXTENSION_TRANSITION_RULE,
    DETERMINISTIC_REPEATED_EXTENSION_TRANSFORMATION_RULE,
    DETERMINISTIC_REPEATED_EXTENSION_RENAME_TRANSFORMATION_RULE,
    DETERMINISTIC_RAW_FILESYSTEM_METADATA_WRITE_RULE,
    DETERMINISTIC_RANSOM_NOTE_ARTIFACT_RULE,
    DETERMINISTIC_RUN_KEY_EXECUTABLE_BINDING_RULE,
    DETERMINISTIC_EXECUTED_DESTRUCTIVE_RECOVERY_COMMAND_RULE,
    DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE,
    DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE,
    annotate_claim_semantics,
)

from .agent_prompts import AGENT_PROMPTS, AgentPrompt, default_prompt
from .llm_protocol import OUTPUT_SCHEMA
from .system_policy import EVIDENCE_POLICY, SYSTEM_PROMPT
from .evidence import ToolResult, compact_event_for_memory
from .registry import EvidenceLedger, ToolRegistry

CONFIDENCE_LEVELS = {"low", "medium", "high"}


@dataclass(frozen=True)
class MemoryFact:
    fact_id: str
    source_tool: str
    query: dict[str, Any]
    summary: str
    evidence_ref_ids: tuple[str, ...]
    block_ids: tuple[str, ...]
    event_offsets: tuple[int, ...]
    aggregate_digest: dict[str, Any] = field(default_factory=dict)
    deterministic_rule_supports: tuple[dict[str, Any], ...] = ()
    event_examples: tuple[dict[str, Any], ...] = ()
    block_examples: tuple[dict[str, Any], ...] = ()
    limitations: tuple[str, ...] = ()
    purpose: str | None = None
    matched_count: int = 0
    returned_count: int = 0
    returned_event_count: int = 0
    returned_block_count: int = 0
    cursor: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "source_tool": self.source_tool,
            "query": self.query,
            "summary": self.summary,
            "evidence_ref_ids": list(self.evidence_ref_ids),
            "block_ids": list(self.block_ids),
            "event_offsets": list(self.event_offsets),
            "aggregate_digest": self.aggregate_digest,
            "deterministic_rule_supports": [
                dict(support) for support in self.deterministic_rule_supports
            ],
            "event_examples": list(self.event_examples),
            "block_examples": list(self.block_examples),
            "limitations": list(self.limitations),
            "purpose": self.purpose,
            "matched_count": self.matched_count,
            "returned_count": self.returned_count,
            "cursor": self.cursor,
            "visibility": {
                "returned_event_count": self.returned_event_count,
                "visible_event_count": len(self.event_examples),
                "hidden_event_count": max(0, self.returned_event_count - len(self.event_examples)),
                "returned_block_count": self.returned_block_count,
                "visible_block_count": len(self.block_examples),
                "hidden_block_count": max(0, self.returned_block_count - len(self.block_examples)),
            },
        }


@dataclass
class WorkingMemory:
    facts: list[MemoryFact] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    max_facts: int = 12

    def record_observation(self, result: ToolResult, purpose: str | None = None) -> MemoryFact:
        event_offsets = tuple(unique_ints(ref.offset for ref in result.evidence_refs if ref.offset is not None))
        fact = MemoryFact(
            fact_id=f"fact_{len(self.facts) + 1:06d}",
            source_tool=result.tool_name,
            query=dict(result.query),
            summary=summarize_tool_result(result),
            evidence_ref_ids=tuple(ref.ref_id for ref in result.evidence_refs),
            block_ids=tuple(unique_values(block_ids_from_result(result))),
            event_offsets=event_offsets,
            aggregate_digest=compact_value(result.aggregates),
            deterministic_rule_supports=deterministic_rule_supports_from_result(result),
            event_examples=tuple(
                compact_event_for_memory(event, offset=event_offsets[index] if index < len(event_offsets) else None)
                for index, event in enumerate(result.events[:5])
            ),
            block_examples=tuple(compact_value(block, max_items=8) for block in result.blocks[:5]),
            limitations=tuple(result.limitations),
            purpose=purpose,
            matched_count=result.matched_count,
            returned_count=result.returned_count,
            returned_event_count=len(result.events),
            returned_block_count=len(result.blocks),
            cursor=result.cursor,
        )
        self.facts.append(fact)
        return fact

    def add_open_question(self, question: str) -> None:
        if question and question not in self.open_questions:
            self.open_questions.append(question)

    def evidence_ref_ids(self) -> tuple[str, ...]:
        return tuple(unique_values(ref_id for fact in self.facts for ref_id in fact.evidence_ref_ids))

    def block_ids(self) -> tuple[str, ...]:
        return tuple(unique_values(block_id for fact in self.facts for block_id in fact.block_ids))

    def to_context(self) -> dict[str, Any]:
        recent = self.facts[-self.max_facts:]
        return {
            "facts": [fact.to_dict() for fact in recent],
            "deterministic_claim_contracts": deterministic_claim_contracts(recent),
            "visible_fact_ids": [fact.fact_id for fact in recent],
            "open_questions": list(self.open_questions),
            "evidence_ref_count": len(self.evidence_ref_ids()),
            "block_ref_count": len(self.block_ids()),
            "truncated_fact_count": max(0, len(self.facts) - len(recent)),
        }


@dataclass(frozen=True)
class Claim:
    claim_id: str
    agent_id: str
    claim_type: str
    statement: str
    confidence: str
    evidence_ref_ids: tuple[str, ...]
    supporting_block_ids: tuple[str, ...] = ()
    alternative_explanations: tuple[str, ...] = ()
    supporting_rule_ids: tuple[str, ...] = ()
    uncertainty: tuple[str, ...] = ()
    status: str = "candidate"
    behavior_class: str = "unclassified"
    risk_primitives: tuple[str, ...] = ()
    dual_use_primitives: tuple[str, ...] = ()
    review_notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.confidence not in CONFIDENCE_LEVELS:
            raise ValueError(f"unsupported confidence: {self.confidence}")
        if not self.evidence_ref_ids:
            raise ValueError("claim must cite at least one evidence reference")

    def with_status(self, status: str, notes: tuple[str, ...] = ()) -> "Claim":
        return Claim(
            claim_id=self.claim_id,
            agent_id=self.agent_id,
            claim_type=self.claim_type,
            statement=self.statement,
            confidence=self.confidence,
            evidence_ref_ids=self.evidence_ref_ids,
            supporting_block_ids=self.supporting_block_ids,
            supporting_rule_ids=self.supporting_rule_ids,
            alternative_explanations=self.alternative_explanations,
            uncertainty=self.uncertainty,
            status=status,
            behavior_class=self.behavior_class,
            risk_primitives=self.risk_primitives,
            dual_use_primitives=self.dual_use_primitives,
            review_notes=notes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "agent_id": self.agent_id,
            "claim_type": self.claim_type,
            "statement": self.statement,
            "confidence": self.confidence,
            "evidence_ref_ids": list(self.evidence_ref_ids),
            "supporting_block_ids": list(self.supporting_block_ids),
            "alternative_explanations": list(self.alternative_explanations),
            "supporting_rule_ids": list(self.supporting_rule_ids),
            "uncertainty": list(self.uncertainty),
            "status": self.status,
            "behavior_class": self.behavior_class,
            "risk_primitives": list(self.risk_primitives),
            "dual_use_primitives": list(self.dual_use_primitives),
            "review_notes": list(self.review_notes),
        }


@dataclass
class ClaimLedger:
    claims: dict[str, Claim] = field(default_factory=dict)

    def add_candidate(
        self,
        agent_id: str,
        claim_type: str,
        statement: str,
        confidence: str,
        evidence_ref_ids: tuple[str, ...],
        supporting_block_ids: tuple[str, ...] = (),
        alternative_explanations: tuple[str, ...] = (),
        supporting_rule_ids: tuple[str, ...] = (),
        uncertainty: tuple[str, ...] = (),
        claim_id: str | None = None,
        known_ref_ids: tuple[str, ...] | None = None,
        behavior_class: str | None = None,
        risk_primitives: tuple[str, ...] = (),
        dual_use_primitives: tuple[str, ...] = (),
    ) -> Claim:
        if known_ref_ids is not None:
            unknown = sorted(set(evidence_ref_ids) - set(known_ref_ids))
            if unknown:
                raise ValueError(f"claim cites unknown evidence refs: {unknown}")
        base_claim = {
            "claim_id": claim_id or f"claim_{len(self.claims) + 1:06d}",
            "agent_id": agent_id,
            "claim_type": claim_type,
            "statement": statement,
            "confidence": confidence,
            "evidence_ref_ids": tuple(unique_values(evidence_ref_ids)),
            "supporting_block_ids": tuple(unique_values(supporting_block_ids)),
            "alternative_explanations": alternative_explanations,
            "supporting_rule_ids": tuple(unique_values(supporting_rule_ids)),
            "uncertainty": uncertainty,
            "status": "candidate",
            "behavior_class": behavior_class or "",
            "risk_primitives": risk_primitives,
            "dual_use_primitives": dual_use_primitives,
        }
        semantics = annotate_claim_semantics(base_claim)
        claim = Claim(
            claim_id=base_claim["claim_id"],
            agent_id=agent_id,
            claim_type=claim_type,
            statement=statement,
            confidence=confidence,
            evidence_ref_ids=base_claim["evidence_ref_ids"],
            supporting_block_ids=base_claim["supporting_block_ids"],
            alternative_explanations=alternative_explanations,
            supporting_rule_ids=base_claim["supporting_rule_ids"],
            uncertainty=uncertainty,
            behavior_class=str(semantics.get("behavior_class") or "unclassified"),
            risk_primitives=tuple(unique_values(semantics.get("risk_primitives") or ())),
            dual_use_primitives=tuple(unique_values(semantics.get("dual_use_primitives") or ())),
        )
        self.claims[claim.claim_id] = claim
        return claim

    def mark(self, claim_id: str, status: str, notes: tuple[str, ...] = ()) -> Claim:
        if claim_id not in self.claims:
            raise KeyError(f"unknown claim: {claim_id}")
        claim = self.claims[claim_id].with_status(status, notes)
        self.claims[claim_id] = claim
        return claim

    def accepted(self) -> list[Claim]:
        return [claim for claim in self.claims.values() if claim.status == "accepted"]

    def to_context(self) -> dict[str, Any]:
        return {
            "claims": [claim.to_dict() for claim in self.claims.values()],
            "claim_count": len(self.claims),
        }


@dataclass
class LoopState:
    agent_id: str
    round_index: int = 0
    max_rounds: int = 4
    remaining_tool_calls: int = 8
    previous_tool_calls: list[dict[str, Any]] = field(default_factory=list)
    unresolved_questions: list[str] = field(default_factory=list)

    def record_tool_call(self, result: ToolResult) -> None:
        self.previous_tool_calls.append({
            "tool_name": result.tool_name,
            "query": result.query,
            "matched_count": result.matched_count,
            "returned_count": result.returned_count,
            "limitations": list(result.limitations),
        })
        self.remaining_tool_calls = max(0, self.remaining_tool_calls - 1)

    def add_unresolved_question(self, question: str) -> None:
        if question and question not in self.unresolved_questions:
            self.unresolved_questions.append(question)

    def next_round(self) -> None:
        self.round_index += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "round_index": self.round_index,
            "max_rounds": self.max_rounds,
            "remaining_tool_calls": self.remaining_tool_calls,
            "previous_tool_calls": list(self.previous_tool_calls),
            "unresolved_questions": list(self.unresolved_questions),
        }


@dataclass(frozen=True)
class LLMContext:
    system_prompt: str
    agent_prompt: dict[str, Any]
    task_prompt: str
    evidence_policy: tuple[str, ...]
    available_tools: tuple[dict[str, Any], ...]
    working_context: dict[str, Any]
    loop_state: dict[str, Any]
    output_schema: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "system_prompt": self.system_prompt,
            "agent_prompt": self.agent_prompt,
            "task_prompt": self.task_prompt,
            "evidence_policy": list(self.evidence_policy),
            "available_tools": list(self.available_tools),
            "working_context": self.working_context,
            "loop_state": self.loop_state,
            "output_schema": self.output_schema,
        }


class LLMContextBuilder:
    def __init__(
        self,
        registry: ToolRegistry,
        agent_prompts: dict[str, AgentPrompt] | None = None,
    ) -> None:
        self.registry = registry
        self.agent_prompts = dict(AGENT_PROMPTS) if agent_prompts is None else dict(agent_prompts)

    def build(
        self,
        agent_id: str,
        memory: WorkingMemory,
        loop_state: LoopState,
        task_prompt: str | None = None,
        claim_ledger: ClaimLedger | None = None,
        session_context: dict[str, Any] | None = None,
    ) -> LLMContext:
        prompt = self.agent_prompts.get(agent_id, default_prompt(agent_id))
        tools = tuple(spec.to_dict() for spec in self.registry.specs_for_agent(agent_id))
        working_context = memory.to_context()
        working_context["query_surface"] = self.registry.tools.store.query_surface()
        if session_context is not None:
            working_context["session_context"] = session_context
        if claim_ledger is not None:
            working_context["claim_ledger"] = claim_ledger.to_context()
        return LLMContext(
            system_prompt=SYSTEM_PROMPT,
            agent_prompt=prompt.to_dict(),
            task_prompt=task_prompt or prompt.default_task,
            evidence_policy=EVIDENCE_POLICY,
            available_tools=tools,
            working_context=working_context,
            loop_state=loop_state.to_dict(),
            output_schema=OUTPUT_SCHEMA,
        )


@dataclass(frozen=True)
class ToolCallPlan:
    tool_name: str
    kwargs: dict[str, Any]
    purpose: str | None = None


@dataclass(frozen=True)
class DryRunResult:
    context: LLMContext
    memory: WorkingMemory
    claim_ledger: ClaimLedger
    evidence_ledger: EvidenceLedger

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context.to_dict(),
            "memory": self.memory.to_context(),
            "claim_ledger": self.claim_ledger.to_context(),
            "evidence_ledger": self.evidence_ledger.to_dict(),
        }


class DryRunAgentRunner:
    """Executes planned tool calls without invoking an external model."""

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry
        self.context_builder = LLMContextBuilder(registry)

    def run(
        self,
        agent_id: str,
        tool_calls: tuple[ToolCallPlan, ...],
        task_prompt: str | None = None,
        claim_statement: str | None = None,
        claim_type: str = "behavior_observation",
        confidence: str = "medium",
    ) -> DryRunResult:
        memory = WorkingMemory()
        claims = ClaimLedger()
        evidence_ledger = EvidenceLedger()
        loop_state = LoopState(agent_id=agent_id, remaining_tool_calls=len(tool_calls))
        for call in tool_calls:
            result = self.registry.call_for_agent(agent_id, call.tool_name, ledger=evidence_ledger, **call.kwargs)
            memory.record_observation(result, purpose=call.purpose)
            loop_state.record_tool_call(result)
        if claim_statement:
            claims.add_candidate(
                agent_id=agent_id,
                claim_type=claim_type,
                statement=claim_statement,
                confidence=confidence,
                evidence_ref_ids=memory.evidence_ref_ids(),
                supporting_block_ids=memory.block_ids(),
                known_ref_ids=memory.evidence_ref_ids(),
            )
        context = self.context_builder.build(agent_id, memory, loop_state, task_prompt, claims)
        return DryRunResult(context, memory, claims, evidence_ledger)


def summarize_tool_result(result: ToolResult) -> str:
    parts = [
        f"{result.tool_name} matched {result.matched_count} item(s)",
        f"returned {result.returned_count}",
        f"refs {len(result.evidence_refs)}",
    ]
    if result.blocks:
        parts.append(f"blocks {len(result.blocks)}")
    if result.events:
        parts.append(f"events {len(result.events)}")
    if result.limitations:
        parts.append("limitations: " + "; ".join(result.limitations))
    return ", ".join(parts)


def block_ids_from_result(result: ToolResult) -> list[str]:
    block_ids: list[str] = []
    for ref in result.evidence_refs:
        if ref.block_id:
            block_ids.append(ref.block_id)
    for block in result.blocks:
        block_id = block.get("block_id")
        if block_id:
            block_ids.append(str(block_id))
    return block_ids


DETERMINISTIC_RULE_CONTRACTS = {
    "find_file_extension_renames": {
        "rule_id": DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE,
        "minimum_key": "min_rename_count",
        "count_key": "rename_count",
        "requires_scope_count": True,
    },
}


def deterministic_rule_supports_from_result(result: ToolResult) -> tuple[dict[str, Any], ...]:
    if result.tool_name == "find_destructive_recovery_commands":
        return deterministic_recovery_command_supports_from_result(result)
    if result.tool_name == "find_concealed_script_host_fingerprinting":
        return deterministic_concealed_script_host_fingerprinting_supports_from_result(result)
    if result.tool_name == "find_deployed_elevated_autostart_tasks":
        return deterministic_deployed_elevated_autostart_task_supports_from_result(result)
    if result.tool_name == "find_file_extension_transitions":
        return deterministic_file_extension_transition_supports_from_result(result)
    if result.tool_name == "find_file_extension_renames":
        return deterministic_file_extension_rename_supports_from_result(result)
    if result.tool_name == "find_raw_filesystem_metadata_writes":
        return deterministic_raw_filesystem_metadata_write_supports_from_result(result)
    if result.tool_name == "find_ransom_note_artifacts":
        return deterministic_ransom_note_artifact_supports_from_result(result)
    if result.tool_name == "find_run_key_executable_bindings":
        return deterministic_run_key_executable_binding_supports_from_result(result)
    contract = DETERMINISTIC_RULE_CONTRACTS.get(result.tool_name)
    if contract is None:
        return ()
    if str(result.query.get("scope") or "") != "direct_user_shared":
        return ()
    minimum_key = str(contract["minimum_key"])
    try:
        minimum = int(result.query.get(minimum_key) or 0)
    except (TypeError, ValueError):
        return ()
    if minimum < 3:
        return ()

    minimum_scope_count = 0
    if bool(contract["requires_scope_count"]):
        try:
            minimum_scope_count = int(result.query.get("min_scope_count") or 0)
        except (TypeError, ValueError):
            return ()
        if minimum_scope_count < 2:
            return ()

    raw_supports = result.aggregates.get("deterministic_rule_supports")
    if not isinstance(raw_supports, list):
        return ()
    available_refs = {ref.ref_id for ref in result.evidence_refs}
    expected_rule_id = str(contract["rule_id"])
    count_key = str(contract["count_key"])
    supports: list[dict[str, Any]] = []
    for raw in raw_supports:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("rule_id") or "") != expected_rule_id:
            continue
        refs = tuple(str(item) for item in raw.get("evidence_ref_ids") or ())
        if len(refs) != 2 or any(not ref.startswith("event:") for ref in refs):
            continue
        if refs[0] == refs[1] or not set(refs).issubset(available_refs):
            continue
        try:
            count = int(raw.get(count_key) or 0)
        except (TypeError, ValueError):
            continue
        if count < minimum:
            continue
        if minimum_scope_count:
            try:
                qualifying_scope_count = int(raw.get("qualifying_scope_count") or 0)
            except (TypeError, ValueError):
                continue
            scopes = {
                str(item)
                for item in raw.get("target_scopes") or ()
                if str(item)
            }
            if (
                qualifying_scope_count < minimum_scope_count
                or len(scopes) < 2
            ):
                continue
        support = dict(raw)
        support["rule_id"] = expected_rule_id
        support["evidence_ref_ids"] = refs
        support[count_key] = count
        supports.append(support)
    return tuple(supports)


def deterministic_file_extension_transition_supports_from_result(
    result: ToolResult,
) -> tuple[dict[str, Any], ...]:
    scope = str(result.query.get("scope") or "")
    try:
        minimum = int(result.query.get("min_pair_count") or 0)
    except (TypeError, ValueError):
        return ()
    if scope == "direct_user_shared" and minimum >= 3:
        expected_rule_id = DETERMINISTIC_DIRECT_USER_EXTENSION_TRANSITION_RULE
        required_count = minimum
    elif scope == "all" and minimum >= 20:
        expected_rule_id = DETERMINISTIC_REPEATED_EXTENSION_TRANSFORMATION_RULE
        required_count = 20
    else:
        return ()
    raw_supports = result.aggregates.get("deterministic_rule_supports")
    if not isinstance(raw_supports, list):
        return ()
    available_refs = {ref.ref_id for ref in result.evidence_refs}
    supports: list[dict[str, Any]] = []
    for raw in raw_supports:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("rule_id") or "") != expected_rule_id:
            continue
        refs = tuple(str(item) for item in raw.get("evidence_ref_ids") or ())
        if len(refs) != 2 or refs[0] == refs[1] or any(not ref.startswith("event:") for ref in refs):
            continue
        if not set(refs).issubset(available_refs):
            continue
        try:
            pair_count = int(raw.get("pair_count") or 0)
        except (TypeError, ValueError):
            continue
        if pair_count < required_count or not str(raw.get("extension") or ""):
            continue
        support = dict(raw)
        support["rule_id"] = expected_rule_id
        support["evidence_ref_ids"] = refs
        support["pair_count"] = pair_count
        supports.append(support)
    return tuple(supports)


def deterministic_file_extension_rename_supports_from_result(
    result: ToolResult,
) -> tuple[dict[str, Any], ...]:
    scope = str(result.query.get("scope") or "")
    try:
        minimum = int(result.query.get("min_rename_count") or 0)
    except (TypeError, ValueError):
        return ()
    broad_rule = scope == "all" and minimum >= 20
    direct_user_rule = scope == "direct_user_shared" and minimum >= 3
    if not broad_rule and not direct_user_rule:
        return ()
    try:
        minimum_scope_count = int(result.query.get("min_scope_count") or 0)
    except (TypeError, ValueError):
        return ()
    if direct_user_rule and minimum_scope_count < 2:
        return ()
    expected_rule_id = (
        DETERMINISTIC_REPEATED_EXTENSION_RENAME_TRANSFORMATION_RULE
        if broad_rule
        else DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE
    )
    raw_supports = result.aggregates.get("deterministic_rule_supports")
    if not isinstance(raw_supports, list):
        return ()
    available_refs = {ref.ref_id for ref in result.evidence_refs}
    supports: list[dict[str, Any]] = []
    for raw in raw_supports:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("rule_id") or "") != expected_rule_id:
            continue
        refs = tuple(str(item) for item in raw.get("evidence_ref_ids") or ())
        if len(refs) != 2 or refs[0] == refs[1] or any(not ref.startswith("event:") for ref in refs):
            continue
        if not set(refs).issubset(available_refs):
            continue
        try:
            rename_count = int(raw.get("rename_count") or 0)
        except (TypeError, ValueError):
            continue
        if rename_count < (20 if broad_rule else minimum):
            continue
        destination_extension = str(raw.get("destination_extension") or "")
        if not destination_extension:
            continue
        if broad_rule:
            try:
                unique_original_count = int(raw.get("unique_original_count") or 0)
            except (TypeError, ValueError):
                continue
            if (
                unique_original_count < 20
                or str(raw.get("rename_kind") or "") != "extension_append"
            ):
                continue
        else:
            try:
                qualifying_scope_count = int(raw.get("qualifying_scope_count") or 0)
            except (TypeError, ValueError):
                continue
            scopes = {
                str(item)
                for item in raw.get("target_scopes") or ()
                if str(item)
            }
            if qualifying_scope_count < minimum_scope_count or len(scopes) < 2:
                continue
        support = dict(raw)
        support["rule_id"] = expected_rule_id
        support["evidence_ref_ids"] = refs
        support["rename_count"] = rename_count
        supports.append(support)
    return tuple(supports)


def deterministic_raw_filesystem_metadata_write_supports_from_result(
    result: ToolResult,
) -> tuple[dict[str, Any], ...]:
    raw_supports = result.aggregates.get("deterministic_rule_supports")
    if not isinstance(raw_supports, list):
        return ()
    available_refs = {ref.ref_id for ref in result.evidence_refs}
    supports: list[dict[str, Any]] = []
    for raw in raw_supports:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("rule_id") or "") != DETERMINISTIC_RAW_FILESYSTEM_METADATA_WRITE_RULE:
            continue
        refs = tuple(str(item) for item in raw.get("evidence_ref_ids") or ())
        if (
            len(refs) < 2
            or len(set(refs)) != len(refs)
            or any(not ref.startswith("event:") for ref in refs)
            or not set(refs).issubset(available_refs)
        ):
            continue
        try:
            structural_write_count = int(raw.get("structural_write_count") or 0)
        except (TypeError, ValueError):
            continue
        metadata_objects = tuple(
            str(item) for item in raw.get("metadata_objects") or () if str(item)
        )
        if (
            structural_write_count < 20
            or not metadata_objects
            or any(not item.startswith("$") or item == "$logfile" for item in metadata_objects)
        ):
            continue
        support = dict(raw)
        support["rule_id"] = DETERMINISTIC_RAW_FILESYSTEM_METADATA_WRITE_RULE
        support["evidence_ref_ids"] = refs
        support["metadata_objects"] = metadata_objects
        support["structural_write_count"] = structural_write_count
        supports.append(support)
    return tuple(supports)


def deterministic_ransom_note_artifact_supports_from_result(
    result: ToolResult,
) -> tuple[dict[str, Any], ...]:
    raw_supports = result.aggregates.get("deterministic_rule_supports")
    if not isinstance(raw_supports, list):
        return ()
    available_refs = {ref.ref_id for ref in result.evidence_refs}
    supports: list[dict[str, Any]] = []
    for raw in raw_supports:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("rule_id") or "") != DETERMINISTIC_RANSOM_NOTE_ARTIFACT_RULE:
            continue
        refs = tuple(str(item) for item in raw.get("evidence_ref_ids") or ())
        if not refs or len(refs) > 2 or any(not ref.startswith("event:") for ref in refs):
            continue
        if not set(refs).issubset(available_refs):
            continue
        operation_kinds = tuple(str(item) for item in raw.get("operation_kinds") or () if str(item))
        if not set(operation_kinds) & {"create", "write"}:
            continue
        if not str(raw.get("note_path") or "") or not str(raw.get("note_basename") or ""):
            continue
        support = dict(raw)
        support["rule_id"] = DETERMINISTIC_RANSOM_NOTE_ARTIFACT_RULE
        support["evidence_ref_ids"] = refs
        support["operation_kinds"] = operation_kinds
        supports.append(support)
    return tuple(supports)


def deterministic_run_key_executable_binding_supports_from_result(
    result: ToolResult,
) -> tuple[dict[str, Any], ...]:
    raw_supports = result.aggregates.get("deterministic_rule_supports")
    if not isinstance(raw_supports, list):
        return ()
    available_refs = {ref.ref_id for ref in result.evidence_refs}
    supports: list[dict[str, Any]] = []
    for raw in raw_supports:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("rule_id") or "") != DETERMINISTIC_RUN_KEY_EXECUTABLE_BINDING_RULE:
            continue
        refs = tuple(str(item) for item in raw.get("evidence_ref_ids") or ())
        if len(refs) != 1 or not refs[0].startswith("event:") or not set(refs).issubset(available_refs):
            continue
        registry_key = str(raw.get("registry_key") or "").casefold()
        payload_path = str(raw.get("payload_path") or "").casefold()
        if "\\currentversion\\run" not in registry_key or not payload_path.endswith((".com", ".exe", ".pif", ".scr")):
            continue
        support = dict(raw)
        support["rule_id"] = DETERMINISTIC_RUN_KEY_EXECUTABLE_BINDING_RULE
        support["evidence_ref_ids"] = refs
        supports.append(support)
    return tuple(supports)


def deterministic_recovery_command_supports_from_result(result: ToolResult) -> tuple[dict[str, Any], ...]:
    raw_supports = result.aggregates.get("deterministic_rule_supports")
    if not isinstance(raw_supports, list):
        return ()
    available_refs = {ref.ref_id for ref in result.evidence_refs}
    supports: list[dict[str, Any]] = []
    for raw in raw_supports:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("rule_id") or "") != DETERMINISTIC_EXECUTED_DESTRUCTIVE_RECOVERY_COMMAND_RULE:
            continue
        refs = tuple(str(item) for item in raw.get("evidence_ref_ids") or ())
        if len(refs) != 2 or refs[0] == refs[1] or any(not ref.startswith("event:") for ref in refs):
            continue
        if not set(refs).issubset(available_refs):
            continue
        try:
            execution_count = int(raw.get("execution_count") or 0)
        except (TypeError, ValueError):
            continue
        if execution_count < 1 or not str(raw.get("command_kind") or ""):
            continue
        support = dict(raw)
        support["rule_id"] = DETERMINISTIC_EXECUTED_DESTRUCTIVE_RECOVERY_COMMAND_RULE
        support["evidence_ref_ids"] = refs
        support["execution_count"] = execution_count
        supports.append(support)
    return tuple(supports)


def deterministic_concealed_script_host_fingerprinting_supports_from_result(
    result: ToolResult,
) -> tuple[dict[str, Any], ...]:
    raw_supports = result.aggregates.get("deterministic_rule_supports")
    if not isinstance(raw_supports, list):
        return ()
    available_refs = {ref.ref_id for ref in result.evidence_refs}
    supports: list[dict[str, Any]] = []
    for raw in raw_supports:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("rule_id") or "") != DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE:
            continue
        refs = tuple(str(item) for item in raw.get("evidence_ref_ids") or ())
        if len(refs) != 2 or refs[0] == refs[1] or any(not ref.startswith("event:") for ref in refs):
            continue
        if not set(refs).issubset(available_refs):
            continue
        markers = tuple(str(item) for item in raw.get("concealment_markers") or () if str(item))
        if not markers or not str(raw.get("host_fingerprint_kind") or ""):
            continue
        try:
            decoded_layer_count = int(raw.get("decoded_layer_count") or 0)
            encoded_offset = int(raw.get("encoded_execution_offset"))
            fingerprint_offset = int(raw.get("host_fingerprint_offset"))
        except (TypeError, ValueError):
            continue
        if decoded_layer_count < 1 or encoded_offset == fingerprint_offset:
            continue
        if {f"event:{encoded_offset}", f"event:{fingerprint_offset}"} != set(refs):
            continue
        support = dict(raw)
        support["rule_id"] = DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE
        support["evidence_ref_ids"] = refs
        support["concealment_markers"] = markers
        support["decoded_layer_count"] = decoded_layer_count
        supports.append(support)
    return tuple(supports)



def deterministic_deployed_elevated_autostart_task_supports_from_result(
    result: ToolResult,
) -> tuple[dict[str, Any], ...]:
    raw_supports = result.aggregates.get("deterministic_rule_supports")
    if not isinstance(raw_supports, list):
        return ()
    available_refs = {ref.ref_id for ref in result.evidence_refs}
    supports: list[dict[str, Any]] = []
    for raw in raw_supports:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("rule_id") or "") != DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE:
            continue
        refs = tuple(str(item) for item in raw.get("evidence_ref_ids") or ())
        if len(refs) != 3 or len(set(refs)) != 3 or any(not ref.startswith("event:") for ref in refs):
            continue
        if not set(refs).issubset(available_refs):
            continue
        try:
            deployment_offset = int(raw.get("deployment_offset"))
            task_create_offset = int(raw.get("task_create_offset"))
            task_start_offset = int(raw.get("task_start_offset"))
        except (TypeError, ValueError):
            continue
        if {f"event:{deployment_offset}", f"event:{task_create_offset}", f"event:{task_start_offset}"} != set(refs):
            continue
        if not str(raw.get("deployed_path") or "") or not str(raw.get("task_target") or ""):
            continue
        if str(raw.get("task_trigger") or "").casefold() not in {"onlogon", "onstart"}:
            continue
        if raw.get("run_as_system") is not True or raw.get("run_level_highest") is not True:
            continue
        support = dict(raw)
        support["rule_id"] = DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE
        support["evidence_ref_ids"] = refs
        supports.append(support)
    return tuple(supports)

def deterministic_claim_contracts(facts: list[MemoryFact]) -> list[dict[str, Any]]:
    """Expose verified policy-boundary evidence as an LLM terminal contract."""
    contracts: list[dict[str, Any]] = []
    for fact in facts:
        for support in fact.deterministic_rule_supports:
            rule_id = str(support.get("rule_id") or "")
            refs = tuple(str(item) for item in support.get("evidence_ref_ids") or ())
            if not refs:
                continue
            if rule_id in {
                DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE,
                DETERMINISTIC_DIRECT_USER_EXTENSION_TRANSITION_RULE,
                DETERMINISTIC_REPEATED_EXTENSION_TRANSFORMATION_RULE,
                DETERMINISTIC_REPEATED_EXTENSION_RENAME_TRANSFORMATION_RULE,
            }:
                if len(refs) < 2:
                    continue
                contracts.append({
                    "fact_id": fact.fact_id,
                    "rule_id": rule_id,
                    "claim_type": "file_transformation_behavior",
                    "confidence": "high",
                    "required_evidence_ref_ids": list(refs),
                    "terminal_requirement": (
                        "Return a high-confidence file_transformation_behavior claim that cites both "
                        "required event references. This establishes a destructive user-data "
                        "transformation policy boundary, but does not by itself establish file-content encryption."
                    ),
                })
            elif rule_id == DETERMINISTIC_RAW_FILESYSTEM_METADATA_WRITE_RULE:
                contracts.append({
                    "fact_id": fact.fact_id,
                    "rule_id": rule_id,
                    "claim_type": "file_transformation_behavior",
                    "confidence": "high",
                    "required_evidence_ref_ids": list(refs),
                    "terminal_requirement": (
                        "Return a high-confidence file_transformation_behavior claim that cites the required "
                        "event reference. It establishes a successful write to a raw filesystem metadata "
                        "object; do not claim wider filesystem corruption unless separately observed."
                    ),
                })
            elif rule_id == DETERMINISTIC_RANSOM_NOTE_ARTIFACT_RULE:
                contracts.append({
                    "fact_id": fact.fact_id,
                    "rule_id": rule_id,
                    "claim_type": "ransom_note_deployment_behavior|ransom_note_deployment_uncertain",
                    "confidence": "medium_or_high",
                    "required_evidence_ref_ids": list(refs),
                    "terminal_requirement": (
                        "Return a ransom_note_deployment_behavior or ransom_note_deployment_uncertain claim "
                        "with medium or high confidence and cite the required event reference. A verified "
                        "note-like artifact cannot be concluded as no_evidence; preserve uncertainty about "
                        "note content, encryption, or extortion impact unless separately observed."
                    ),
                })
            elif rule_id == DETERMINISTIC_RUN_KEY_EXECUTABLE_BINDING_RULE:
                contracts.append({
                    "fact_id": fact.fact_id,
                    "rule_id": rule_id,
                    "claim_type": "registry_behavior|registry_uncertain",
                    "confidence": "medium_or_high",
                    "required_evidence_ref_ids": list(refs),
                    "terminal_requirement": (
                        "Return a registry_behavior or registry_uncertain claim with medium or high confidence "
                        "and cite the required event reference. A verified executable Run or RunOnce value "
                        "binding cannot be concluded as no_evidence; preserve uncertainty about later autostart "
                        "execution unless separately observed."
                    ),
                })
            elif rule_id == DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE:
                if len(refs) < 2:
                    continue
                contracts.append({
                    "fact_id": fact.fact_id,
                    "rule_id": rule_id,
                    "claim_type": "process_execution_behavior",
                    "confidence": "high",
                    "required_evidence_ref_ids": list(refs),
                    "terminal_requirement": (
                        "Return a high-confidence process_execution_behavior claim that cites both required "
                        "event references. They establish concealed encoded script execution with host "
                        "fingerprinting; do not claim encryption, exfiltration, or ransomware impact unless "
                        "separately observed."
                    ),
                })
            elif rule_id == DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE:
                if len(refs) < 3:
                    continue
                contracts.append({
                    "fact_id": fact.fact_id,
                    "rule_id": rule_id,
                    "claim_type": "process_execution_behavior",
                    "confidence": "high",
                    "required_evidence_ref_ids": list(refs),
                    "terminal_requirement": (
                        "Return a high-confidence process_execution_behavior claim that cites all three "
                        "required event references. They establish executable deployment and execution of an "
                        "elevated scheduled task configured for logon or startup; do not claim post-reboot "
                        "execution unless it is separately observed."
                    ),
                })
            elif rule_id == DETERMINISTIC_EXECUTED_DESTRUCTIVE_RECOVERY_COMMAND_RULE:
                if len(refs) < 2:
                    continue
                contracts.append({
                    "fact_id": fact.fact_id,
                    "rule_id": rule_id,
                    "claim_type": "recovery_impact_behavior",
                    "confidence": "medium_or_high",
                    "required_evidence_ref_ids": list(refs),
                    "terminal_requirement": (
                        "Return a recovery_impact_behavior claim that cites both required event references. "
                        "They establish execution of a destructive recovery command; describe the external "
                        "recovery-impact effect as uncertain unless it is separately observed."
                    ),
                })
    return contracts

def compact_value(value: Any, depth: int = 0, max_items: int = 3) -> Any:
    if depth >= 3:
        return "..."
    if isinstance(value, dict):
        return {str(k): compact_value(v, depth + 1, max_items) for k, v in list(value.items())[:max_items]}
    if isinstance(value, (list, tuple)):
        return [compact_value(item, depth + 1, max_items) for item in list(value)[:max_items]]
    return value


def unique_values(values: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out


def unique_ints(values: Any) -> list[int]:
    out: list[int] = []
    seen: set[int] = set()
    for value in values:
        item = int(value)
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out

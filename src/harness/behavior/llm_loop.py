"""LLM-backed ReAct loop for behavior evidence agents."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from .agent_prompts import AgentPrompt
from .context import ClaimLedger, LLMContext, LLMContextBuilder, LoopState, ToolCallPlan, WorkingMemory
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
)
from .llm_protocol import compact_response, context_to_messages, parse_agent_response, parse_json_object
from .registry import EvidenceLedger, ToolRegistry


class JSONChatClient(Protocol):
    """Minimal JSON chat interface used by the evidence loop."""

    def complete_json(self, messages: tuple[dict[str, str], ...]) -> dict[str, Any]:
        """Return a JSON object produced from the supplied chat messages."""


@dataclass(frozen=True)
class OpenAICompatibleConfig:
    model: str
    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = 60.0
    temperature: float = 0.0
    max_tokens: int | None = None
    parse_retries: int = 3

    @classmethod
    def from_env(cls) -> "OpenAICompatibleConfig":
        model = os.environ.get("HARNESS_LLM_MODEL") or os.environ.get("OPENAI_MODEL")
        if not model:
            raise ValueError("set HARNESS_LLM_MODEL or OPENAI_MODEL before constructing the LLM client")
        return cls(
            model=model,
            api_key=os.environ.get("HARNESS_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY"),
            base_url=(
                os.environ.get("HARNESS_LLM_BASE_URL")
                or os.environ.get("OPENAI_BASE_URL")
                or os.environ.get("OPENAI_API_BASE")
                or "https://api.openai.com/v1"
            ),
            timeout_seconds=float(os.environ.get("HARNESS_LLM_TIMEOUT", "60")),
            temperature=float(os.environ.get("HARNESS_LLM_TEMPERATURE", "0")),
            max_tokens=_optional_int(os.environ.get("HARNESS_LLM_MAX_TOKENS")),
            parse_retries=int(os.environ.get("HARNESS_LLM_PARSE_RETRIES", "3")),
        )


class OpenAISDKCompatibleChatClient:
    """SDK-backed client for OpenAI-compatible chat-completions APIs."""

    def __init__(self, config: OpenAICompatibleConfig | None = None, trust_env: bool = False) -> None:
        self.config = config or OpenAICompatibleConfig.from_env()
        try:
            from openai import OpenAI
            import httpx
        except ImportError as exc:
            raise RuntimeError("install openai and httpx to use OpenAISDKCompatibleChatClient") from exc
        self.client = OpenAI(
            base_url=self.config.base_url,
            api_key=self.config.api_key,
            http_client=httpx.Client(trust_env=trust_env, timeout=self.config.timeout_seconds),
            timeout=self.config.timeout_seconds,
        )

    def complete_json(self, messages: tuple[dict[str, str], ...]) -> dict[str, Any]:
        return self._complete_json(messages, attempts=max(1, self.config.parse_retries))

    def complete_json_once(self, messages: tuple[dict[str, str], ...]) -> dict[str, Any]:
        """One transport attempt and one JSON parse, for bounded submission repair."""
        return self._complete_json(messages, attempts=1,
                                   request_client=self.client.with_options(max_retries=0))

    def _complete_json(self, messages, *, attempts, request_client=None):
        from harness.model_context import assert_blind_model_messages
        from harness.structured_output import response_format, decode_output
        assert_blind_model_messages(messages)
        payload = json.loads(messages[-1]['content'])
        strict = 'structured_output' in payload
        kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": list(messages),
            "temperature": self.config.temperature,
            "response_format": response_format(payload),
        }
        if self.config.max_tokens is not None:
            kwargs["max_tokens"] = self.config.max_tokens

        last_error: Exception | None = None
        if strict and request_client is None:
            request_client = self.client.with_options(max_retries=0)
        for _attempt in range(1 if strict else attempts):
            response = self._create_completion(request_client or self.client, kwargs)
            content = response.choices[0].message.content or ""
            if strict and (response.choices[0].finish_reason != 'stop' or getattr(response.choices[0].message,'refusal',None)):
                error = ValueError('Strict structured output was refused or did not finish normally')
                error.raw_response_content = content
                raise error
            try:
                data = parse_json_object(content)
                if strict:
                    data = decode_output(data,payload)
            except (ValueError, json.JSONDecodeError) as exc:
                if strict:
                    error = ValueError('Strict structured output failed local validation: '+str(exc))
                    error.raw_response_content = content
                    raise error from exc
                last_error = exc
                continue
            if response.usage is not None:
                data["_usage"] = {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                }
            return data
        error = ValueError(f"LLM response was not parseable JSON after {attempts} attempt(s): {last_error}")
        error.raw_response_content = content
        raise error

    def _create_completion(self, request_client, kwargs):
        """Recorder hook shared by normal calls and a retry-disabled correction."""
        return request_client.chat.completions.create(**kwargs)


@dataclass(frozen=True)
class LLMEvidenceLoopConfig:
    max_rounds: int = 6
    max_tool_calls: int = 10
    stop_after_claim: bool = True
    max_response_format_retries: int = 1
    max_submission_corrections: int = 0
    require_investigation_closure: bool = False
    strict_json_schema: bool = False

    def __post_init__(self):
        if type(self.max_submission_corrections) is not int or self.max_submission_corrections not in (0, 1):
            raise ValueError("max_submission_corrections must be 0 or 1")
        if type(self.require_investigation_closure) is not bool:
            raise ValueError("require_investigation_closure must be a boolean")
        if type(self.strict_json_schema) is not bool:
            raise ValueError("strict_json_schema must be a boolean")
        if self.strict_json_schema and not self.require_investigation_closure:
            raise ValueError("strict_json_schema requires the closure-aware investigation runner")


@dataclass(frozen=True)
class LLMEvidenceLoopResult:
    status: str
    agent_id: str
    context: LLMContext
    memory: WorkingMemory
    claim_ledger: ClaimLedger
    evidence_ledger: EvidenceLedger
    model_responses: tuple[dict[str, Any], ...] = ()
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "agent_id": self.agent_id,
            "context": self.context.to_dict(),
            "memory": self.memory.to_context(),
            "claim_ledger": self.claim_ledger.to_context(),
            "evidence_ledger": self.evidence_ledger.to_dict(),
            "model_responses": list(self.model_responses),
            "diagnostics": self.diagnostics,
        }


class LLMEvidenceAgentRunner:
    """Runs an evidence agent by alternating LLM decisions and registry tool calls."""

    def __init__(
        self,
        registry: ToolRegistry,
        client: JSONChatClient,
        config: LLMEvidenceLoopConfig | None = None,
        agent_prompts: dict[str, AgentPrompt] | None = None,
    ) -> None:
        self.registry = registry
        self.client = client
        self.config = config or LLMEvidenceLoopConfig()
        self.context_builder = LLMContextBuilder(registry, agent_prompts=agent_prompts)

    def make_claim_ledger(self):
        return ClaimLedger()

    def make_memory(self):
        return WorkingMemory()

    def messages_for_context(self, context):
        return context_to_messages(context)

    def parse_response(self, response):
        return parse_agent_response(response)

    def claim_contract_error(self, agent_id, outputs, memory):
        return unmet_deterministic_claim_contract(agent_id, outputs, memory)

    def terminal_submission_error(self, action, memory, loop_state, *, correction=False):
        return None

    def record_claim_outputs(self, agent_id, ledger, outputs, memory):
        add_claim_outputs(agent_id, ledger, outputs, memory)

    def run(
        self,
        agent_id: str,
        task_prompt: str | None = None,
        seed_tool_calls: tuple[ToolCallPlan, ...] = (),
        session_context: dict[str, Any] | None = None,
    ) -> LLMEvidenceLoopResult:
        memory = self.make_memory()
        claims = self.make_claim_ledger()
        evidence_ledger = EvidenceLedger()
        loop_state = LoopState(
            agent_id=agent_id,
            max_rounds=self.config.max_rounds,
            remaining_tool_calls=self.config.max_tool_calls,
        )
        model_responses: list[dict[str, Any]] = []
        diagnostics: dict[str, Any] = {}

        response_format_retries = 0
        seed_error = self._run_seed_calls(agent_id, seed_tool_calls, memory, evidence_ledger, loop_state)
        if seed_error:
            diagnostics["error"] = seed_error
            context = self.context_builder.build(
                agent_id,
                memory,
                loop_state,
                task_prompt,
                claims,
                session_context=session_context,
            )
            return LLMEvidenceLoopResult(
                "tool_error",
                agent_id,
                context,
                memory,
                claims,
                evidence_ledger,
                diagnostics=diagnostics,
            )

        status = "exhausted"
        while loop_state.round_index < loop_state.max_rounds:
            context = self.context_builder.build(
                agent_id, memory, loop_state, task_prompt, claims, session_context=session_context
            )
            response = self.client.complete_json(self.messages_for_context(context))
            model_responses.append(compact_response(response))
            action = self.parse_response(response)

            if action.kind in {"claim_output", "no_evidence"}:
                closing_error = self.terminal_submission_error(action, memory, loop_state)
                if closing_error:
                    if not request_contract_correction(closing_error, diagnostics, memory, loop_state):
                        status = "invalid_response"
                        break
                    continue

            if action.kind == "tool_request":
                if loop_state.remaining_tool_calls <= 0:
                    memory.add_open_question("model requested a tool after the tool-call budget was exhausted")
                    diagnostics["error"] = "tool-call budget exhausted"
                    status = "exhausted"
                    break
                try:
                    result = self.registry.call_for_agent(
                        agent_id,
                        action.tool_name,
                        ledger=evidence_ledger,
                        **action.arguments,
                    )
                except (KeyError, PermissionError, TypeError, ValueError, IndexError) as exc:
                    diagnostics["error"] = str(exc)
                    diagnostics["failed_tool"] = action.tool_name
                    status = "tool_error"
                    break
                memory.record_observation(result, purpose=action.purpose)
                loop_state.record_tool_call(result)
                loop_state.next_round()
                continue
            if action.kind == "no_evidence":
                contract_error = self.claim_contract_error(
                    agent_id,
                    (),
                    memory,
                )
                if contract_error:
                    if not request_contract_correction(
                        contract_error,
                        diagnostics,
                        memory,
                        loop_state,
                    ):
                        status = "invalid_response"
                        break
                    continue
                try:
                    completion = no_evidence_completion(action, memory)
                except ValueError as exc:
                    if not request_contract_correction(
                        str(exc),
                        diagnostics,
                        memory,
                        loop_state,
                    ):
                        status = "invalid_response"
                        break
                    continue
                diagnostics["completion"] = completion
                status = "completed_no_evidence"
                break

            if action.kind == "claim_output":
                contract_error = self.claim_contract_error(
                    agent_id,
                    action.claims,
                    memory,
                )
                if contract_error:
                    if not request_contract_correction(
                        contract_error,
                        diagnostics,
                        memory,
                        loop_state,
                    ):
                        status = "invalid_response"
                        break
                    continue
                try:
                    self.record_claim_outputs(agent_id, claims, action.claims, memory)
                except ValueError as exc:
                    claim_error = (
                        f"{exc}. Return a corrected claim_output using only evidence references "
                        "already present in working_context; do not introduce new evidence."
                    )
                    if not request_contract_correction(
                        claim_error,
                        diagnostics,
                        memory,
                        loop_state,
                    ):
                        status = "invalid_response"
                        break
                    continue
                status = "completed"
                if self.config.stop_after_claim:
                    break
                loop_state.next_round()
                continue

            format_error = action.error or "unrecognized model response"
            if request_response_format_correction(
                format_error,
                diagnostics,
                memory,
                loop_state,
                retries_used=response_format_retries,
                max_retries=self.config.max_response_format_retries,
            ):
                response_format_retries += 1
                continue
            status = "invalid_response"
            break

        final_context = self.context_builder.build(
            agent_id, memory, loop_state, task_prompt, claims, session_context=session_context
        )
        return LLMEvidenceLoopResult(
            status=status,
            agent_id=agent_id,
            context=final_context,
            memory=memory,
            claim_ledger=claims,
            evidence_ledger=evidence_ledger,
            model_responses=tuple(model_responses),
            diagnostics=diagnostics,
        )

    def _run_seed_calls(
        self,
        agent_id: str,
        seed_tool_calls: tuple[ToolCallPlan, ...],
        memory: WorkingMemory,
        evidence_ledger: EvidenceLedger,
        loop_state: LoopState,
    ) -> str | None:
        for call in seed_tool_calls:
            if loop_state.remaining_tool_calls <= 0:
                return "tool-call budget exhausted during seed calls"
            try:
                result = self.registry.call_for_agent(agent_id, call.tool_name, ledger=evidence_ledger, **call.kwargs)
            except (KeyError, PermissionError, TypeError, ValueError, IndexError) as exc:
                return str(exc)
            memory.record_observation(result, purpose=call.purpose)
            loop_state.record_tool_call(result)
        return None


def add_claim_outputs(
    agent_id: str,
    ledger: ClaimLedger,
    claim_outputs: tuple[dict[str, Any], ...],
    memory: WorkingMemory,
) -> None:
    known_refs = memory.evidence_ref_ids()
    known_ref_ids = set(known_refs)
    known_blocks = set(memory.block_ids())
    # Validate the full response before the ledger is mutated by any claim.
    for claim in claim_outputs:
        if (
            str(claim.get("behavior_class") or "").casefold() == "dual_use"
            and str(claim.get("claim_type") or "").casefold().endswith("uncertain")
        ):
            raise ValueError(
                "Contradictory claim semantics: behavior_class=dual_use conflicts with an "
                "uncertain claim_type. Clarify whether the cited operation is a supported "
                "dual-use observation (use its behavior claim_type and retain unknown "
                "contents, effects, and intent in uncertainty), or an unresolved risk "
                "finding (retain uncertain claim_type without asserting dual_use)"
            )
        evidence_ref_ids = tuple(str(ref) for ref in claim.get("evidence_ref_ids", ()))
        non_claimable_refs = sorted(
            ref
            for ref in evidence_ref_ids
            if not (ref.startswith("event:") or ref.startswith("block:"))
        )
        if non_claimable_refs:
            raise ValueError(
                "claim_output must cite only event:* or block:* evidence refs; "
                "use no_evidence with checked_fact_ids for observation ids"
            )
        unknown_refs = sorted(set(evidence_ref_ids) - known_ref_ids)
        if unknown_refs:
            raise ValueError(f"claim cites unknown evidence refs: {unknown_refs}")

    for claim in claim_outputs:
        evidence_ref_ids = tuple(str(ref) for ref in claim.get("evidence_ref_ids", ()))
        non_claimable_refs = sorted(
            ref
            for ref in evidence_ref_ids
            if not (ref.startswith("event:") or ref.startswith("block:"))
        )
        if non_claimable_refs:
            raise ValueError(
                "claim_output must cite only event:* or block:* evidence refs; "
                "use no_evidence with checked_fact_ids for observation ids"
            )
        requested_block_ids = tuple(str(block_id) for block_id in claim.get("supporting_block_ids", ()))
        unknown_blocks = sorted(set(requested_block_ids) - known_blocks)
        supporting_block_ids = tuple(block_id for block_id in requested_block_ids if block_id in known_blocks)
        uncertainty = [str(item) for item in claim.get("uncertainty", ())]
        if unknown_blocks:
            uncertainty.append("Ignored non-block supporting ids: " + ", ".join(unknown_blocks))
        supporting_rule_ids = deterministic_transition_rule_ids(
            agent_id,
            str(claim.get("claim_type") or "behavior_observation"),
            str(claim.get("confidence") or "medium"),
            evidence_ref_ids,
            memory,
        )
        ledger.add_candidate(
            agent_id=agent_id,
            claim_type=str(claim.get("claim_type") or "behavior_observation"),
            statement=str(claim.get("statement") or "").strip(),
            confidence=str(claim.get("confidence") or "medium"),
            evidence_ref_ids=evidence_ref_ids,
            supporting_block_ids=supporting_block_ids,
            alternative_explanations=tuple(str(item) for item in claim.get("alternative_explanations", ())),
            supporting_rule_ids=supporting_rule_ids,
            uncertainty=tuple(uncertainty),
            known_ref_ids=known_refs,
            behavior_class=str(claim.get("behavior_class") or ""),
            risk_primitives=tuple(str(item) for item in claim.get("risk_primitives", claim.get("risk_primitive", ())) or ()),
            dual_use_primitives=tuple(str(item) for item in claim.get("dual_use_primitives", claim.get("dual_use_primitive", ())) or ()),
        )


DETERMINISTIC_FILE_TRANSFORMATION_RULE_IDS = frozenset({
    DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE,
    DETERMINISTIC_DIRECT_USER_EXTENSION_TRANSITION_RULE,
    DETERMINISTIC_REPEATED_EXTENSION_TRANSFORMATION_RULE,
    DETERMINISTIC_REPEATED_EXTENSION_RENAME_TRANSFORMATION_RULE,
    DETERMINISTIC_RAW_FILESYSTEM_METADATA_WRITE_RULE,
})
DETERMINISTIC_RECOVERY_RULE_IDS = frozenset({
    DETERMINISTIC_EXECUTED_DESTRUCTIVE_RECOVERY_COMMAND_RULE,
})
DETERMINISTIC_PROCESS_EXECUTION_RULE_IDS = frozenset({
    DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE,
    DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE,
})
DETERMINISTIC_RANSOM_NOTE_RULE_IDS = frozenset({
    DETERMINISTIC_RANSOM_NOTE_ARTIFACT_RULE,
})
DETERMINISTIC_REGISTRY_RULE_IDS = frozenset({
    DETERMINISTIC_RUN_KEY_EXECUTABLE_BINDING_RULE,
})


def deterministic_transition_rule_ids(
    agent_id: str,
    claim_type: str,
    confidence: str,
    evidence_ref_ids: tuple[str, ...],
    memory: WorkingMemory,
) -> tuple[str, ...]:
    if agent_id == "file_transformation":
        eligible_rule_ids = DETERMINISTIC_FILE_TRANSFORMATION_RULE_IDS
        if claim_type != "file_transformation_behavior" or str(confidence).casefold() != "high":
            return ()
    elif agent_id == "recovery":
        eligible_rule_ids = DETERMINISTIC_RECOVERY_RULE_IDS
        if (
            claim_type != "recovery_impact_behavior"
            or str(confidence).casefold() not in {"medium", "high"}
        ):
            return ()
    elif agent_id == "process":
        eligible_rule_ids = DETERMINISTIC_PROCESS_EXECUTION_RULE_IDS
        if claim_type != "process_execution_behavior" or str(confidence).casefold() != "high":
            return ()
    elif agent_id == "ransom_note":
        eligible_rule_ids = DETERMINISTIC_RANSOM_NOTE_RULE_IDS
        if (
            claim_type not in {
                "ransom_note_deployment_behavior",
                "ransom_note_deployment_uncertain",
            }
            or str(confidence).casefold() not in {"medium", "high"}
        ):
            return ()
    elif agent_id == "registry":
        eligible_rule_ids = DETERMINISTIC_REGISTRY_RULE_IDS
        if (
            claim_type not in {"registry_behavior", "registry_uncertain"}
            or str(confidence).casefold() not in {"medium", "high"}
        ):
            return ()
    else:
        return ()
    cited_refs = set(evidence_ref_ids)
    for fact in memory.facts:
        for support in fact.deterministic_rule_supports:
            rule_id = str(support.get("rule_id") or "")
            if rule_id not in eligible_rule_ids:
                continue
            required_refs = {str(ref) for ref in support.get("evidence_ref_ids") or ()}
            if required_refs and required_refs.issubset(cited_refs):
                return (rule_id,)
    return ()


def unmet_deterministic_claim_contract(
    agent_id: str,
    claim_outputs: tuple[dict[str, Any], ...],
    memory: WorkingMemory,
) -> str | None:
    """Reject terminal actions that discard a verified policy boundary."""
    if agent_id == "recovery":
        supports = [
            support
            for fact in memory.facts
            for support in fact.deterministic_rule_supports
            if str(support.get("rule_id") or "") in DETERMINISTIC_RECOVERY_RULE_IDS
        ]
        if not supports:
            return None
        for claim in claim_outputs:
            if str(claim.get("claim_type") or "") != "recovery_impact_behavior":
                continue
            if str(claim.get("confidence") or "").casefold() not in {"medium", "high"}:
                continue
            cited_refs = {str(ref) for ref in claim.get("evidence_ref_ids") or ()}
            for support in supports:
                required_refs = {str(ref) for ref in support.get("evidence_ref_ids") or ()}
                if len(required_refs) >= 2 and required_refs.issubset(cited_refs):
                    return None
        required = sorted({
            ref
            for support in supports
            for ref in support.get("evidence_ref_ids") or ()
        })
        return (
            "A verified destructive recovery-command contract remains unsatisfied. "
            "Return recovery_impact_behavior with medium or high confidence and cite both representative "
            "event references; describe the external recovery effect as uncertain unless separately observed. "
            f"Available contract event references: {', '.join(required)}."
        )
    if agent_id == "process":
        supports = [
            support
            for fact in memory.facts
            for support in fact.deterministic_rule_supports
            if str(support.get("rule_id") or "") in DETERMINISTIC_PROCESS_EXECUTION_RULE_IDS
        ]
        if not supports:
            return None
        for claim in claim_outputs:
            if str(claim.get("claim_type") or "") != "process_execution_behavior":
                continue
            if str(claim.get("confidence") or "").casefold() != "high":
                continue
            cited_refs = {str(ref) for ref in claim.get("evidence_ref_ids") or ()}
            for support in supports:
                required_refs = {str(ref) for ref in support.get("evidence_ref_ids") or ()}
                if len(required_refs) >= 2 and required_refs.issubset(cited_refs):
                    return None
        required = sorted({
            ref
            for support in supports
            for ref in support.get("evidence_ref_ids") or ()
        })
        return (
            "A verified concealed encoded-script or elevated scheduled-task process-execution contract remains unsatisfied. "
            "Return process_execution_behavior with high confidence and cite every required event "
            "reference from one verified contract. Preserve the contract-specific scope: do not "
            "claim encryption, exfiltration, post-reboot execution, or ransomware impact unless separately supported. "
            f"Available contract event references: {', '.join(required)}."
        )

    if agent_id == "ransom_note":
        supports = [
            support
            for fact in memory.facts
            for support in fact.deterministic_rule_supports
            if str(support.get("rule_id") or "") in DETERMINISTIC_RANSOM_NOTE_RULE_IDS
        ]
        if not supports:
            return None
        for claim in claim_outputs:
            if str(claim.get("claim_type") or "") not in {
                "ransom_note_deployment_behavior",
                "ransom_note_deployment_uncertain",
            }:
                continue
            if str(claim.get("confidence") or "").casefold() not in {"medium", "high"}:
                continue
            cited_refs = {str(ref) for ref in claim.get("evidence_ref_ids") or ()}
            for support in supports:
                required_refs = {str(ref) for ref in support.get("evidence_ref_ids") or ()}
                if required_refs and required_refs.issubset(cited_refs):
                    return None
        required = sorted({
            ref
            for support in supports
            for ref in support.get("evidence_ref_ids") or ()
        })
        return (
            "A verified ransom-note-artifact contract remains unsatisfied. Return "
            "ransom_note_deployment_behavior or ransom_note_deployment_uncertain with medium or high "
            "confidence and cite the representative event reference; do not return no_evidence. "
            f"Available contract event references: {', '.join(required)}."
        )

    if agent_id == "registry":
        supports = [
            support
            for fact in memory.facts
            for support in fact.deterministic_rule_supports
            if str(support.get("rule_id") or "") in DETERMINISTIC_REGISTRY_RULE_IDS
        ]
        if not supports:
            return None
        for claim in claim_outputs:
            if str(claim.get("claim_type") or "") not in {"registry_behavior", "registry_uncertain"}:
                continue
            if str(claim.get("confidence") or "").casefold() not in {"medium", "high"}:
                continue
            cited_refs = {str(ref) for ref in claim.get("evidence_ref_ids") or ()}
            for support in supports:
                required_refs = {str(ref) for ref in support.get("evidence_ref_ids") or ()}
                if required_refs and required_refs.issubset(cited_refs):
                    return None
        required = sorted({
            ref
            for support in supports
            for ref in support.get("evidence_ref_ids") or ()
        })
        return (
            "A verified executable Run or RunOnce binding contract remains unsatisfied. Return "
            "registry_behavior or registry_uncertain with medium or high confidence and cite the "
            "representative event reference; do not return no_evidence. "
            f"Available contract event references: {', '.join(required)}."
        )

    if agent_id != "file_transformation":
        return None
    supports = [
        support
        for fact in memory.facts
        for support in fact.deterministic_rule_supports
        if str(support.get("rule_id") or "") in DETERMINISTIC_FILE_TRANSFORMATION_RULE_IDS
    ]
    if not supports:
        return None
    for claim in claim_outputs:
        if str(claim.get("claim_type") or "") != "file_transformation_behavior":
            continue
        if str(claim.get("confidence") or "").casefold() != "high":
            continue
        cited_refs = {str(ref) for ref in claim.get("evidence_ref_ids") or ()}
        for support in supports:
            required_refs = {str(ref) for ref in support.get("evidence_ref_ids") or ()}
            if required_refs and required_refs.issubset(cited_refs):
                return None
    required = sorted({
        ref
        for support in supports
        for ref in support.get("evidence_ref_ids") or ()
    })
    return (
        "A verified deterministic file-transformation contract remains unsatisfied. The contract may "
        "establish a broad extension transformation or a raw-filesystem metadata write. Return "
        "file_transformation_behavior with confidence high and cite every representative "
        "event reference from one contract; do not return no_evidence or a medium/low claim. "
        f"Available contract event references: {', '.join(required)}."
    )


def request_contract_correction(
    error: str,
    diagnostics: dict[str, Any],
    memory: WorkingMemory,
    loop_state: LoopState,
) -> bool:
    """Schedule a corrective model turn while the bounded loop has capacity."""
    diagnostics.setdefault("contract_violations", []).append(error)
    if loop_state.round_index + 1 >= loop_state.max_rounds:
        diagnostics["error"] = error
        return False
    memory.add_open_question(error)
    loop_state.next_round()
    return True

def request_response_format_correction(
    error: str,
    diagnostics: dict[str, Any],
    memory: WorkingMemory,
    loop_state: LoopState,
    *,
    retries_used: int,
    max_retries: int,
) -> bool:
    """Give malformed model output one bounded chance to satisfy the protocol."""
    diagnostics.setdefault("response_format_violations", []).append(error)
    if retries_used >= max_retries or loop_state.round_index + 1 >= loop_state.max_rounds:
        diagnostics["error"] = error
        return False
    memory.add_open_question(
        "The previous response violated the output protocol: "
        f"{error}. Return exactly one conformant JSON object; do not add prose or reinterpret evidence."
    )
    loop_state.next_round()
    diagnostics["response_format_retries"] = retries_used + 1
    return True

def no_evidence_completion(action: Any, memory: WorkingMemory) -> dict[str, Any]:
    visible_fact_ids = tuple(fact.fact_id for fact in memory.facts[-memory.max_facts:])
    visible_fact_id_set = set(visible_fact_ids)
    unknown = sorted(set(action.checked_fact_ids) - visible_fact_id_set)
    if unknown:
        allowed = ", ".join(visible_fact_ids) or "<none>"
        raise ValueError(
            "no_evidence.checked_fact_ids must be a subset of working_context.visible_fact_ids; "
            f"allowed fact ids: {allowed}; invalid fact ids: {', '.join(unknown)}"
        )
    return {
        "kind": "no_evidence",
        "checked_fact_ids": list(action.checked_fact_ids),
        "scope": str(action.scope or ""),
        "uncertainty": list(action.uncertainty),
    }


def _optional_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    return int(value)

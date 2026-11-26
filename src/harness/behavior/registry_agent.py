"""Deterministic registry evidence agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .context import ClaimLedger, LLMContext, LLMContextBuilder, LoopState, WorkingMemory
from .evidence import ToolResult
from .registry import EvidenceLedger, ToolRegistry

AGENT_ID = "registry"
REGISTRY_WRITE_KINDS = ("registry_modification",)
REGISTRY_READ_KINDS = ("registry_discovery",)
REGISTRY_SEQUENCE_PATTERNS = (
    ("registry_open", "registry_write"),
    ("registry_open", "registry_query"),
)


@dataclass(frozen=True)
class RegistryConfig:
    min_event_count: int = 1
    max_blocks: int = 5
    replay_block_count: int = 2
    representative_event_limit: int = 5
    include_neighbor_context: bool = True
    sequence_limit: int = 3


@dataclass(frozen=True)
class RegistryResult:
    status: str
    selected_block_ids: tuple[str, ...]
    context: LLMContext
    memory: WorkingMemory
    claim_ledger: ClaimLedger
    evidence_ledger: EvidenceLedger
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "selected_block_ids": list(self.selected_block_ids),
            "context": self.context.to_dict(),
            "memory": self.memory.to_context(),
            "claim_ledger": self.claim_ledger.to_context(),
            "evidence_ledger": self.evidence_ledger.to_dict(),
            "diagnostics": self.diagnostics,
        }


class RegistryAgent:
    """Evidence agent for registry query and write behavior."""

    agent_id = AGENT_ID

    def __init__(self, registry: ToolRegistry, config: RegistryConfig | None = None) -> None:
        self.registry = registry
        self.config = config or RegistryConfig()
        self.context_builder = LLMContextBuilder(registry)

    def analyze(self, task_prompt: str | None = None) -> RegistryResult:
        memory = WorkingMemory()
        claims = ClaimLedger()
        evidence_ledger = EvidenceLedger()
        loop_state = LoopState(agent_id=self.agent_id, remaining_tool_calls=self._tool_budget())

        write_blocks = self._list_kind(
            "registry_modification",
            evidence_ledger,
            memory,
            loop_state,
            purpose="find registry write macro blocks",
        )
        read_blocks = self._list_kind(
            "registry_discovery",
            evidence_ledger,
            memory,
            loop_state,
            purpose="find registry discovery macro blocks",
        )
        selected_blocks = prioritized_blocks(write_blocks.blocks, read_blocks.blocks, self.config.replay_block_count)
        selected_block_ids = tuple(block["block_id"] for block in selected_blocks)

        sequences: list[ToolResult] = []
        for pattern in REGISTRY_SEQUENCE_PATTERNS:
            sequences.append(
                self._call(
                    "find_behavior_sequence",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose="find registry operation sequence " + "->".join(pattern),
                    families=list(pattern),
                    limit=self.config.sequence_limit,
                )
            )

        if selected_blocks:
            for block_id in selected_block_ids:
                self._call(
                    "get_block_events",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"replay representative registry events for {block_id}",
                    block_id=block_id,
                    representative_only=True,
                    limit=self.config.representative_event_limit,
                )
            if self.config.include_neighbor_context and selected_block_ids:
                self._call(
                    "neighbor_blocks",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"inspect same-process context around {selected_block_ids[0]}",
                    block_id=selected_block_ids[0],
                    before=1,
                    after=1,
                )
            claims.add_candidate(
                agent_id=self.agent_id,
                claim_type="registry_behavior",
                statement=claim_statement(selected_blocks, sequences),
                confidence=claim_confidence(write_blocks, read_blocks, sequences),
                evidence_ref_ids=memory.evidence_ref_ids(),
                supporting_block_ids=selected_block_ids,
                alternative_explanations=BENIGN_ALTERNATIVES,
                uncertainty=uncertainties_from_memory(memory),
                known_ref_ids=memory.evidence_ref_ids(),
            )
            status = "supported"
        else:
            question = "No registry discovery or modification behavior block was returned from the retained behavior trace."
            memory.add_open_question(question)
            loop_state.add_unresolved_question(question)
            status = "unresolved"

        context = self.context_builder.build(self.agent_id, memory, loop_state, task_prompt, claims)
        return RegistryResult(
            status=status,
            selected_block_ids=selected_block_ids,
            context=context,
            memory=memory,
            claim_ledger=claims,
            evidence_ledger=evidence_ledger,
            diagnostics={
                "matched_registry_write_blocks": write_blocks.matched_count,
                "matched_registry_read_blocks": read_blocks.matched_count,
                "sequence_matches": sum(result.matched_count for result in sequences),
                "selected_block_count": len(selected_block_ids),
            },
        )

    def _list_kind(
        self,
        behavior_kind: str,
        evidence_ledger: EvidenceLedger,
        memory: WorkingMemory,
        loop_state: LoopState,
        purpose: str,
    ) -> ToolResult:
        return self._call(
            "list_blocks",
            evidence_ledger,
            memory,
            loop_state,
            purpose=purpose,
            behavior_kind=behavior_kind,
            min_event_count=self.config.min_event_count,
            level="macro",
            limit=self.config.max_blocks,
        )

    def _call(
        self,
        tool_name: str,
        evidence_ledger: EvidenceLedger,
        memory: WorkingMemory,
        loop_state: LoopState,
        purpose: str,
        **kwargs: Any,
    ) -> ToolResult:
        result = self.registry.call_for_agent(self.agent_id, tool_name, ledger=evidence_ledger, **kwargs)
        memory.record_observation(result, purpose=purpose)
        loop_state.record_tool_call(result)
        return result

    def _tool_budget(self) -> int:
        budget = 2 + len(REGISTRY_SEQUENCE_PATTERNS) + self.config.replay_block_count
        if self.config.include_neighbor_context:
            budget += 1
        return budget


BENIGN_ALTERNATIVES = (
    "installer registry setup or cleanup",
    "compatibility, locale, or environment checks",
    "ordinary application configuration reads or writes",
)


def prioritized_blocks(write_blocks: tuple[dict[str, Any], ...], read_blocks: tuple[dict[str, Any], ...], limit: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for block in list(write_blocks) + list(read_blocks):
        block_id = block.get("block_id")
        if block_id and all(item.get("block_id") != block_id for item in selected):
            selected.append(block)
            if len(selected) >= limit:
                break
    return selected


def claim_statement(blocks: list[dict[str, Any]], sequences: list[ToolResult]) -> str:
    write_count = sum(1 for block in blocks if block.get("behavior_kind") == "registry_modification")
    read_count = sum(1 for block in blocks if block.get("behavior_kind") == "registry_discovery")
    sequence_count = sum(result.matched_count for result in sequences)
    scopes = ", ".join(unique_values([str(block.get("target_scope") or "") for block in blocks])) or "unknown registry scope"
    return (
        f"sample-attributed behavior includes {write_count} registry modification block(s) "
        f"and {read_count} registry discovery block(s); {sequence_count} registry sequence(s) were observed over {scopes}"
    )


def claim_confidence(write_blocks: ToolResult, read_blocks: ToolResult, sequences: list[ToolResult]) -> str:
    sequence_count = sum(result.matched_count for result in sequences)
    if write_blocks.matched_count and sequence_count:
        return "high"
    if write_blocks.matched_count or read_blocks.matched_count:
        return "medium"
    return "low"


def uncertainties_from_memory(memory: WorkingMemory) -> tuple[str, ...]:
    limitations: list[str] = []
    for fact in memory.facts:
        for limitation in fact.limitations:
            if limitation not in limitations:
                limitations.append(limitation)
    if not limitations:
        limitations.append("claim identifies registry behavior in retained dynamic events; persistence or recovery semantics require target interpretation")
    return tuple(limitations)


def unique_values(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out

"""Deterministic file-transformation evidence agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .context import ClaimLedger, LLMContext, LLMContextBuilder, LoopState, WorkingMemory
from .evidence import ToolResult
from .registry import EvidenceLedger, ToolRegistry

AGENT_ID = "file_transformation"


@dataclass(frozen=True)
class FileTransformationConfig:
    min_event_count: int = 1
    max_blocks: int = 5
    replay_block_count: int = 2
    representative_event_limit: int = 5
    include_neighbor_context: bool = True


@dataclass(frozen=True)
class FileTransformationResult:
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


class FileTransformationAgent:
    """Evidence agent for sample-attributed file transformation behavior.

    This class is deliberately deterministic. It validates the harness data flow
    that a later LLM-backed agent will use: scoped tool calls, memory
    compression, evidence-bound claim creation, and prompt-context assembly.
    """

    agent_id = AGENT_ID

    def __init__(self, registry: ToolRegistry, config: FileTransformationConfig | None = None) -> None:
        self.registry = registry
        self.config = config or FileTransformationConfig()
        self.context_builder = LLMContextBuilder(registry)

    def analyze(self, task_prompt: str | None = None) -> FileTransformationResult:
        memory = WorkingMemory()
        claims = ClaimLedger()
        evidence_ledger = EvidenceLedger()
        loop_state = LoopState(agent_id=self.agent_id, remaining_tool_calls=self._tool_budget())

        transformation = self._call(
            "list_blocks",
            evidence_ledger,
            memory,
            loop_state,
            purpose="find file transformation macro blocks",
            behavior_kind="file_transformation",
            min_event_count=self.config.min_event_count,
            level="macro",
            limit=self.config.max_blocks,
        )
        blocks = list(transformation.blocks)
        selected_block_ids = tuple(block["block_id"] for block in blocks[: self.config.replay_block_count])

        if not blocks:
            self._call(
                "list_blocks",
                evidence_ledger,
                memory,
                loop_state,
                purpose="inspect file-related blocks after no transformation blocks were found",
                category="file",
                min_event_count=max(1, self.config.min_event_count),
                level="macro",
                limit=self.config.max_blocks,
            )
            question = "No file_transformation behavior block was returned; inspect whether file activity is only discovery or lifecycle noise."
            memory.add_open_question(question)
            loop_state.add_unresolved_question(question)
            status = "unresolved"
        else:
            for block_id in selected_block_ids:
                self._call(
                    "get_block_events",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"replay representative events for {block_id}",
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
                claim_type="file_transformation_behavior",
                statement=claim_statement(blocks),
                confidence=claim_confidence(blocks),
                evidence_ref_ids=memory.evidence_ref_ids(),
                supporting_block_ids=selected_block_ids,
                alternative_explanations=BENIGN_ALTERNATIVES,
                uncertainty=uncertainties_from_memory(memory),
                known_ref_ids=memory.evidence_ref_ids(),
            )
            status = "supported"

        context = self.context_builder.build(self.agent_id, memory, loop_state, task_prompt, claims)
        return FileTransformationResult(
            status=status,
            selected_block_ids=selected_block_ids,
            context=context,
            memory=memory,
            claim_ledger=claims,
            evidence_ledger=evidence_ledger,
            diagnostics={
                "matched_transformation_blocks": transformation.matched_count,
                "returned_transformation_blocks": transformation.returned_count,
                "selected_block_count": len(selected_block_ids),
            },
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
        budget = 1 + self.config.replay_block_count
        if self.config.include_neighbor_context:
            budget += 1
        budget += 1  # unresolved fallback inspection
        return budget


BENIGN_ALTERNATIVES = (
    "installer or updater writing application files",
    "archive extraction or backup synchronization",
    "document conversion or bulk user-file processing",
)


def claim_statement(blocks: list[dict[str, Any]]) -> str:
    total_events = sum(int(block.get("event_count") or 0) for block in blocks)
    top = blocks[0]
    families = ", ".join(top.get("operation_families", [])) or "unknown operations"
    scope = top.get("target_scope") or "unknown target scope"
    return (
        f"sample-attributed behavior includes {len(blocks)} file-transformation macro block(s) "
        f"covering {total_events} event(s); the leading block uses {families} over {scope}"
    )


def claim_confidence(blocks: list[dict[str, Any]]) -> str:
    total_events = sum(int(block.get("event_count") or 0) for block in blocks)
    if len(blocks) >= 3 and total_events >= 10:
        return "high"
    if total_events >= 2:
        return "medium"
    return "low"


def uncertainties_from_memory(memory: WorkingMemory) -> tuple[str, ...]:
    limitations: list[str] = []
    for fact in memory.facts:
        for limitation in fact.limitations:
            if limitation not in limitations:
                limitations.append(limitation)
    if not limitations:
        limitations.append("claim is based on retained dynamic events and representative block replay, not full semantic encryption proof")
    return tuple(limitations)

"""Deterministic evidence auditor for evidence-bound behavior claims."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .context import Claim, ClaimLedger, LLMContext, LLMContextBuilder, LoopState, WorkingMemory
from .evidence import ToolResult
from .registry import EvidenceLedger, ToolRegistry

AGENT_ID = "evidence_auditor"


@dataclass(frozen=True)
class EvidenceAuditorConfig:
    representative_event_limit: int = 5
    neighbor_context: bool = True
    neighbor_before: int = 1
    neighbor_after: int = 1


@dataclass(frozen=True)
class ClaimReview:
    claim_id: str
    status: str
    notes: tuple[str, ...]
    checked_evidence_refs: tuple[str, ...]
    checked_block_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "status": self.status,
            "notes": list(self.notes),
            "checked_evidence_refs": list(self.checked_evidence_refs),
            "checked_block_ids": list(self.checked_block_ids),
        }


@dataclass(frozen=True)
class EvidenceAuditorResult:
    audited_claim_ledger: ClaimLedger
    reviews: tuple[ClaimReview, ...]
    context: LLMContext
    memory: WorkingMemory
    evidence_ledger: EvidenceLedger
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "audited_claim_ledger": self.audited_claim_ledger.to_context(),
            "reviews": [review.to_dict() for review in self.reviews],
            "context": self.context.to_dict(),
            "memory": self.memory.to_context(),
            "evidence_ledger": self.evidence_ledger.to_dict(),
            "diagnostics": self.diagnostics,
        }


class EvidenceAuditorAgent:
    """Audits candidate claims without broad evidence discovery."""

    agent_id = AGENT_ID

    def __init__(self, registry: ToolRegistry, config: EvidenceAuditorConfig | None = None) -> None:
        self.registry = registry
        self.config = config or EvidenceAuditorConfig()
        self.context_builder = LLMContextBuilder(registry)

    def audit(self, claim_ledger: ClaimLedger, task_prompt: str | None = None) -> EvidenceAuditorResult:
        memory = WorkingMemory()
        reviewed = ClaimLedger()
        evidence_ledger = EvidenceLedger()
        claims = list(claim_ledger.claims.values())
        loop_state = LoopState(agent_id=self.agent_id, remaining_tool_calls=self._tool_budget(claims))
        reviews: list[ClaimReview] = []

        for claim in claims:
            review = self._review_claim(claim, memory, evidence_ledger, loop_state)
            reviewed.claims[claim.claim_id] = claim.with_status(review.status, review.notes)
            reviews.append(review)

        context = self.context_builder.build(self.agent_id, memory, loop_state, task_prompt, reviewed)
        return EvidenceAuditorResult(
            audited_claim_ledger=reviewed,
            reviews=tuple(reviews),
            context=context,
            memory=memory,
            evidence_ledger=evidence_ledger,
            diagnostics={
                "claim_count": len(claims),
                "accepted_count": sum(1 for review in reviews if review.status == "accepted"),
                "revised_count": sum(1 for review in reviews if review.status == "revised"),
                "rejected_count": sum(1 for review in reviews if review.status == "rejected"),
            },
        )

    def _review_claim(
        self,
        claim: Claim,
        memory: WorkingMemory,
        evidence_ledger: EvidenceLedger,
        loop_state: LoopState,
    ) -> ClaimReview:
        notes: list[str] = []
        checked_refs: list[str] = []
        checked_blocks: list[str] = []
        cited_refs = set(claim.evidence_ref_ids)
        event_refs, block_refs, malformed_refs = split_evidence_refs(claim.evidence_ref_ids)
        notes.extend(f"malformed evidence ref: {ref}" for ref in malformed_refs)

        for offset, ref_id in event_refs:
            result = self._safe_call("get_event", evidence_ledger, memory, loop_state, f"verify {ref_id}", offset=offset)
            if result is None or result.returned_count != 1:
                notes.append(f"unresolved event evidence ref: {ref_id}")
            else:
                checked_refs.append(ref_id)

        for block_id, ref_id in block_refs:
            result = self._safe_call("get_block", evidence_ledger, memory, loop_state, f"verify {ref_id}", block_id=block_id)
            if result is None or result.returned_count != 1:
                notes.append(f"unresolved block evidence ref: {ref_id}")
            else:
                checked_refs.append(ref_id)
                checked_blocks.append(block_id)

        if not claim.supporting_block_ids:
            notes.append("claim has no supporting block ids; revise to event-level evidence only")
            return ClaimReview(
                claim_id=claim.claim_id,
                status="revised" if checked_refs and not malformed_refs else "rejected",
                notes=tuple(notes),
                checked_evidence_refs=tuple(unique_values(checked_refs)),
                checked_block_ids=tuple(unique_values(checked_blocks)),
            )

        aligned_blocks: list[str] = []
        for block_id in claim.supporting_block_ids:
            block_result = self._safe_call("get_block", evidence_ledger, memory, loop_state, f"verify supporting block {block_id}", block_id=block_id)
            if block_result is None or block_result.returned_count != 1 or not block_result.blocks:
                notes.append(f"supporting block could not be resolved: {block_id}")
                continue
            checked_blocks.append(block_id)
            replay = self._safe_call(
                "get_block_events",
                evidence_ledger,
                memory,
                loop_state,
                f"replay representatives for {block_id}",
                block_id=block_id,
                representative_only=True,
                limit=self.config.representative_event_limit,
            )
            if replay is None or replay.returned_count == 0:
                notes.append(f"supporting block has no replayable representative events: {block_id}")
                continue
            if self.config.neighbor_context:
                self._safe_call(
                    "neighbor_blocks",
                    evidence_ledger,
                    memory,
                    loop_state,
                    f"inspect same-process neighbor context for {block_id}",
                    block_id=block_id,
                    before=self.config.neighbor_before,
                    after=self.config.neighbor_after,
                )
            if block_aligns_with_refs(block_id, block_result, replay, cited_refs):
                aligned_blocks.append(block_id)
            else:
                notes.append(f"supporting block is not aligned with cited evidence refs: {block_id}")

        if malformed_refs or any(note.startswith("unresolved") or "could not be resolved" in note or "no replayable" in note for note in notes):
            status = "rejected"
        elif aligned_blocks and len(aligned_blocks) == len(tuple(unique_values(claim.supporting_block_ids))):
            status = "accepted"
            if not notes:
                notes.append("all cited evidence refs and supporting blocks were replayable and aligned")
        elif aligned_blocks:
            status = "revised"
            notes.append("only a subset of supporting blocks aligned with cited evidence")
        else:
            status = "rejected"
            notes.append("no supporting block aligned with cited evidence")

        return ClaimReview(
            claim_id=claim.claim_id,
            status=status,
            notes=tuple(unique_values(notes)),
            checked_evidence_refs=tuple(unique_values(checked_refs)),
            checked_block_ids=tuple(unique_values(checked_blocks)),
        )

    def _safe_call(
        self,
        tool_name: str,
        evidence_ledger: EvidenceLedger,
        memory: WorkingMemory,
        loop_state: LoopState,
        purpose: str,
        **kwargs: Any,
    ) -> ToolResult | None:
        try:
            result = self.registry.call_for_agent(self.agent_id, tool_name, ledger=evidence_ledger, **kwargs)
        except (KeyError, IndexError, ValueError):
            return None
        memory.record_observation(result, purpose=purpose)
        loop_state.record_tool_call(result)
        return result

    def _tool_budget(self, claims: list[Claim]) -> int:
        budget = 0
        for claim in claims:
            budget += len(claim.evidence_ref_ids)
            budget += len(claim.supporting_block_ids) * (2 + int(self.config.neighbor_context))
        return max(1, budget)


EvidenceEventRef = tuple[int, str]
EvidenceBlockRef = tuple[str, str]


def split_evidence_refs(refs: tuple[str, ...]) -> tuple[list[EvidenceEventRef], list[EvidenceBlockRef], list[str]]:
    events: list[EvidenceEventRef] = []
    blocks: list[EvidenceBlockRef] = []
    malformed: list[str] = []
    for ref in refs:
        if ref.startswith("event:"):
            try:
                events.append((int(ref.split(":", 1)[1]), ref))
            except ValueError:
                malformed.append(ref)
        elif ref.startswith("block:"):
            block_id = ref.split(":", 1)[1]
            if block_id:
                blocks.append((block_id, ref))
            else:
                malformed.append(ref)
        else:
            malformed.append(ref)
    return events, blocks, malformed


def block_aligns_with_refs(block_id: str, block_result: ToolResult, replay: ToolResult, cited_refs: set[str]) -> bool:
    if f"block:{block_id}" in cited_refs:
        return True
    for ref in replay.evidence_refs:
        if ref.ref_id in cited_refs:
            return True
    for block in block_result.blocks:
        for offset in block.get("representative_offsets", []):
            if f"event:{offset}" in cited_refs:
                return True
    return False


def unique_values(values: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out


"""Deterministic recovery-impact evidence agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .context import ClaimLedger, LLMContext, LLMContextBuilder, LoopState, WorkingMemory
from .evidence import ToolResult
from .registry import EvidenceLedger, ToolRegistry

AGENT_ID = "recovery"

RECOVERY_PROCESS_KEYS = (
    "vssadmin.exe",
    "wbadmin.exe",
    "bcdedit.exe",
    "wmic.exe",
    "powershell.exe",
    "cmd.exe",
)

RECOVERY_TARGET_KEYS = (
    "shadowcopy",
    "shadow copy",
    "safeboot",
    "bcd",
    "backup",
    "system volume information",
    "wbengine",
    "windows\\system32\\config",
)

RECOVERY_SEQUENCE_FAMILIES = ("process_start", "registry_write")


@dataclass(frozen=True)
class RecoveryImpactConfig:
    max_events_per_key: int = 5
    max_targets: int = 5
    window_before: int = 2
    window_after: int = 3
    sequence_limit: int = 3


@dataclass(frozen=True)
class RecoveryImpactResult:
    status: str
    selected_event_offsets: tuple[int, ...]
    context: LLMContext
    memory: WorkingMemory
    claim_ledger: ClaimLedger
    evidence_ledger: EvidenceLedger
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "selected_event_offsets": list(self.selected_event_offsets),
            "context": self.context.to_dict(),
            "memory": self.memory.to_context(),
            "claim_ledger": self.claim_ledger.to_context(),
            "evidence_ledger": self.evidence_ledger.to_dict(),
            "diagnostics": self.diagnostics,
        }


class RecoveryImpactAgent:
    """Evidence agent for backup, recovery, shadow-copy, and boot-impact surfaces."""

    agent_id = AGENT_ID

    def __init__(self, registry: ToolRegistry, config: RecoveryImpactConfig | None = None) -> None:
        self.registry = registry
        self.config = config or RecoveryImpactConfig()
        self.context_builder = LLMContextBuilder(registry)

    def analyze(self, task_prompt: str | None = None) -> RecoveryImpactResult:
        memory = WorkingMemory()
        claims = ClaimLedger()
        evidence_ledger = EvidenceLedger()
        loop_state = LoopState(agent_id=self.agent_id, remaining_tool_calls=self._tool_budget())

        process_hits: list[ToolResult] = []
        for key in RECOVERY_PROCESS_KEYS:
            result = self._call(
                "list_events",
                evidence_ledger,
                memory,
                loop_state,
                purpose=f"search recovery-related process name {key}",
                index_name="process_name_index",
                key=key,
                limit=self.config.max_events_per_key,
            )
            if result.returned_count:
                process_hits.append(result)

        target_hits: list[ToolResult] = []
        for target in RECOVERY_TARGET_KEYS[: self.config.max_targets]:
            result = self._call(
                "trace_target",
                evidence_ledger,
                memory,
                loop_state,
                purpose=f"search recovery-related target {target}",
                target=target,
                prefix=True,
                limit=self.config.max_events_per_key,
            )
            if result.returned_count:
                target_hits.append(result)

        sequence = self._call(
            "find_behavior_sequence",
            evidence_ledger,
            memory,
            loop_state,
            purpose="search process-to-registry recovery impact sequence",
            families=list(RECOVERY_SEQUENCE_FAMILIES),
            limit=self.config.sequence_limit,
        )

        selected_offsets = tuple(first_offsets(process_hits + target_hits, limit=3))
        if selected_offsets:
            for offset in selected_offsets[:2]:
                self._call(
                    "get_window_around_event",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"inspect local context around recovery evidence event:{offset}",
                    offset=offset,
                    before=self.config.window_before,
                    after=self.config.window_after,
                )
            claims.add_candidate(
                agent_id=self.agent_id,
                claim_type="recovery_impact_behavior",
                statement=claim_statement(process_hits, target_hits, sequence),
                confidence=claim_confidence(process_hits, target_hits, sequence),
                evidence_ref_ids=memory.evidence_ref_ids(),
                supporting_block_ids=memory.block_ids(),
                alternative_explanations=BENIGN_ALTERNATIVES,
                uncertainty=uncertainties_from_memory(memory),
                known_ref_ids=memory.evidence_ref_ids(),
            )
            status = "supported"
        else:
            question = "No recovery-related process, target, or process-to-registry sequence was observed in the retained behavior trace."
            memory.add_open_question(question)
            loop_state.add_unresolved_question(question)
            status = "unresolved"

        context = self.context_builder.build(self.agent_id, memory, loop_state, task_prompt, claims)
        return RecoveryImpactResult(
            status=status,
            selected_event_offsets=selected_offsets,
            context=context,
            memory=memory,
            claim_ledger=claims,
            evidence_ledger=evidence_ledger,
            diagnostics={
                "process_hit_keys": hit_keys(process_hits),
                "target_hit_queries": hit_targets(target_hits),
                "sequence_matches": sequence.matched_count,
                "selected_event_count": len(selected_offsets),
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
        return len(RECOVERY_PROCESS_KEYS) + min(len(RECOVERY_TARGET_KEYS), self.config.max_targets) + 1 + 2


BENIGN_ALTERNATIVES = (
    "administrator or maintenance tool inspecting backup or boot configuration",
    "installer or updater invoking service or boot configuration helpers",
    "failed recovery-surface probe without modification effect",
)


def first_offsets(results: list[ToolResult], limit: int) -> list[int]:
    offsets: list[int] = []
    for result in results:
        for ref in result.evidence_refs:
            if ref.offset is not None and ref.offset not in offsets:
                offsets.append(ref.offset)
                if len(offsets) >= limit:
                    return offsets
    return offsets


def claim_statement(process_hits: list[ToolResult], target_hits: list[ToolResult], sequence: ToolResult) -> str:
    process_keys = hit_keys(process_hits)
    target_keys = hit_targets(target_hits)
    parts = []
    if process_keys:
        parts.append("recovery-related process evidence for " + ", ".join(process_keys))
    if target_keys:
        parts.append("recovery-related target evidence for " + ", ".join(target_keys))
    if sequence.matched_count:
        parts.append(f"{sequence.matched_count} process-to-registry sequence(s)")
    return "sample-attributed behavior includes " + "; ".join(parts)


def claim_confidence(process_hits: list[ToolResult], target_hits: list[ToolResult], sequence: ToolResult) -> str:
    evidence_classes = int(bool(process_hits)) + int(bool(target_hits)) + int(sequence.matched_count)
    total_events = sum(result.returned_count for result in process_hits + target_hits)
    if evidence_classes >= 2 and total_events >= 2:
        return "high"
    if total_events >= 1 or sequence.matched_count:
        return "medium"
    return "low"


def hit_keys(results: list[ToolResult]) -> tuple[str, ...]:
    values = []
    for result in results:
        key = str(result.query.get("key") or "")
        if key and key not in values:
            values.append(key)
    return tuple(values)


def hit_targets(results: list[ToolResult]) -> tuple[str, ...]:
    values = []
    for result in results:
        target = str(result.query.get("target") or "")
        if target and target not in values:
            values.append(target)
    return tuple(values)


def uncertainties_from_memory(memory: WorkingMemory) -> tuple[str, ...]:
    limitations: list[str] = []
    for fact in memory.facts:
        for limitation in fact.limitations:
            if limitation not in limitations:
                limitations.append(limitation)
    if not limitations:
        limitations.append("claim identifies recovery-impact surfaces in retained dynamic events; command semantics may require raw detail or static context")
    return tuple(limitations)

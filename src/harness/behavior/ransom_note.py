"""Deterministic ransom-note deployment evidence agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .context import ClaimLedger, LLMContext, LLMContextBuilder, LoopState, WorkingMemory
from .evidence import ToolResult
from .registry import EvidenceLedger, ToolRegistry

AGENT_ID = "ransom_note"
DEFAULT_NOTE_PATTERNS = (
    "restore_my_files",
    "how_to_decrypt",
    "decrypt",
    "recover files",
    "ransom",
)


@dataclass(frozen=True)
class RansomNoteConfig:
    patterns: tuple[str, ...] = DEFAULT_NOTE_PATTERNS
    search_limit: int = 80
    max_pages_per_pattern: int = 3
    min_successful_writes: int = 1


@dataclass(frozen=True)
class RansomNoteResult:
    status: str
    context: LLMContext
    memory: WorkingMemory
    claim_ledger: ClaimLedger
    evidence_ledger: EvidenceLedger
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "context": self.context.to_dict(),
            "memory": self.memory.to_context(),
            "claim_ledger": self.claim_ledger.to_context(),
            "evidence_ledger": self.evidence_ledger.to_dict(),
            "diagnostics": self.diagnostics,
        }


class RansomNoteAgent:
    """Evidence agent for sample-attributed ransom-note deployment."""

    agent_id = AGENT_ID

    def __init__(self, registry: ToolRegistry, config: RansomNoteConfig | None = None) -> None:
        self.registry = registry
        self.config = config or RansomNoteConfig()
        self.context_builder = LLMContextBuilder(registry)

    def analyze(self, task_prompt: str | None = None) -> RansomNoteResult:
        memory = WorkingMemory()
        claims = ClaimLedger()
        evidence_ledger = EvidenceLedger()
        loop_state = LoopState(
            agent_id=self.agent_id,
            remaining_tool_calls=len(self.config.patterns) * self.config.max_pages_per_pattern,
        )

        matched_events: list[dict[str, Any]] = []
        for pattern in self.config.patterns:
            cursor: str | None = None
            for page_index in range(self.config.max_pages_per_pattern):
                result = self._call(
                    "search_events",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"search for ransom-note indicator {pattern} page {page_index + 1}",
                    patterns=[pattern],
                    fields=["target", "detail", "process"],
                    limit=self.config.search_limit,
                    cursor=cursor,
                )
                matched_events.extend(result.events)
                cursor = result.cursor
                if cursor is None:
                    break
            if successful_note_writes(matched_events):
                break

        writes = successful_note_writes(matched_events)
        creates = successful_note_creates(matched_events)
        note_paths = unique_values(event_path(event) for event in writes or creates)
        selected_events = writes or creates
        selected_refs = tuple(
            ref_id for ref_id in event_ref_ids(selected_events)
            if ref_id in set(memory.evidence_ref_ids())
        )

        if len(writes) >= self.config.min_successful_writes and selected_refs:
            claims.add_candidate(
                agent_id=self.agent_id,
                claim_type="ransom_note_deployment_behavior",
                statement=claim_statement(writes, creates),
                confidence=claim_confidence(writes, note_paths),
                evidence_ref_ids=selected_refs,
                supporting_block_ids=(),
                alternative_explanations=BENIGN_ALTERNATIVES,
                uncertainty=uncertainties_from_memory(memory),
                known_ref_ids=memory.evidence_ref_ids(),
            )
            status = "supported"
        else:
            question = "No successful ransom-note write was observed in retained dynamic events."
            if creates:
                question = "Potential ransom-note paths were created or opened, but no successful write was observed."
            memory.add_open_question(question)
            loop_state.add_unresolved_question(question)
            status = "unresolved"

        context = self.context_builder.build(self.agent_id, memory, loop_state, task_prompt, claims)
        return RansomNoteResult(
            status=status,
            context=context,
            memory=memory,
            claim_ledger=claims,
            evidence_ledger=evidence_ledger,
            diagnostics={
                "returned_note_events": len(matched_events),
                "successful_create_events": len(creates),
                "successful_write_events": len(writes),
                "unique_note_paths": len(note_paths),
                "note_path_examples": note_paths[:10],
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


BENIGN_ALTERNATIVES = (
    "installer or updater writing user-facing documentation",
    "benign application creating recovery or instruction text files",
    "test harness or analyst fixture using ransom-note-like filenames",
)


def successful_note_writes(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event for event in events
        if is_note_event(event)
        and operation(event) == "writefile"
        and result(event) == "success"
    ]


def successful_note_creates(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event for event in events
        if is_note_event(event)
        and operation(event) == "createfile"
        and result(event) == "success"
    ]


def is_note_event(event: dict[str, Any]) -> bool:
    text = f"{event_path(event)} {event_detail(event)}".casefold()
    indicators = (
        "restore_my_files",
        "how_to_decrypt",
        "decrypt",
        "recover files",
        "ransom",
    )
    return any(indicator in text for indicator in indicators)


def event_ref_ids(events: list[dict[str, Any]]) -> list[str]:
    refs = []
    for event in events:
        filtered = event.get("order", {}).get("filtered")
        if isinstance(filtered, int):
            refs.append(f"event:{filtered}")
    return refs


def event_path(event: dict[str, Any]) -> str:
    target = event.get("target", {})
    return str(target.get("path") or target.get("normalized_path") or "")


def event_detail(event: dict[str, Any]) -> str:
    return str(event.get("detail", {}).get("raw_detail") or "")


def operation(event: dict[str, Any]) -> str:
    return str(event.get("action", {}).get("operation") or "").casefold()


def result(event: dict[str, Any]) -> str:
    return str(event.get("action", {}).get("result") or "").casefold()


def process_names(events: list[dict[str, Any]]) -> list[str]:
    return unique_values(str(event.get("process_context", {}).get("process_name") or "") for event in events)


def claim_statement(writes: list[dict[str, Any]], creates: list[dict[str, Any]]) -> str:
    paths = unique_values(event_path(event) for event in writes)
    actors = process_names(writes)
    examples = "; ".join(paths[:5]) or "unknown note target"
    actor_text = ", ".join(actors[:3]) or "unknown process"
    return (
        f"sample-attributed behavior wrote ransom-note-like files to {len(paths)} unique path(s); "
        f"representative actor process(es): {actor_text}; representative target(s): {examples}"
    )


def claim_confidence(writes: list[dict[str, Any]], paths: list[str]) -> str:
    if len(writes) >= 5 and len(paths) >= 3:
        return "high"
    if writes:
        return "medium"
    return "low"


def uncertainties_from_memory(memory: WorkingMemory) -> tuple[str, ...]:
    limitations: list[str] = []
    for fact in memory.facts:
        for limitation in fact.limitations:
            if limitation not in limitations:
                limitations.append(limitation)
    limitations.append("dynamic file events show note creation/writes, but not the full note text")
    return tuple(limitations)


def unique_values(values: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out

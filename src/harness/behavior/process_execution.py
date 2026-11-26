"""Deterministic process-execution evidence agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from typing import Any

from .context import ClaimLedger, LLMContext, LLMContextBuilder, LoopState, WorkingMemory
from .evidence import ToolResult
from .registry import EvidenceLedger, ToolRegistry

AGENT_ID = "process"
PROCESS_SEQUENCE_FAMILIES = ("process_start",)
INTERPRETER_OR_TOOL_NAMES = {
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "vssadmin.exe",
    "bcdedit.exe",
    "wbadmin.exe",
}


@dataclass(frozen=True)
class ProcessExecutionConfig:
    process_summary_limit: int = 8
    sequence_limit: int = 5
    representative_event_limit: int = 3
    window_before: int = 2
    window_after: int = 3
    trace_process_limit: int = 5


@dataclass(frozen=True)
class ProcessExecutionResult:
    status: str
    selected_event_offsets: tuple[int, ...]
    selected_block_ids: tuple[str, ...]
    context: LLMContext
    memory: WorkingMemory
    claim_ledger: ClaimLedger
    evidence_ledger: EvidenceLedger
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "selected_event_offsets": list(self.selected_event_offsets),
            "selected_block_ids": list(self.selected_block_ids),
            "context": self.context.to_dict(),
            "memory": self.memory.to_context(),
            "claim_ledger": self.claim_ledger.to_context(),
            "evidence_ledger": self.evidence_ledger.to_dict(),
            "diagnostics": self.diagnostics,
        }


class ProcessExecutionAgent:
    """Evidence agent for process-local execution and helper-process activity."""

    agent_id = AGENT_ID

    def __init__(self, registry: ToolRegistry, config: ProcessExecutionConfig | None = None) -> None:
        self.registry = registry
        self.config = config or ProcessExecutionConfig()
        self.context_builder = LLMContextBuilder(registry)

    def analyze(self, task_prompt: str | None = None) -> ProcessExecutionResult:
        memory = WorkingMemory()
        claims = ClaimLedger()
        evidence_ledger = EvidenceLedger()
        loop_state = LoopState(agent_id=self.agent_id, remaining_tool_calls=self._tool_budget())

        summary = self._call(
            "summarize_processes",
            evidence_ledger,
            memory,
            loop_state,
            purpose="inspect process names with representative offsets",
            limit=self.config.process_summary_limit,
        )
        sequence = self._call(
            "find_behavior_sequence",
            evidence_ledger,
            memory,
            loop_state,
            purpose="find process-start evidence sequences",
            families=list(PROCESS_SEQUENCE_FAMILIES),
            limit=self.config.sequence_limit,
        )

        selected_offsets = tuple(sequence_event_offsets(sequence, self.config.representative_event_limit))
        selected_block_ids = tuple(sequence_block_ids(sequence, self.config.sequence_limit))
        inspected_events: list[dict[str, Any]] = []
        actor_processes: list[str] = []
        target_processes: list[str] = []

        if selected_offsets:
            for offset in selected_offsets:
                event_result = self._call(
                    "get_event",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"inspect process execution event:{offset}",
                    offset=offset,
                )
                inspected_events.extend(event_result.events)
                actor_processes.extend(process_names_from_events(event_result.events))
                target_processes.extend(target_names_from_events(event_result.events))
                self._call(
                    "get_window_around_event",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"inspect local context around process execution event:{offset}",
                    offset=offset,
                    before=self.config.window_before,
                    after=self.config.window_after,
                )
            for process_name in unique_values(actor_processes)[:2]:
                self._call(
                    "trace_process",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"trace same-process behavior for {process_name}",
                    process_name=process_name,
                    limit=self.config.trace_process_limit,
                )
            claims.add_candidate(
                agent_id=self.agent_id,
                claim_type="process_execution_behavior",
                statement=claim_statement(sequence, actor_processes, target_processes),
                confidence=claim_confidence(sequence, target_processes),
                evidence_ref_ids=memory.evidence_ref_ids(),
                supporting_block_ids=selected_block_ids,
                alternative_explanations=BENIGN_ALTERNATIVES,
                uncertainty=uncertainties_from_memory(memory),
                known_ref_ids=memory.evidence_ref_ids(),
            )
            status = "supported"
        else:
            question = "No process_start behavior sequence was observed in the retained behavior trace."
            memory.add_open_question(question)
            loop_state.add_unresolved_question(question)
            status = "unresolved"

        context = self.context_builder.build(self.agent_id, memory, loop_state, task_prompt, claims)
        return ProcessExecutionResult(
            status=status,
            selected_event_offsets=selected_offsets,
            selected_block_ids=selected_block_ids,
            context=context,
            memory=memory,
            claim_ledger=claims,
            evidence_ledger=evidence_ledger,
            diagnostics={
                "process_summary_items": summary.returned_count,
                "sequence_matches": sequence.matched_count,
                "actor_processes": unique_values(actor_processes),
                "target_processes": unique_values(target_processes),
                "inspected_event_count": len(inspected_events),
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
        return 2 + self.config.representative_event_limit * 2 + 2


BENIGN_ALTERNATIVES = (
    "installer or updater launching helper processes",
    "runtime dependency or child process used by legitimate software",
    "administrative or user-initiated tool execution visible in the same retained trace",
)


def sequence_event_offsets(sequence: ToolResult, limit: int) -> list[int]:
    offsets: list[int] = []
    for row in sequence.aggregates.get("sequences", []):
        for offset in row.get("representative_offsets", []):
            if offset not in offsets:
                offsets.append(int(offset))
                if len(offsets) >= limit:
                    return offsets
    return offsets


def sequence_block_ids(sequence: ToolResult, limit: int) -> list[str]:
    block_ids: list[str] = []
    for row in sequence.aggregates.get("sequences", []):
        for block_id in row.get("block_ids", []):
            if block_id not in block_ids:
                block_ids.append(str(block_id))
                if len(block_ids) >= limit:
                    return block_ids
    return block_ids


def process_names_from_events(events: tuple[dict[str, Any], ...]) -> list[str]:
    names: list[str] = []
    for event in events:
        name = str(event.get("process_context", {}).get("process_name") or "")
        if name:
            names.append(name)
    return names


def target_names_from_events(events: tuple[dict[str, Any], ...]) -> list[str]:
    names: list[str] = []
    for event in events:
        path = str(event.get("target", {}).get("normalized_path") or event.get("target", {}).get("path") or "")
        name = basename(path)
        if name:
            names.append(name)
    return names


def basename(path: str) -> str:
    if not path:
        return ""
    try:
        return PureWindowsPath(path).name.casefold()
    except Exception:
        return path.rsplit("\\", 1)[-1].casefold()


def claim_statement(sequence: ToolResult, actor_processes: list[str], target_processes: list[str]) -> str:
    actors = ", ".join(unique_values(actor_processes)) or "unknown actor process"
    targets = ", ".join(unique_values(target_processes)) or "unknown target process"
    return (
        f"sample-attributed behavior includes {sequence.matched_count} process-start sequence(s); "
        f"representative actor process(es): {actors}; representative target process(es): {targets}"
    )


def claim_confidence(sequence: ToolResult, target_processes: list[str]) -> str:
    target_set = set(unique_values(target_processes))
    if sequence.matched_count >= 2 or target_set.intersection(INTERPRETER_OR_TOOL_NAMES):
        return "high"
    if sequence.matched_count >= 1:
        return "medium"
    return "low"


def uncertainties_from_memory(memory: WorkingMemory) -> tuple[str, ...]:
    limitations: list[str] = []
    for fact in memory.facts:
        for limitation in fact.limitations:
            if limitation not in limitations:
                limitations.append(limitation)
    if not limitations:
        limitations.append("claim identifies process-start behavior in retained dynamic events; command-line semantics may require parsed detail or static context")
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

"""Deterministic dynamic anti-analysis evidence agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .context import ClaimLedger, LLMContext, LLMContextBuilder, LoopState, WorkingMemory
from .evidence import ToolResult
from .registry import EvidenceLedger, ToolRegistry

AGENT_ID = "anti_analysis"

PROBE_OPERATION_KEYS = (
    "Process Profiling",
    "RegQueryValue",
    "QueryInformationFile",
    "QueryOpen",
)

PROBE_PROCESS_KEYS = (
    "procmon.exe",
    "procexp.exe",
    "wireshark.exe",
    "fiddler.exe",
    "vboxservice.exe",
    "vmtoolsd.exe",
    "ollydbg.exe",
    "x64dbg.exe",
)

PROBE_TERMS = (
    "debug",
    "sandbox",
    "virtualbox",
    "vmware",
    "vbox",
    "qemu",
    "wireshark",
    "procmon",
    "procexp",
    "x64dbg",
    "ollydbg",
)


@dataclass(frozen=True)
class DynamicAntiAnalysisConfig:
    summary_limit: int = 8
    max_events_per_key: int = 5
    max_probe_events: int = 3
    window_before: int = 2
    window_after: int = 3
    trace_process_limit: int = 5


@dataclass(frozen=True)
class DynamicAntiAnalysisResult:
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


class DynamicAntiAnalysisAgent:
    """Evidence agent for environment, debugger, sandbox, and monitor probes."""

    agent_id = AGENT_ID

    def __init__(self, registry: ToolRegistry, config: DynamicAntiAnalysisConfig | None = None) -> None:
        self.registry = registry
        self.config = config or DynamicAntiAnalysisConfig()
        self.context_builder = LLMContextBuilder(registry)

    def analyze(self, task_prompt: str | None = None) -> DynamicAntiAnalysisResult:
        memory = WorkingMemory()
        claims = ClaimLedger()
        evidence_ledger = EvidenceLedger()
        loop_state = LoopState(agent_id=self.agent_id, remaining_tool_calls=self._tool_budget())

        operations = self._call(
            "summarize_operations",
            evidence_ledger,
            memory,
            loop_state,
            purpose="inspect operation distribution for probe-like activity",
            limit=self.config.summary_limit,
        )
        blocks = self._call(
            "summarize_blocks",
            evidence_ledger,
            memory,
            loop_state,
            purpose="inspect behavior block distribution for runtime or registry probes",
            level="macro",
            limit=self.config.summary_limit,
        )

        probe_hits: list[ToolResult] = []
        for operation in PROBE_OPERATION_KEYS:
            result = self._call(
                "list_events",
                evidence_ledger,
                memory,
                loop_state,
                purpose=f"search probe-like operation {operation}",
                index_name="operation_index",
                key=operation,
                limit=self.config.max_events_per_key,
            )
            filtered = filter_probe_result(result)
            if filtered.returned_count:
                probe_hits.append(filtered)

        for process_name in PROBE_PROCESS_KEYS:
            result = self._call(
                "list_events",
                evidence_ledger,
                memory,
                loop_state,
                purpose=f"search monitor or analysis tool process {process_name}",
                index_name="process_name_index",
                key=process_name,
                limit=self.config.max_events_per_key,
            )
            if result.returned_count:
                probe_hits.append(result)

        selected_offsets = tuple(first_offsets(probe_hits, self.config.max_probe_events))
        actor_processes: list[str] = []
        if selected_offsets:
            for offset in selected_offsets:
                window = self._call(
                    "get_window_around_event",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"inspect local context around anti-analysis probe event:{offset}",
                    offset=offset,
                    before=self.config.window_before,
                    after=self.config.window_after,
                )
                actor_processes.extend(process_names_from_events(window.events))
            for process_name in unique_values(actor_processes)[:2]:
                self._call(
                    "trace_process",
                    evidence_ledger,
                    memory,
                    loop_state,
                    purpose=f"trace process containing probe evidence {process_name}",
                    process_name=process_name,
                    limit=self.config.trace_process_limit,
                )
            claims.add_candidate(
                agent_id=self.agent_id,
                claim_type="anti_analysis_behavior",
                statement=claim_statement(probe_hits, actor_processes),
                confidence=claim_confidence(probe_hits, actor_processes),
                evidence_ref_ids=memory.evidence_ref_ids(),
                supporting_block_ids=memory.block_ids(),
                alternative_explanations=BENIGN_ALTERNATIVES,
                uncertainty=uncertainties_from_memory(memory),
                known_ref_ids=memory.evidence_ref_ids(),
            )
            status = "supported"
        else:
            question = "No dynamic anti-analysis probe matching the configured operation, process, or target terms was observed."
            memory.add_open_question(question)
            loop_state.add_unresolved_question(question)
            status = "unresolved"

        context = self.context_builder.build(self.agent_id, memory, loop_state, task_prompt, claims)
        return DynamicAntiAnalysisResult(
            status=status,
            selected_event_offsets=selected_offsets,
            context=context,
            memory=memory,
            claim_ledger=claims,
            evidence_ledger=evidence_ledger,
            diagnostics={
                "operation_summary_items": operations.returned_count,
                "block_summary_items": blocks.returned_count,
                "probe_hit_queries": hit_queries(probe_hits),
                "actor_processes": unique_values(actor_processes),
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
        return 2 + len(PROBE_OPERATION_KEYS) + len(PROBE_PROCESS_KEYS) + self.config.max_probe_events + 2


BENIGN_ALTERNATIVES = (
    "ordinary runtime compatibility check",
    "application dependency or locale discovery",
    "security or monitoring software visible in retained host context",
)


def filter_probe_result(result: ToolResult) -> ToolResult:
    if not result.events:
        return result
    selected_events = []
    selected_refs = []
    for event, ref in zip(result.events, result.evidence_refs):
        if event_contains_probe_term(event):
            selected_events.append(event)
            selected_refs.append(ref)
    if not selected_events:
        return ToolResult(
            tool_name=result.tool_name,
            query=result.query,
            matched_count=result.matched_count,
            returned_count=0,
            limitations=result.limitations + ("operation matched but no configured probe term appeared in returned events",),
        )
    return ToolResult(
        tool_name=result.tool_name,
        query=result.query,
        matched_count=result.matched_count,
        returned_count=len(selected_events),
        evidence_refs=tuple(selected_refs),
        events=tuple(selected_events),
        cursor=result.cursor,
        limitations=result.limitations,
    )


def event_contains_probe_term(event: dict[str, Any]) -> bool:
    text_parts = [
        str(event.get("action", {}).get("operation") or ""),
        str(event.get("target", {}).get("path") or ""),
        str(event.get("target", {}).get("normalized_path") or ""),
        str(event.get("detail", {}).get("raw_detail") or ""),
        str(event.get("process_context", {}).get("process_name") or ""),
    ]
    text = " ".join(text_parts).casefold()
    return any(term in text for term in PROBE_TERMS)


def first_offsets(results: list[ToolResult], limit: int) -> list[int]:
    offsets: list[int] = []
    for result in results:
        for ref in result.evidence_refs:
            if ref.offset is not None and ref.offset not in offsets:
                offsets.append(ref.offset)
                if len(offsets) >= limit:
                    return offsets
    return offsets


def process_names_from_events(events: tuple[dict[str, Any], ...]) -> list[str]:
    names: list[str] = []
    for event in events:
        name = str(event.get("process_context", {}).get("process_name") or "")
        if name:
            names.append(name)
    return names


def claim_statement(probe_hits: list[ToolResult], actor_processes: list[str]) -> str:
    queries = ", ".join(hit_queries(probe_hits)) or "unknown probe query"
    actors = ", ".join(unique_values(actor_processes)) or "unknown actor process"
    return f"sample-attributed behavior includes dynamic anti-analysis probe evidence from {queries}; actor process(es): {actors}"


def claim_confidence(probe_hits: list[ToolResult], actor_processes: list[str]) -> str:
    hit_count = sum(result.returned_count for result in probe_hits)
    actor_count = len(unique_values(actor_processes))
    if hit_count >= 2 and actor_count >= 1:
        return "high"
    if hit_count >= 1:
        return "medium"
    return "low"


def uncertainties_from_memory(memory: WorkingMemory) -> tuple[str, ...]:
    limitations: list[str] = []
    for fact in memory.facts:
        for limitation in fact.limitations:
            if limitation not in limitations:
                limitations.append(limitation)
    if not limitations:
        limitations.append("claim identifies dynamic probe behavior; intent requires relation to later behavior suppression or early exit")
    return tuple(limitations)


def hit_queries(results: list[ToolResult]) -> tuple[str, ...]:
    values: list[str] = []
    for result in results:
        key = str(result.query.get("key") or result.query.get("index_name") or "")
        if key and key not in values:
            values.append(key)
    return tuple(values)


def unique_values(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out

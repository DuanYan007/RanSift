"""Agent-facing tool registry and evidence ledger."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .evidence import EvidenceRef, EvidenceTools, ToolResult

ToolCallable = Callable[..., ToolResult]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    returns: str
    limitations: tuple[str, ...] = ()
    agents: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "returns": self.returns,
            "limitations": list(self.limitations),
            "agents": list(self.agents),
        }


@dataclass
class EvidenceLedger:
    seen_ref_ids: set[str] = field(default_factory=set)
    accepted_ref_ids: set[str] = field(default_factory=set)
    rejected_ref_ids: set[str] = field(default_factory=set)
    open_questions: list[str] = field(default_factory=list)
    tool_history: list[dict[str, Any]] = field(default_factory=list)

    def record_result(self, result: ToolResult) -> dict[str, Any]:
        refs = [ref.ref_id for ref in result.evidence_refs]
        new_refs = [ref_id for ref_id in refs if ref_id not in self.seen_ref_ids]
        duplicate_refs = [ref_id for ref_id in refs if ref_id in self.seen_ref_ids]
        self.seen_ref_ids.update(refs)
        entry = {
            "tool_name": result.tool_name,
            "query": result.query,
            "matched_count": result.matched_count,
            "returned_count": result.returned_count,
            "new_ref_count": len(new_refs),
            "duplicate_ref_count": len(duplicate_refs),
            "limitations": list(result.limitations),
        }
        self.tool_history.append(entry)
        return entry

    def accept_refs(self, refs: list[EvidenceRef]) -> None:
        for ref in refs:
            self.accepted_ref_ids.add(ref.ref_id)
            self.seen_ref_ids.add(ref.ref_id)

    def reject_refs(self, refs: list[EvidenceRef]) -> None:
        for ref in refs:
            self.rejected_ref_ids.add(ref.ref_id)
            self.seen_ref_ids.add(ref.ref_id)

    def add_open_question(self, question: str) -> None:
        if question and question not in self.open_questions:
            self.open_questions.append(question)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seen_ref_count": len(self.seen_ref_ids),
            "accepted_ref_count": len(self.accepted_ref_ids),
            "rejected_ref_count": len(self.rejected_ref_ids),
            "open_questions": list(self.open_questions),
            "tool_history": list(self.tool_history),
        }


class ToolRegistry:
    def __init__(self, tools: EvidenceTools) -> None:
        self.tools = tools
        self._specs = build_tool_specs()
        self._callables: dict[str, ToolCallable] = {
            "get_event": tools.get_event,
            "get_window_around_event": tools.get_window_around_event,
            "list_events": tools.list_events,
            "list_index_keys": tools.list_index_keys,
            "search_events": tools.search_events,
            "get_block": tools.get_block,
            "list_blocks": tools.list_blocks,
            "get_block_events": tools.get_block_events,
            "summarize_operations": tools.summarize_operations,
            "summarize_processes": tools.summarize_processes,
            "summarize_blocks": tools.summarize_blocks,
            "explain_event_origin": tools.explain_event_origin,
            "trace_process": tools.trace_process,
            "get_process_timeline": tools.get_process_timeline,
            "trace_target": tools.trace_target,
            "find_target_activity": tools.find_target_activity,
            "find_command_invocations": tools.find_command_invocations,
            "find_concealed_script_host_fingerprinting": tools.find_concealed_script_host_fingerprinting,
            "find_deployed_elevated_autostart_tasks": tools.find_deployed_elevated_autostart_tasks,
            "find_destructive_recovery_commands": tools.find_destructive_recovery_commands,
            "find_behavior_sequence": tools.find_behavior_sequence,
            "find_file_extension_transitions": tools.find_file_extension_transitions,
            "find_file_extension_renames": tools.find_file_extension_renames,
            "find_raw_filesystem_metadata_writes": tools.find_raw_filesystem_metadata_writes,
            "find_ransom_note_artifacts": tools.find_ransom_note_artifacts,
            "find_run_key_executable_bindings": tools.find_run_key_executable_bindings,
            "neighbor_blocks": tools.neighbor_blocks,
        }

    def spec(self, name: str) -> ToolSpec:
        return self._specs[name]

    def specs_for_agent(self, agent_id: str) -> list[ToolSpec]:
        names = AGENT_TOOL_WHITELISTS.get(agent_id)
        if names is None:
            return [spec for spec in self._specs.values() if agent_id in spec.agents or "all" in spec.agents]
        missing = [name for name in names if name not in self._specs]
        if missing:
            raise KeyError(f"agent {agent_id!r} references unregistered tools: {missing}")
        return [self._specs[name] for name in names]

    def tool_names_for_agent(self, agent_id: str) -> list[str]:
        return [spec.name for spec in self.specs_for_agent(agent_id)]

    def validate_arguments(self, name: str, arguments: dict[str, Any]) -> None:
        """Reject a known tree-node identifier used as a process instance key.

        Do not silently drop a bad filter or broaden it to every instance of a
        reused PID. Unknown identifiers retain the existing query semantics.
        """
        key = arguments.get("process_key")
        if not key or not isinstance(key, str):
            return
        indexes = self.tools.store.index_maps
        if key.casefold() in indexes.get("node_index", {}) and key.casefold() not in indexes.get("process_key_index", {}):
            raise ValueError("process_key is a tree node_id, not a process instance key. "
                             "Use process.process_key from a returned event or process_instance.key from a block; "
                             "if only a PID is known, omit process_key and retain attribution limits.")

    def call(self, name: str, ledger: EvidenceLedger | None = None, **kwargs: Any) -> ToolResult:
        if name not in self._callables:
            raise KeyError(f"unknown tool: {name}")
        self.validate_arguments(name, kwargs)
        result = self._callables[name](**kwargs)
        if ledger is not None:
            ledger.record_result(result)
        return result

    def call_for_agent(self, agent_id: str, name: str, ledger: EvidenceLedger | None = None, **kwargs: Any) -> ToolResult:
        allowed = set(self.tool_names_for_agent(agent_id))
        if name not in allowed:
            raise PermissionError(f"tool {name!r} is not allowed for agent {agent_id!r}")
        return self.call(name, ledger=ledger, **kwargs)


def build_tool_specs() -> dict[str, ToolSpec]:
    specs = [
        ToolSpec(
            name="get_event",
            description="Return one normalized event by filtered offset.",
            parameters={"offset": "int"},
            returns="one event and one event EvidenceRef",
            agents=("all",),
        ),
        ToolSpec(
            name="get_window_around_event",
            description="Return a bounded local window around an event offset.",
            parameters={"offset": "int", "before": "int", "after": "int"},
            returns="bounded event window with EvidenceRefs",
            limitations=("bounded by trace start/end",),
            agents=("file_discovery", "file_transformation", "registry", "process"),
        ),
        ToolSpec(
            name="list_events",
            description="List events from one index key with cursor pagination.",
            parameters={"index_name": "str", "key": "str", "limit": "int", "cursor": "str|null"},
            returns="events and event EvidenceRefs",
            limitations=("requires known index name", "paginated"),
            agents=("all",),
        ),
        ToolSpec(
            name="list_index_keys",
            description="List valid keys from an index, optionally filtered by substring.",
            parameters={"index_name": "str", "pattern": "str|null", "limit": "int", "cursor": "str|null"},
            returns="index keys with counts and representative EvidenceRefs",
            limitations=("requires known index name", "paginated", "keys are normalized lowercase"),
            agents=("all",),
        ),
        ToolSpec(
            name="search_events",
            description="Search bounded normalized events where every supplied substring occurs across selected fields.",
            parameters={"patterns": "list[str]|str", "fields": "list[str]", "limit": "int", "cursor": "str|null"},
            returns="matching events and event EvidenceRefs",
            limitations=("all supplied patterns are conjunctive over normalized compact event text", "paginated"),
            agents=("all",),
        ),
        ToolSpec(
            name="list_blocks",
            description="List compact behavior blocks by kind/category/count.",
            parameters={"behavior_kind": "str|null", "category": "str|null", "min_event_count": "int", "level": "macro|micro", "limit": "int", "cursor": "str|null"},
            returns="compact blocks, block refs, representative event refs",
            limitations=("paginated", "does not return full source offsets"),
            agents=("all",),
        ),
        ToolSpec(
            name="get_block",
            description="Return one compact behavior block by block id.",
            parameters={"block_id": "str"},
            returns="one compact block, one block EvidenceRef, and representative event refs",
            limitations=("does not return full source offsets",),
            agents=("all",),
        ),
        ToolSpec(
            name="get_block_events",
            description="Return representative or bounded source events for one block.",
            parameters={"block_id": "str", "representative_only": "bool", "limit": "int"},
            returns="events for a block with EvidenceRefs",
            limitations=("full source offsets are bounded by limit",),
            agents=("all",),
        ),
        ToolSpec(
            name="trace_process",
            description="Summarize blocks and representative events for a process instance.",
            parameters={"process_key": "str|null", "pid": "int|null", "process_name": "str|null", "limit": "int"},
            returns="process-local compact blocks and representative refs",
            limitations=("bounded result",),
            agents=("file_discovery", "file_transformation", "registry", "process", "anti_analysis"),
        ),
        ToolSpec(
            name="trace_target",
            description="Trace events and blocks that touch a normalized target or target prefix.",
            parameters={"target": "str", "prefix": "bool", "limit": "int"},
            returns="target-related events/blocks with EvidenceRefs",
            limitations=("prefix scans block target examples and event paths",),
            agents=("file_discovery", "file_transformation", "registry", "recovery"),
        ),
        ToolSpec(
            name="get_process_timeline",
            description="Return a bounded event timeline for one attributed process instance.",
            parameters={"process_key": "str|null", "pid": "int|null", "process_name": "str|null", "limit": "int", "cursor": "str|null"},
            returns="process-local events with EvidenceRefs",
            limitations=("bounded result", "does not infer behavior intent"),
            agents=("all",),
        ),
        ToolSpec(
            name="find_target_activity",
            description="Return bounded events touching a normalized target or target prefix.",
            parameters={"target": "str", "prefix": "bool", "process_key": "str|null", "limit": "int", "cursor": "str|null"},
            returns="target-related events with EvidenceRefs",
            limitations=("prefix match over normalized target paths", "bounded result"),
            agents=("all",),
        ),
        ToolSpec(
            name="find_command_invocations",
            description="Return process or command-line events matching required command terms.",
            parameters={"terms": "list[str]|str|null", "process_key": "str|null", "pid": "int|null", "process_name": "str|null", "limit": "int", "cursor": "str|null"},
            returns="command invocation events with EvidenceRefs",
            limitations=("substring match over command-line, detail, target, and process fields", "bounded result"),
            agents=("process", "recovery", "anti_analysis", "registry", "ransom_note"),
        ),
        ToolSpec(
            name="find_concealed_script_host_fingerprinting",
            description=(
                "Find sample-attributed successful encoded PowerShell execution whose decoded content "
                "explicitly conceals a window and is paired with a hardware-identifier query."
            ),
            parameters={"limit": "int"},
            returns="bounded execution-chain evidence and deterministic supports",
            limitations=(
                "decodes bounded Base64 command content without execution",
                "does not establish ransomware impact, encryption, or exfiltration",
            ),
            agents=("process",),
        ),
        ToolSpec(
            name="find_deployed_elevated_autostart_tasks",
            description=(
                "Find an executable deployed by the attributed process tree and made persistent by an "
                "executed elevated schtasks /CREATE command that targets the same path at logon or startup."
            ),
            parameters={"limit": "int"},
            returns="three-event deployment and task-execution evidence with deterministic supports",
            limitations=(
                "requires SYSTEM and HIGHEST task settings",
                "does not establish post-reboot task execution",
            ),
            agents=("process",),
        ),
        ToolSpec(
            name="find_destructive_recovery_commands",
            description="Find attributed destructive recovery commands with paired successful Process Create and Process Start evidence.",
            parameters={"limit": "int"},
            returns="paired process-execution events and deterministic command-execution supports",
            limitations=("establishes command execution, not the resulting recovery-impact state",),
            agents=("recovery",),
        ),
        ToolSpec(
            name="find_behavior_sequence",
            description="Find bounded event sequences matching operation families within one process.",
            parameters={"families": "list[str]", "process_key": "str|null", "limit": "int"},
            returns="sequence aggregates with representative event refs",
            limitations=("deterministic order match, not an intent claim",),
            agents=("file_transformation", "registry", "process", "recovery"),
        ),
        ToolSpec(
            name="find_file_extension_transitions",
            description="Find same-process successful writes to added-extension files followed by successful deletion of the original path.",
            parameters={"process_key": "str|null", "scope": "all|direct_user_shared", "min_pair_count": "int", "max_order_gap": "int", "limit": "int"},
            returns="grouped transition summaries, representative write/delete events, and event EvidenceRefs",
            limitations=(
                "pairs are limited to retained same-process WriteFile and delete events",
                "does not prove file-content encryption or malicious intent",
            ),
            agents=("file_transformation",),
        ),
        ToolSpec(
            name="find_file_extension_renames",
            description="Find same-process successful in-directory renames that change source extensions, grouped by target scope and destination extension.",
            parameters={"process_key": "str|null", "scope": "all|direct_user_shared", "min_rename_count": "int", "min_scope_count": "int", "limit": "int"},
            returns="grouped rename summaries, representative source/destination events, and event EvidenceRefs",
            limitations=(
                "requires retained SetRenameInformation events with a parseable same-directory destination path",
                "does not prove file-content encryption or malicious intent",
            ),
            agents=("file_transformation",),
        ),
        ToolSpec(
            name="find_raw_filesystem_metadata_writes",
            description="Find recorded process-attributed writes to NTFS metadata objects; assess filesystem-maintenance versus deliberate raw access from additional context.",
            parameters={"limit": "int"},
            returns="metadata-write groups, representative event refs, and deterministic supports",
            limitations=(
                "requires successful content writes rather than reads or opens",
                "process attribution and paging/non-cached writes alone do not establish deliberate raw access or corruption",
                "the detector establishes a write pattern, not malicious intent or the broader payload objective",
            ),
            agents=("file_transformation",),
        ),
        ToolSpec(
            name="find_ransom_note_artifacts",
            description="Find note-like basenames with successful create or write evidence.",
            parameters={"limit": "int"},
            returns="note-artifact groups, event refs, and deterministic candidate supports",
            limitations=(
                "does not inspect note content",
                "does not establish encryption or extortion impact by itself",
            ),
            agents=("ransom_note",),
        ),
        ToolSpec(
            name="find_run_key_executable_bindings",
            description="Find successful Run or RunOnce registry values that bind an executable payload path.",
            parameters={"limit": "int"},
            returns="autostart bindings, event refs, and deterministic candidate supports",
            limitations=(
                "excludes RegCreateKey-only observations",
                "does not establish later autostart execution",
            ),
            agents=("registry",),
        ),
        ToolSpec(
            name="neighbor_blocks",
            description="Return compact blocks before and after a block in the same process timeline.",
            parameters={"block_id": "str", "before": "int", "after": "int"},
            returns="neighbor compact blocks and refs",
            limitations=("same process only",),
            agents=("all",),
        ),
        ToolSpec(
            name="summarize_operations",
            description="Aggregate operation counts with representative offsets.",
            parameters={"limit": "int"},
            returns="operation aggregates with representative EvidenceRefs",
            limitations=("aggregate is not a claim",),
            agents=("all",),
        ),
        ToolSpec(
            name="summarize_processes",
            description="Aggregate process-name counts with representative offsets.",
            parameters={"limit": "int"},
            returns="process aggregates with representative EvidenceRefs",
            limitations=("aggregate is not a claim",),
            agents=("all",),
        ),
        ToolSpec(
            name="summarize_blocks",
            description="Aggregate behavior blocks by behavior kind.",
            parameters={"level": "macro|micro", "limit": "int"},
            returns="block-kind aggregates with representative block refs",
            limitations=("aggregate is not a claim",),
            agents=("all",),
        ),
        ToolSpec(
            name="explain_event_origin",
            description="Return source order, process context, and time for one event.",
            parameters={"offset": "int"},
            returns="origin metadata and event EvidenceRef",
            agents=("evidence_auditor", "all"),
        ),
    ]
    return {spec.name: spec for spec in specs}


AGENT_TOOL_WHITELISTS: dict[str, tuple[str, ...]] = {
    "file_discovery": ("summarize_blocks", "list_blocks", "get_block_events", "neighbor_blocks", "trace_process", "get_process_timeline", "trace_target", "find_target_activity", "get_window_around_event", "list_events", "list_index_keys", "search_events"),
    "file_transformation": ("list_blocks", "get_block_events", "trace_target", "find_target_activity", "find_behavior_sequence", "find_file_extension_transitions", "find_file_extension_renames", "find_raw_filesystem_metadata_writes", "trace_process", "get_process_timeline", "neighbor_blocks", "get_window_around_event", "list_events", "list_index_keys", "search_events"),
    "ransom_note": ("find_ransom_note_artifacts", "search_events", "find_command_invocations", "list_index_keys", "list_events", "get_window_around_event", "trace_target", "find_target_activity", "trace_process", "get_process_timeline"),
    "registry": ("find_run_key_executable_bindings", "summarize_blocks", "list_blocks", "get_block_events", "trace_target", "find_target_activity", "find_command_invocations", "find_behavior_sequence", "trace_process", "get_process_timeline", "neighbor_blocks", "list_events", "list_index_keys", "search_events"),
    "process": ("summarize_processes", "trace_process", "get_process_timeline", "find_command_invocations", "find_concealed_script_host_fingerprinting", "find_deployed_elevated_autostart_tasks", "find_behavior_sequence", "neighbor_blocks", "get_event", "get_window_around_event", "list_events", "list_index_keys", "search_events"),
    "recovery": ("summarize_processes", "list_events", "list_index_keys", "search_events", "find_command_invocations", "find_destructive_recovery_commands", "trace_process", "get_process_timeline", "trace_target", "find_target_activity", "find_behavior_sequence", "get_window_around_event"),
    "anti_analysis": ("summarize_operations", "summarize_blocks", "trace_process", "get_process_timeline", "find_command_invocations", "list_events", "list_index_keys", "search_events", "get_window_around_event"),
    "evidence_auditor": ("get_event", "get_block", "get_block_events", "explain_event_origin", "neighbor_blocks"),
}

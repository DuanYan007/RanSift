"""Evidence store and atomic read-only tools for behavior analysis."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .classification import (
    DETERMINISTIC_EXECUTED_DESTRUCTIVE_RECOVERY_COMMAND_RULE,
    destructive_recovery_command_kind,
)
from .concealed_execution import search_concealed_script_host_fingerprinting
from .autostart_persistence import search_deployed_elevated_autostart_tasks
from .file_renames import rename_destination_path, search_file_extension_renames
from .file_transitions import TRANSITION_SCOPE_ALL, search_file_extension_transitions
from .ransom_note_artifacts import search_ransom_note_artifacts
from .raw_filesystem_metadata import search_raw_filesystem_metadata_writes
from .run_key_persistence import search_run_key_executable_bindings

DEFAULT_LIMIT = 20
MAX_LIMIT = 200
MAX_EVENT_EXCERPT = 240


@dataclass(frozen=True)
class EvidenceRef:
    ref_id: str
    kind: str
    offset: int | None = None
    block_id: str | None = None
    source_order: str | None = None
    process_instance: dict[str, Any] | None = None
    representative: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ref_id": self.ref_id,
            "kind": self.kind,
            "offset": self.offset,
            "block_id": self.block_id,
            "source_order": self.source_order,
            "process_instance": self.process_instance,
            "representative": self.representative,
        }


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    query: dict[str, Any]
    matched_count: int = 0
    returned_count: int = 0
    evidence_refs: tuple[EvidenceRef, ...] = ()
    events: tuple[dict[str, Any], ...] = ()
    blocks: tuple[dict[str, Any], ...] = ()
    aggregates: dict[str, Any] = field(default_factory=dict)
    cursor: str | None = None
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "query": self.query,
            "matched_count": self.matched_count,
            "returned_count": self.returned_count,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "events": list(self.events),
            "blocks": list(self.blocks),
            "aggregates": self.aggregates,
            "cursor": self.cursor,
            "limitations": list(self.limitations),
        }


class EvidenceStore:
    """Read-only view over one sample's normalized trace, index, and blocks."""

    def __init__(self, trace_path: str | Path, index_path: str | Path, blocks_path: str | Path | None = None) -> None:
        self.trace_path = Path(trace_path)
        self.index_path = Path(index_path)
        self.blocks_path = Path(blocks_path) if blocks_path else None
        self._events: list[dict[str, Any]] | None = None
        self._index: dict[str, Any] | None = None
        self._blocks_payload: dict[str, Any] | None = None
        self._blocks_by_id: dict[str, dict[str, Any]] | None = None

    @classmethod
    def from_catalog(
        cls,
        trace_path: str | Path,
        catalog_path: str | Path,
        phase_blocks_path: str | Path,
        checkpoints_path: str | Path,
    ):
        """Open a sealed behavior catalog without materializing its full trace."""
        from .catalog_store import CatalogEvidenceStore

        return CatalogEvidenceStore(
            trace_path,
            catalog_path,
            phase_blocks_path,
            checkpoints_path,
        )

    @property
    def events(self) -> list[dict[str, Any]]:
        if self._events is None:
            self._events = []
            with self.trace_path.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        self._events.append(json.loads(line))
        return self._events

    @property
    def index(self) -> dict[str, Any]:
        if self._index is None:
            self._index = json.loads(self.index_path.read_text(encoding="utf-8"))
        return self._index

    @property
    def index_maps(self) -> dict[str, dict[str, list[int]]]:
        return self.index.get("indexes", {})

    @property
    def blocks_payload(self) -> dict[str, Any]:
        if self.blocks_path is None:
            return {"micro_blocks": [], "macro_blocks": []}
        if self._blocks_payload is None:
            self._blocks_payload = json.loads(self.blocks_path.read_text(encoding="utf-8"))
        return self._blocks_payload

    @property
    def blocks_by_id(self) -> dict[str, dict[str, Any]]:
        if self._blocks_by_id is None:
            blocks: dict[str, dict[str, Any]] = {}
            for block in self.blocks_payload.get("micro_blocks", []) + self.blocks_payload.get("macro_blocks", []):
                blocks[block["block_id"]] = block
            self._blocks_by_id = blocks
        return self._blocks_by_id

    def get_event(self, offset: int) -> dict[str, Any]:
        if offset < 0 or offset >= len(self.events):
            raise IndexError(f"event offset out of range: {offset}")
        return self.events[offset]

    def get_block(self, block_id: str) -> dict[str, Any]:
        try:
            return self.blocks_by_id[block_id]
        except KeyError as exc:
            raise KeyError(f"unknown block_id: {block_id}") from exc

    def evidence_ref_for_event(self, offset: int, representative: bool = False) -> EvidenceRef:
        event = self.get_event(offset)
        return EvidenceRef(
            ref_id=f"event:{offset}",
            kind="event",
            offset=offset,
            source_order=event.get("order", {}).get("source"),
            process_instance=event.get("process_context"),
            representative=representative,
        )

    def evidence_ref_for_block(self, block: dict[str, Any], representative: bool = False) -> EvidenceRef:
        return EvidenceRef(
            ref_id=f"block:{block['block_id']}",
            kind="block",
            block_id=block["block_id"],
            process_instance=block.get("process_instance"),
            representative=representative,
        )

    def query_surface(self, limit: int = 40) -> dict[str, Any]:
        """Return bounded dynamic vocabulary that agents may use in tool calls."""
        index_names = sorted(self.index_maps)
        compact_indexes = {}
        for name in (
            "operation_index",
            "process_name_index",
            "category_index",
            "namespace_index",
            "extension_index",
            "result_index",
        ):
            index = self.index_maps.get(name, {})
            compact_indexes[name] = [
                {"key": key, "count": len(offsets)}
                for key, offsets in sorted(index.items(), key=lambda item: (-len(item[1]), item[0]))[:limit]
            ]
        return {
            "index_names": index_names,
            "index_key_counts": {name: len(index) for name, index in self.index_maps.items()},
            "common_index_keys": compact_indexes,
            "block_kinds": block_kind_counts(self.blocks_payload),
            "query_rules": (
                "list_events.index_name must be one of index_names.",
                "list_events.key values are normalized to lowercase.",
                "list_blocks.behavior_kind must use a value from block_kinds.",
                "Use search_events for command-line substrings, ransom-note names, extensions, or recovery-tool terms.",
            ),
        }


class EvidenceTools:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def get_event(self, offset: int) -> ToolResult:
        event = self.store.get_event(offset)
        ref = self.store.evidence_ref_for_event(offset, representative=True)
        return ToolResult(
            tool_name="get_event",
            query={"offset": offset},
            matched_count=1,
            returned_count=1,
            evidence_refs=(ref,),
            events=(event,),
        )

    def get_window_around_event(self, offset: int, before: int = 5, after: int = 5) -> ToolResult:
        before = max(0, min(before, MAX_LIMIT))
        after = max(0, min(after, MAX_LIMIT))
        start = max(0, offset - before)
        end = min(len(self.store.events), offset + after + 1)
        offsets = list(range(start, end))
        events = tuple(self.store.get_event(item) for item in offsets)
        refs = tuple(self.store.evidence_ref_for_event(item, representative=(item == offset)) for item in offsets)
        return ToolResult(
            tool_name="get_window_around_event",
            query={"offset": offset, "before": before, "after": after},
            matched_count=len(offsets),
            returned_count=len(offsets),
            evidence_refs=refs,
            events=events,
            limitations=("window is bounded by trace start/end",),
        )

    def list_events(self, index_name: str, key: str, limit: int = DEFAULT_LIMIT, cursor: str | None = None) -> ToolResult:
        limit = bounded_limit(limit)
        normalized_key = normalize_key(key)
        index = self.store.index_maps.get(index_name)
        if index is None:
            return ToolResult(
                tool_name="list_events",
                query={"index_name": index_name, "key": key, "limit": limit, "cursor": cursor},
                limitations=(f"unknown index: {index_name}",),
            )
        offsets = index.get(normalized_key, [])
        start = parse_cursor(cursor)
        selected = offsets[start:start + limit]
        next_cursor = str(start + len(selected)) if start + len(selected) < len(offsets) else None
        refs = tuple(self.store.evidence_ref_for_event(offset, representative=True) for offset in selected)
        events = tuple(self.store.get_event(offset) for offset in selected)
        limitations = () if next_cursor is None else ("result truncated; use cursor to continue",)
        return ToolResult(
            tool_name="list_events",
            query={"index_name": index_name, "key": key, "limit": limit, "cursor": cursor},
            matched_count=len(offsets),
            returned_count=len(selected),
            evidence_refs=refs,
            events=events,
            cursor=next_cursor,
            limitations=limitations,
        )

    def list_index_keys(
        self,
        index_name: str,
        pattern: str | None = None,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        index = self.store.index_maps.get(index_name)
        if index is None:
            return ToolResult(
                tool_name="list_index_keys",
                query={"index_name": index_name, "pattern": pattern, "limit": limit, "cursor": cursor},
                limitations=(f"unknown index: {index_name}",),
            )
        normalized_pattern = normalize_key(pattern or "")
        rows = []
        for key, offsets in index.items():
            if normalized_pattern and normalized_pattern not in key:
                continue
            rows.append((key, offsets))
        rows.sort(key=lambda item: (-len(item[1]), item[0]))
        start = parse_cursor(cursor)
        selected = rows[start:start + limit]
        next_cursor = str(start + len(selected)) if start + len(selected) < len(rows) else None
        evidence_refs = tuple(
            self.store.evidence_ref_for_event(offsets[0], representative=True)
            for _, offsets in selected
            if offsets
        )
        limitations = () if next_cursor is None else ("result truncated; use cursor to continue",)
        return ToolResult(
            tool_name="list_index_keys",
            query={"index_name": index_name, "pattern": pattern, "limit": limit, "cursor": cursor},
            matched_count=len(rows),
            returned_count=len(selected),
            evidence_refs=evidence_refs,
            aggregates={
                "keys": [
                    {"key": key, "count": len(offsets), "representative_offset": offsets[0] if offsets else None}
                    for key, offsets in selected
                ]
            },
            cursor=next_cursor,
            limitations=limitations,
        )

    def search_events(
        self,
        patterns: list[str] | str,
        fields: list[str] | None = None,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        pattern_values = [patterns] if isinstance(patterns, str) else list(patterns)
        normalized_patterns = [normalize_key(item) for item in pattern_values if normalize_key(item)]
        selected_fields = tuple(fields or ("operation", "target", "detail", "process"))
        if not normalized_patterns:
            return ToolResult(
                tool_name="search_events",
                query={"patterns": pattern_values, "fields": list(selected_fields), "limit": limit, "cursor": cursor},
                limitations=("empty pattern list",),
            )
        matched_offsets = []
        for offset, event in enumerate(self.store.events):
            haystack = event_search_text(event, selected_fields)
            if all(pattern in haystack for pattern in normalized_patterns):
                matched_offsets.append(offset)
        start = parse_cursor(cursor)
        selected_offsets = matched_offsets[start:start + limit]
        next_cursor = str(start + len(selected_offsets)) if start + len(selected_offsets) < len(matched_offsets) else None
        refs = tuple(self.store.evidence_ref_for_event(offset, representative=True) for offset in selected_offsets)
        events = tuple(self.store.get_event(offset) for offset in selected_offsets)
        limitations = () if next_cursor is None else ("result truncated; use cursor to continue",)
        return ToolResult(
            tool_name="search_events",
            query={"patterns": pattern_values, "fields": list(selected_fields), "limit": limit, "cursor": cursor},
            matched_count=len(matched_offsets),
            returned_count=len(selected_offsets),
            evidence_refs=refs,
            events=events,
            cursor=next_cursor,
            limitations=limitations,
        )

    def get_block(self, block_id: str) -> ToolResult:
        block = self.store.get_block(block_id)
        ref = self.store.evidence_ref_for_block(block, representative=True)
        event_refs = tuple(self.store.evidence_ref_for_event(offset, representative=True) for offset in block.get("representative_offsets", []))
        return ToolResult(
            tool_name="get_block",
            query={"block_id": block_id},
            matched_count=1,
            returned_count=1,
            evidence_refs=(ref,) + event_refs,
            blocks=(compact_block_for_tool(block),),
        )

    def list_blocks(
        self,
        behavior_kind: str | None = None,
        category: str | None = None,
        min_event_count: int = 1,
        level: str = "macro",
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        source = self.store.blocks_payload.get("macro_blocks" if level == "macro" else "micro_blocks", [])
        blocks = []
        for block in source:
            if behavior_kind and block.get("behavior_kind") != behavior_kind:
                continue
            if category and block.get("category") != category:
                continue
            if int(block.get("event_count") or 0) < min_event_count:
                continue
            blocks.append(block)
        blocks.sort(key=lambda block: (-int(block.get("event_count") or 0), block.get("order_range", [0])[0], block.get("block_id", "")))
        start = parse_cursor(cursor)
        selected = blocks[start:start + limit]
        next_cursor = str(start + len(selected)) if start + len(selected) < len(blocks) else None
        block_refs = tuple(self.store.evidence_ref_for_block(block, representative=True) for block in selected)
        event_refs = tuple(
            self.store.evidence_ref_for_event(offset, representative=True)
            for block in selected
            for offset in block.get("representative_offsets", [])[:2]
        )
        limitations = () if next_cursor is None else ("result truncated; use cursor to continue",)
        return ToolResult(
            tool_name="list_blocks",
            query={
                "behavior_kind": behavior_kind,
                "category": category,
                "min_event_count": min_event_count,
                "level": level,
                "limit": limit,
                "cursor": cursor,
            },
            matched_count=len(blocks),
            returned_count=len(selected),
            evidence_refs=block_refs + event_refs,
            blocks=tuple(compact_block_for_tool(block) for block in selected),
            cursor=next_cursor,
            limitations=limitations,
        )

    def get_block_events(self, block_id: str, representative_only: bool = True, limit: int = DEFAULT_LIMIT) -> ToolResult:
        limit = bounded_limit(limit)
        block = self.store.get_block(block_id)
        offsets = block.get("representative_offsets", []) if representative_only else expand_block_offsets(block)
        selected = offsets[:limit]
        refs = tuple(self.store.evidence_ref_for_event(offset, representative=offset in block.get("representative_offsets", [])) for offset in selected)
        events = tuple(self.store.get_event(offset) for offset in selected)
        limitations = []
        if len(selected) < len(offsets):
            limitations.append("result truncated by limit")
        if representative_only:
            limitations.append("representative_only omits non-representative source offsets")
        return ToolResult(
            tool_name="get_block_events",
            query={"block_id": block_id, "representative_only": representative_only, "limit": limit},
            matched_count=len(offsets),
            returned_count=len(selected),
            evidence_refs=refs,
            events=events,
            blocks=(compact_block_for_tool(block),),
            limitations=tuple(limitations),
        )


    def trace_process(
        self,
        process_key: str | None = None,
        pid: int | None = None,
        process_name: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        blocks = []
        for block in self.store.blocks_payload.get("macro_blocks", []):
            process = block.get("process_instance", {})
            if process_key and process.get("key") != process_key:
                continue
            if pid is not None and int(process.get("pid") or 0) != int(pid):
                continue
            if process_name and str(process.get("process_name") or "").casefold() != process_name.casefold():
                continue
            blocks.append(block)
        blocks.sort(key=lambda block: block.get("order_range", [0])[0])
        selected = blocks[:limit]
        block_refs = tuple(self.store.evidence_ref_for_block(block, representative=True) for block in selected)
        event_refs = tuple(
            self.store.evidence_ref_for_event(offset, representative=True)
            for block in selected
            for offset in block.get("representative_offsets", [])[:1]
        )
        limitations = () if len(selected) == len(blocks) else ("result truncated by limit",)
        return ToolResult(
            tool_name="trace_process",
            query={"process_key": process_key, "pid": pid, "process_name": process_name, "limit": limit},
            matched_count=len(blocks),
            returned_count=len(selected),
            evidence_refs=block_refs + event_refs,
            blocks=tuple(compact_block_for_tool(block) for block in selected),
            aggregates={"process_count": len({block.get("process_instance", {}).get("key") for block in blocks})},
            limitations=limitations,
        )

    def get_process_timeline(
        self,
        process_key: str | None = None,
        pid: int | None = None,
        process_name: str | None = None,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        matched_offsets = [
            offset for offset, event in enumerate(self.store.events)
            if process_matches(event, process_key=process_key, pid=pid, process_name=process_name)
        ]
        start = parse_cursor(cursor)
        selected_offsets = matched_offsets[start:start + limit]
        next_cursor = str(start + len(selected_offsets)) if start + len(selected_offsets) < len(matched_offsets) else None
        refs = tuple(self.store.evidence_ref_for_event(offset, representative=True) for offset in selected_offsets)
        events = tuple(self.store.get_event(offset) for offset in selected_offsets)
        limitations = () if next_cursor is None else ("result truncated; use cursor to continue",)
        return ToolResult(
            tool_name="get_process_timeline",
            query={"process_key": process_key, "pid": pid, "process_name": process_name, "limit": limit, "cursor": cursor},
            matched_count=len(matched_offsets),
            returned_count=len(selected_offsets),
            evidence_refs=refs,
            events=events,
            cursor=next_cursor,
            aggregates={"operation_counts": event_operation_counts(events)},
            limitations=limitations,
        )

    def trace_target(self, target: str, prefix: bool = True, limit: int = DEFAULT_LIMIT) -> ToolResult:
        limit = bounded_limit(limit)
        normalized = normalize_key(target).replace("/", "\\")
        matched_offsets: list[int] = []
        for offset, event in enumerate(self.store.events):
            path = normalize_key(event.get("target", {}).get("normalized_path") or "")
            if target_matches(path, normalized, prefix):
                matched_offsets.append(offset)
        selected_offsets = matched_offsets[:limit]
        refs = [self.store.evidence_ref_for_event(offset, representative=True) for offset in selected_offsets]
        events = [self.store.get_event(offset) for offset in selected_offsets]

        matched_blocks = []
        for block in self.store.blocks_payload.get("macro_blocks", []):
            candidates = [normalize_key(block.get("target_scope") or "")]
            candidates.extend(normalize_key(item) for item in block.get("target_examples", []))
            if any(target_matches(candidate, normalized, prefix) for candidate in candidates):
                matched_blocks.append(block)
        selected_blocks = matched_blocks[:limit]
        refs.extend(self.store.evidence_ref_for_block(block, representative=True) for block in selected_blocks)
        limitations = []
        if len(selected_offsets) < len(matched_offsets) or len(selected_blocks) < len(matched_blocks):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="trace_target",
            query={"target": target, "prefix": prefix, "limit": limit},
            matched_count=len(matched_offsets) + len(matched_blocks),
            returned_count=len(selected_offsets) + len(selected_blocks),
            evidence_refs=tuple(refs),
            events=tuple(events),
            blocks=tuple(compact_block_for_tool(block) for block in selected_blocks),
            aggregates={"matched_event_count": len(matched_offsets), "matched_block_count": len(matched_blocks)},
            limitations=tuple(limitations),
        )

    def find_target_activity(
        self,
        target: str,
        prefix: bool = True,
        process_key: str | None = None,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        normalized = normalize_key(target).replace("/", "\\")
        matched_offsets = []
        for offset, event in enumerate(self.store.events):
            if process_key and not process_matches(event, process_key=process_key):
                continue
            path = normalize_key(event.get("target", {}).get("normalized_path") or "")
            if target_matches(path, normalized, prefix):
                matched_offsets.append(offset)
        start = parse_cursor(cursor)
        selected_offsets = matched_offsets[start:start + limit]
        next_cursor = str(start + len(selected_offsets)) if start + len(selected_offsets) < len(matched_offsets) else None
        refs = tuple(self.store.evidence_ref_for_event(offset, representative=True) for offset in selected_offsets)
        events = tuple(self.store.get_event(offset) for offset in selected_offsets)
        limitations = () if next_cursor is None else ("result truncated; use cursor to continue",)
        return ToolResult(
            tool_name="find_target_activity",
            query={"target": target, "prefix": prefix, "process_key": process_key, "limit": limit, "cursor": cursor},
            matched_count=len(matched_offsets),
            returned_count=len(selected_offsets),
            evidence_refs=refs,
            events=events,
            cursor=next_cursor,
            aggregates={"operation_counts": event_operation_counts(events)},
            limitations=limitations,
        )

    def find_command_invocations(
        self,
        terms: list[str] | str | None = None,
        process_key: str | None = None,
        pid: int | None = None,
        process_name: str | None = None,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        wanted = [normalize_key(item) for item in ([terms] if isinstance(terms, str) else list(terms or [])) if normalize_key(item)]
        matched_offsets = []
        for offset, event in enumerate(self.store.events):
            if (process_key or pid is not None or process_name) and not process_matches(
                event,
                process_key=process_key,
                pid=pid,
                process_name=process_name,
            ):
                continue
            text = command_text(event)
            if not is_command_invocation(event):
                continue
            if wanted and not all(term in text for term in wanted):
                continue
            matched_offsets.append(offset)
        start = parse_cursor(cursor)
        selected_offsets = matched_offsets[start:start + limit]
        next_cursor = str(start + len(selected_offsets)) if start + len(selected_offsets) < len(matched_offsets) else None
        refs = tuple(self.store.evidence_ref_for_event(offset, representative=True) for offset in selected_offsets)
        events = tuple(self.store.get_event(offset) for offset in selected_offsets)
        limitations = () if next_cursor is None else ("result truncated; use cursor to continue",)
        return ToolResult(
            tool_name="find_command_invocations",
            query={"terms": terms, "process_key": process_key, "pid": pid, "process_name": process_name, "limit": limit, "cursor": cursor},
            matched_count=len(matched_offsets),
            returned_count=len(selected_offsets),
            evidence_refs=refs,
            events=events,
            cursor=next_cursor,
            aggregates={"operation_counts": event_operation_counts(events)},
            limitations=limitations,
        )


    def find_concealed_script_host_fingerprinting(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        """Find encoded script execution that hides a window and fingerprints the host.

        The search decodes bounded Base64 command content without execution. A
        deterministic support requires successful PowerShell process start with
        explicit concealment semantics and a separate successful hardware-ID
        query in the attributed trace.
        """
        limit = bounded_limit(limit)
        search = search_concealed_script_host_fingerprinting(
            enumerate(self.store.events),
            limit=limit,
        )
        refs = tuple(
            self.store.evidence_ref_for_event(offset, representative=True)
            for offset in search.representative_offsets
        )
        events = tuple(self.store.get_event(offset) for offset in search.representative_offsets)
        limitations = [
            "decodes bounded Base64 command content without executing it",
            "requires explicit window-concealment semantics and a successful hardware-identifier query",
            "does not establish ransomware impact, encryption, or exfiltration",
        ]
        if search.matched_chain_count > len(search.chains):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_concealed_script_host_fingerprinting",
            query={"limit": limit},
            matched_count=search.matched_chain_count,
            returned_count=len(search.chains),
            evidence_refs=refs,
            events=events,
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def find_deployed_elevated_autostart_tasks(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        """Find deployed executables made persistent by executed elevated autostart tasks."""
        limit = bounded_limit(limit)
        search = search_deployed_elevated_autostart_tasks(
            enumerate(self.store.events),
            limit=limit,
        )
        limitations = [
            "requires a successful executable write in ProgramData or user AppData/Startup",
            "requires paired successful Process Create and Process Start for schtasks /CREATE",
            "requires an ONLOGON or ONSTART task targeting the same executable as SYSTEM at HIGHEST run level",
            "does not establish that the task later ran after reboot or logon",
        ]
        if search.matched_chain_count > len(search.chains):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_deployed_elevated_autostart_tasks",
            query={"limit": limit},
            matched_count=search.matched_chain_count,
            returned_count=len(search.chains),
            evidence_refs=tuple(
                self.store.evidence_ref_for_event(offset, representative=True)
                for offset in search.representative_offsets
            ),
            events=tuple(self.store.get_event(offset) for offset in search.representative_offsets),
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def find_destructive_recovery_commands(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        """Find directly observed destructive recovery commands with execution pairs.

        A command line alone can be a process-create attempt. This tool emits a
        deterministic support only after a successful Process Create and the
        corresponding successful Process Start establish execution in the
        attributed process tree. It does not infer the command's external
        effect.
        """
        limit = bounded_limit(limit)
        creates_by_child: dict[tuple[str, int], list[tuple[int, dict[str, Any]]]] = (
            defaultdict(list)
        )
        pairs: list[dict[str, Any]] = []

        for offset, event in enumerate(self.store.events):
            action = event.get("action", {})
            if normalize_key(action.get("result")) != "success":
                continue
            command_kind = destructive_recovery_command_kind(command_text(event))
            if command_kind is None:
                continue
            operation = normalize_key(action.get("operation"))
            if operation == "process create":
                child_pid = created_process_pid(event)
                if child_pid is not None:
                    creates_by_child[(command_kind, child_pid)].append((offset, event))
                continue
            if operation != "process start":
                continue
            child_pid = process_pid(event)
            if child_pid is None:
                continue
            candidates = creates_by_child.get((command_kind, child_pid), [])
            create = next((item for item in reversed(candidates) if item[0] < offset), None)
            if create is None:
                continue
            create_offset, create_event = create
            pairs.append({
                "command_kind": command_kind,
                "create_offset": create_offset,
                "start_offset": offset,
                "parent_process_key": process_key(create_event),
                "child_process_key": process_key(event),
            })

        selected = pairs[:limit]
        refs: list[EvidenceRef] = []
        events: list[dict[str, Any]] = []
        supports: list[dict[str, Any]] = []
        for pair in selected:
            create_offset = int(pair["create_offset"])
            start_offset = int(pair["start_offset"])
            refs.extend((
                self.store.evidence_ref_for_event(create_offset, representative=True),
                self.store.evidence_ref_for_event(start_offset, representative=True),
            ))
            events.extend((self.store.get_event(create_offset), self.store.get_event(start_offset)))
            supports.append({
                "rule_id": DETERMINISTIC_EXECUTED_DESTRUCTIVE_RECOVERY_COMMAND_RULE,
                "command_kind": pair["command_kind"],
                "execution_count": 1,
                "evidence_ref_ids": [f"event:{create_offset}", f"event:{start_offset}"],
                "parent_process_key": pair["parent_process_key"],
                "child_process_key": pair["child_process_key"],
            })
        return ToolResult(
            tool_name="find_destructive_recovery_commands",
            query={"limit": limit},
            matched_count=len(pairs),
            returned_count=len(selected),
            evidence_refs=tuple(refs),
            events=tuple(events),
            aggregates={
                "execution_pairs": selected,
                "deterministic_rule_supports": supports,
            },
            limitations=(
                "a paired successful Process Create and Process Start establishes command execution, not recovery-impact completion",
            ),
        )

    def find_behavior_sequence(
        self,
        families: list[str],
        process_key: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        wanted = [normalize_key(family) for family in families if family]
        if not wanted:
            return ToolResult(
                tool_name="find_behavior_sequence",
                query={"families": families, "process_key": process_key, "limit": limit},
                limitations=("empty sequence pattern",),
            )
        atoms = []
        for block in self.store.blocks_payload.get("micro_blocks", []):
            process = block.get("process_instance", {})
            if process_key and process.get("key") != process_key:
                continue
            block_families = [normalize_key(item) for item in block.get("operation_families", [])]
            atoms.append((block, block_families))
        atoms.sort(key=lambda item: item[0].get("order_range", [0])[0])
        sequences: list[list[dict[str, Any]]] = []
        for index, (block, block_families) in enumerate(atoms):
            if wanted[0] not in block_families:
                continue
            sequence = [block]
            if len(wanted) == 1:
                sequences.append(sequence)
                continue
            position = 1
            last_order = block.get("order_range", [0, 0])[1]
            for next_block, next_families in atoms[index + 1:]:
                if next_block.get("process_instance", {}).get("key") != block.get("process_instance", {}).get("key"):
                    continue
                if next_block.get("order_range", [0])[0] - last_order > 250:
                    break
                if wanted[position] in next_families:
                    sequence.append(next_block)
                    position += 1
                    last_order = next_block.get("order_range", [0, 0])[1]
                    if position == len(wanted):
                        sequences.append(sequence)
                        break
        selected = sequences[:limit]
        refs = []
        rows = []
        for sequence in selected:
            rows.append({
                "block_ids": [block["block_id"] for block in sequence],
                "order_range": [sequence[0].get("order_range", [0])[0], sequence[-1].get("order_range", [0, 0])[1]],
                "representative_offsets": [offset for block in sequence for offset in block.get("representative_offsets", [])[:1]],
            })
            refs.extend(self.store.evidence_ref_for_block(block, representative=True) for block in sequence)
            refs.extend(
                self.store.evidence_ref_for_event(offset, representative=True)
                for block in sequence
                for offset in block.get("representative_offsets", [])[:1]
            )
        limitations = () if len(selected) == len(sequences) else ("result truncated by limit",)
        return ToolResult(
            tool_name="find_behavior_sequence",
            query={"families": families, "process_key": process_key, "limit": limit},
            matched_count=len(sequences),
            returned_count=len(selected),
            evidence_refs=tuple(refs),
            aggregates={"sequences": rows},
            limitations=limitations,
        )

    def find_file_extension_transitions(
        self,
        process_key: str | None = None,
        scope: str = TRANSITION_SCOPE_ALL,
        min_pair_count: int = 1,
        max_order_gap: int = 250,
        limit: int = DEFAULT_LIMIT,
    ) -> ToolResult:
        """Return replayable write-plus-delete transitions for one process scope."""
        limit = bounded_limit(limit)
        transition = search_file_extension_transitions(
            self.store.events,
            process_key=process_key,
            scope=scope,
            min_pair_count=min_pair_count,
            max_order_gap=max_order_gap,
            group_limit=limit,
        )
        query = {
            "process_key": process_key,
            "scope": transition.scope,
            "min_pair_count": transition.min_pair_count,
            "max_order_gap": transition.max_order_gap,
            "limit": limit,
        }
        if not transition.valid_scope:
            return ToolResult(
                tool_name="find_file_extension_transitions",
                query=query,
                limitations=transition.limitations,
            )
        refs = tuple(
            self.store.evidence_ref_for_event(offset, representative=True)
            for offset in transition.representative_offsets
        )
        events = tuple(self.store.get_event(offset) for offset in transition.representative_offsets)
        return ToolResult(
            tool_name="find_file_extension_transitions",
            query=query,
            matched_count=len(transition.groups),
            returned_count=len(transition.groups),
            evidence_refs=refs,
            events=events,
            aggregates=transition.aggregates(),
            limitations=transition.limitations,
        )

    def find_file_extension_renames(
        self,
        process_key: str | None = None,
        scope: str = TRANSITION_SCOPE_ALL,
        min_rename_count: int = 1,
        min_scope_count: int = 1,
        limit: int = DEFAULT_LIMIT,
    ) -> ToolResult:
        """Return replayable added-extension rename groups for one process scope."""
        limit = bounded_limit(limit)
        rename_search = search_file_extension_renames(
            self.store.events,
            process_key=process_key,
            scope=scope,
            min_rename_count=min_rename_count,
            min_scope_count=min_scope_count,
            group_limit=limit,
        )
        query = {
            "process_key": process_key,
            "scope": rename_search.scope,
            "min_rename_count": rename_search.min_rename_count,
            "min_scope_count": rename_search.min_scope_count,
            "limit": limit,
        }
        if not rename_search.valid_scope:
            return ToolResult(
                tool_name="find_file_extension_renames",
                query=query,
                limitations=rename_search.limitations,
            )
        refs = tuple(
            self.store.evidence_ref_for_event(offset, representative=True)
            for offset in rename_search.representative_offsets
        )
        events = tuple(
            self.store.get_event(offset)
            for offset in rename_search.representative_offsets
        )
        return ToolResult(
            tool_name="find_file_extension_renames",
            query=query,
            matched_count=len(rename_search.groups),
            returned_count=len(rename_search.groups),
            evidence_refs=refs,
            events=events,
            aggregates=rename_search.aggregates(),
            limitations=rename_search.limitations,
        )

    def find_raw_filesystem_metadata_writes(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        """Find successful sample-attributed writes to raw filesystem metadata."""
        limit = bounded_limit(limit)
        search = search_raw_filesystem_metadata_writes(
            enumerate(self.store.events),
            limit=limit,
        )
        limitations = list(search.limitations)
        if search.matched_group_count > len(search.groups):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_raw_filesystem_metadata_writes",
            query={"limit": limit},
            matched_count=search.matched_group_count,
            returned_count=len(search.groups),
            evidence_refs=tuple(
                self.store.evidence_ref_for_event(offset, representative=True)
                for offset in search.representative_offsets
            ),
            events=tuple(
                self.store.get_event(offset)
                for offset in search.representative_offsets
            ),
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def find_ransom_note_artifacts(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        """Find successful note-like file artifacts without treating them as impact proof."""
        limit = bounded_limit(limit)
        search = search_ransom_note_artifacts(
            enumerate(self.store.events),
            limit=limit,
        )
        limitations = list(search.limitations)
        if search.matched_artifact_count > len(search.artifacts):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_ransom_note_artifacts",
            query={"limit": limit},
            matched_count=search.matched_artifact_count,
            returned_count=len(search.artifacts),
            evidence_refs=tuple(
                self.store.evidence_ref_for_event(offset, representative=True)
                for offset in search.representative_offsets
            ),
            events=tuple(
                self.store.get_event(offset)
                for offset in search.representative_offsets
            ),
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def find_run_key_executable_bindings(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        """Find successful executable Run or RunOnce value bindings."""
        limit = bounded_limit(limit)
        search = search_run_key_executable_bindings(
            enumerate(self.store.events),
            limit=limit,
        )
        limitations = list(search.limitations)
        if search.matched_binding_count > len(search.bindings):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_run_key_executable_bindings",
            query={"limit": limit},
            matched_count=search.matched_binding_count,
            returned_count=len(search.bindings),
            evidence_refs=tuple(
                self.store.evidence_ref_for_event(offset, representative=True)
                for offset in search.representative_offsets
            ),
            events=tuple(
                self.store.get_event(offset)
                for offset in search.representative_offsets
            ),
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def neighbor_blocks(self, block_id: str, before: int = 2, after: int = 2) -> ToolResult:
        before = max(0, min(before, 20))
        after = max(0, min(after, 20))
        target_block = self.store.get_block(block_id)
        process_key = target_block.get("process_instance", {}).get("key")
        level = 'micro' if target_block.get('level') == 'micro' else 'macro'
        blocks = [
            block for block in self.store.blocks_payload.get(level+'_blocks', [])
            if block.get("process_instance", {}).get("key") == process_key
        ]
        blocks.sort(key=lambda block: block.get("order_range", [0])[0])
        position = next((idx for idx, block in enumerate(blocks) if block.get("block_id") == block_id), None)
        if position is None:
            return ToolResult(
                tool_name="neighbor_blocks",
                query={"block_id": block_id, "before": before, "after": after},
                limitations=("block has no same-level, same-process timeline",),
            )
        start = max(0, position - before)
        end = min(len(blocks), position + after + 1)
        selected = blocks[start:end]
        refs = tuple(self.store.evidence_ref_for_block(block, representative=(block.get("block_id") == block_id)) for block in selected)
        return ToolResult(
            tool_name="neighbor_blocks",
            query={"block_id": block_id, "before": before, "after": after},
            matched_count=len(selected),
            returned_count=len(selected),
            evidence_refs=refs,
            blocks=tuple(compact_block_for_tool(block) for block in selected),
            limitations=(f"same-process {level}-block timeline",),
        )

    def summarize_operations(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        return summarize_index_values(self.store, "operation_index", "summarize_operations", limit)

    def summarize_processes(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        return summarize_index_values(self.store, "process_name_index", "summarize_processes", limit)

    def summarize_blocks(self, level: str = "macro", limit: int = DEFAULT_LIMIT) -> ToolResult:
        limit = bounded_limit(limit)
        source = self.store.blocks_payload.get("macro_blocks" if level == "macro" else "micro_blocks", [])
        by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for block in source:
            by_kind[block.get("behavior_kind", "")].append(block)
        rows = []
        evidence_refs: list[EvidenceRef] = []
        for kind, blocks in sorted(by_kind.items(), key=lambda item: (-sum(int(block.get("event_count") or 0) for block in item[1]), item[0]))[:limit]:
            event_count = sum(int(block.get("event_count") or 0) for block in blocks)
            representative = max(blocks, key=lambda block: int(block.get("event_count") or 0))
            rows.append({
                "behavior_kind": kind,
                "block_count": len(blocks),
                "event_count": event_count,
                "representative_block_id": representative["block_id"],
            })
            evidence_refs.append(self.store.evidence_ref_for_block(representative, representative=True))
        return ToolResult(
            tool_name="summarize_blocks",
            query={"level": level, "limit": limit},
            matched_count=len(by_kind),
            returned_count=len(rows),
            evidence_refs=tuple(evidence_refs),
            aggregates={"by_behavior_kind": rows},
            limitations=("aggregates include representative blocks for audit",),
        )

    def explain_event_origin(self, offset: int) -> ToolResult:
        event = self.store.get_event(offset)
        ref = self.store.evidence_ref_for_event(offset, representative=True)
        origin = {
            "offset": offset,
            "source_order": event.get("order", {}).get("source"),
            "source_numeric": event.get("order", {}).get("source_numeric"),
            "process_context": event.get("process_context"),
            "time": event.get("time"),
        }
        return ToolResult(
            tool_name="explain_event_origin",
            query={"offset": offset},
            matched_count=1,
            returned_count=1,
            evidence_refs=(ref,),
            aggregates={"origin": origin},
        )


def process_matches(event: dict[str, Any], process_key: str | None = None, pid: int | None = None, process_name: str | None = None) -> bool:
    process = event.get("process_context", {})
    from .catalog import process_instance
    if process_key and process_instance(event)["key"] != process_key:
        return False
    if pid is not None and int(process.get("pid") or 0) != int(pid):
        return False
    if process_name and str(process.get("process_name") or "").casefold() != process_name.casefold():
        return False
    return bool(process_key or pid is not None or process_name)


def is_command_invocation(event: dict[str, Any]) -> bool:
    """Procmon launch records, excluding profiling, threads and image loads."""
    operation = str(event.get("action", {}).get("operation") or "").casefold()
    return operation.replace(" ", "").replace("_", "") in {"processcreate", "processstart"}


def command_text(event: dict[str, Any]) -> str:
    detail = event.get("detail", {})
    action = event.get("action", {})
    target = event.get("target", {})
    process = event.get("process_context", {})
    parsed = detail.get("parsed", {}) if isinstance(detail.get("parsed"), dict) else {}
    pieces = [
        parsed.get("command_line"),
        parsed.get("image_path"),
        parsed.get("path"),
    ]
    if action.get("category") == "process":
        pieces.extend([target.get("normalized_path"), process.get("process_name")])
    return normalize_key(" ".join(str(item) for item in pieces if item))


def process_key(event: dict[str, Any]) -> str:
    process = event.get("process_context", {})
    return str(process.get("process_key") or process.get("key") or "")


def process_pid(event: dict[str, Any]) -> int | None:
    try:
        value = int(event.get("process_context", {}).get("pid") or 0)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def created_process_pid(event: dict[str, Any]) -> int | None:
    parsed = event.get("detail", {}).get("parsed", {})
    if isinstance(parsed, dict):
        for key in ("child_pid", "new_pid", "pid"):
            try:
                value = int(parsed.get(key) or 0)
            except (TypeError, ValueError):
                continue
            if value > 0:
                return value
    raw_detail = str(event.get("detail", {}).get("raw_detail") or "")
    match = re.search(r"(?:^|[,;]\s*)PID:\s*(\d+)\b", raw_detail, flags=re.IGNORECASE)
    return int(match.group(1)) if match else None


def event_operation_counts(events: tuple[dict[str, Any], ...]) -> dict[str, int]:
    return dict(sorted(Counter(str(event.get("action", {}).get("operation") or "") for event in events).items()))


def summarize_index_values(store: EvidenceStore, index_name: str, tool_name: str, limit: int) -> ToolResult:
    limit = bounded_limit(limit)
    index = store.index_maps.get(index_name, {})
    rows = []
    evidence_refs: list[EvidenceRef] = []
    for key, offsets in sorted(index.items(), key=lambda item: (-len(item[1]), item[0]))[:limit]:
        representative_offset = offsets[0]
        rows.append({"key": key, "count": len(offsets), "representative_offset": representative_offset})
        evidence_refs.append(store.evidence_ref_for_event(representative_offset, representative=True))
    return ToolResult(
        tool_name=tool_name,
        query={"index_name": index_name, "limit": limit},
        matched_count=len(index),
        returned_count=len(rows),
        evidence_refs=tuple(evidence_refs),
        aggregates={"items": rows},
        limitations=("aggregates include representative offsets for audit",),
    )


def target_matches(candidate: str, target: str, prefix: bool) -> bool:
    if not target:
        return False
    if candidate == target:
        return True
    if prefix:
        return candidate.startswith(target) or target in candidate
    return False


def compact_block_for_tool(block: dict[str, Any], child_limit: int = 20) -> dict[str, Any]:
    child_ids = list(block.get("child_block_ids", []))
    compact = {
        "block_id": block.get("block_id"),
        "level": block.get("level"),
        "behavior_kind": block.get("behavior_kind"),
        "category": block.get("category"),
        "target_scope": block.get("target_scope"),
        "target_examples": list(block.get("target_examples", []))[:5],
        "event_count": block.get("event_count"),
        "operation_families": list(block.get("operation_families", [])),
        "operation_counts": block.get("operation_counts", {}),
        "result_counts": block.get("result_counts", {}),
        "representative_offsets": list(block.get("representative_offsets", [])),
        "source_offset_ranges": list(block.get("source_offset_ranges", [])),
        "order_range": block.get("order_range"),
        "time_range": block.get("time_range"),
        "process_instance": block.get("process_instance"),
        "limitations": list(block.get("limitations", [])),
        "child_block_count": len(child_ids),
        "child_block_ids_preview": child_ids[:child_limit],
    }
    if len(child_ids) > child_limit:
        compact["child_block_ids_omitted"] = len(child_ids) - child_limit
    if "source_offsets" in block:
        compact["source_offsets_omitted"] = len(block.get("source_offsets", []))
    if 'parent_block_id' in block:
        compact['parent_block_id'] = block['parent_block_id']
    return compact



def compact_event_for_memory(event: dict[str, Any], offset: int | None = None) -> dict[str, Any]:
    from .catalog import process_instance
    order = event.get("order", {})
    action = event.get("action", {})
    target = event.get("target", {})
    process = event.get("process_context", {})
    compact = {
        "offset": offset if offset is not None else order.get("filtered"),
        "source_order": order.get("source"),
        "operation": action.get("operation"),
        "category": action.get("category"),
        "result": action.get("result"),
        "target": target.get("normalized_path") or target.get("path") or "",
        "target_namespace": target.get("namespace"),
        "target_extension": target.get("extension"),
        "process": {
            "process_key": process_instance(event)["key"],
            "node_id": process.get("node_id"),
            "pid": process.get("pid"),
            "process_name": process.get("process_name"),
            "depth": process.get("depth"),
        },
        "time": event.get("time", {}).get("raw_time") or event.get("time", {}).get("timestamp"),
    }
    if str(action.get("operation") or "").casefold().startswith("setrenameinformation"):
        # Procmon's target is the source name. The destination is carried in
        # Detail/FileName, not in target; keep both explicit in agent memory.
        rename: dict[str, Any] = {"source_path": compact["target"]}
        destination = rename_destination_path(event)
        if destination:
            rename["destination_path"] = destination
        replacement = re.search(
            r"\bReplaceIfExists:\s*(True|False)\b",
            str(event.get("detail", {}).get("raw_detail") or ""),
            re.IGNORECASE,
        )
        if replacement:
            rename["replace_if_exists"] = replacement.group(1).casefold() == "true"
        compact["rename"] = rename
    excerpt = compact_detail_excerpt(event.get("detail", {}).get("raw_detail") or "")
    if excerpt:
        compact["detail_excerpt"] = excerpt
    return compact


def compact_detail_excerpt(raw_detail: str) -> str:
    text = re.sub(r"\s+", " ", str(raw_detail or "")).strip()
    if not text:
        return ""
    for marker in (", Environment:", "; Environment:", " Environment:"):
        if marker in text:
            text = text.split(marker, 1)[0]
            break
    return text[:MAX_EVENT_EXCERPT]


def event_search_text(event: dict[str, Any], fields: tuple[str, ...]) -> str:
    pieces = []
    action = event.get("action", {})
    target = event.get("target", {})
    process = event.get("process_context", {})
    detail = event.get("detail", {})
    if "operation" in fields:
        pieces.extend([action.get("operation"), action.get("category"), action.get("result")])
    if "target" in fields:
        pieces.extend([target.get("normalized_path"), target.get("path"), target.get("namespace"), target.get("extension")])
    if "detail" in fields:
        pieces.append(detail.get("raw_detail"))
        pieces.append(json.dumps(detail.get("parsed", {}), ensure_ascii=True, sort_keys=True))
    if "process" in fields:
        pieces.extend([process.get("process_name"), process.get("node_id"), str(process.get("pid") or "")])
    return normalize_key(" ".join(str(item) for item in pieces if item is not None))


def block_kind_counts(blocks_payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for level_name, key in (("macro", "macro_blocks"), ("micro", "micro_blocks")):
        counter: Counter[tuple[str, str]] = Counter()
        for block in blocks_payload.get(key, []):
            counter[(str(block.get("behavior_kind") or ""), str(block.get("category") or ""))] += 1
        out[level_name] = [
            {"behavior_kind": kind, "category": category, "block_count": count}
            for (kind, category), count in sorted(counter.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
        ]
    return out

def expand_block_offsets(block: dict[str, Any]) -> list[int]:
    if "source_offsets" in block:
        return list(block["source_offsets"])
    offsets: list[int] = []
    for start, end in block.get("source_offset_ranges", []):
        offsets.extend(range(int(start), int(end) + 1))
    return offsets


def normalize_key(value: str) -> str:
    return str(value or "").strip().casefold()


def bounded_limit(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIMIT))


def parse_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        value = int(cursor)
    except ValueError:
        return 0
    return max(0, value)

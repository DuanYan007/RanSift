"""Streaming evidence queries with exact match counts and bounded result pages."""
from __future__ import annotations

from .catalog_tools import CatalogEvidenceTools
from .concealed_execution import search_concealed_script_host_fingerprinting
from .autostart_persistence import search_deployed_elevated_autostart_tasks
from .file_transitions import TRANSITION_SCOPE_ALL, search_file_extension_transitions
from .ransom_note_artifacts import search_ransom_note_artifacts
from .raw_filesystem_metadata import search_raw_filesystem_metadata_writes
from .run_key_persistence import search_run_key_executable_bindings
from .evidence import (
    DEFAULT_LIMIT,
    ToolResult,
    bounded_limit,
    command_text,
    is_command_invocation,
    compact_block_for_tool,
    event_operation_counts,
    event_search_text,
    normalize_key,
    parse_cursor,
    process_matches,
    target_matches,
)


class StreamingCatalogEvidenceTools(CatalogEvidenceTools):
    def _stream_matches(self, predicate, start: int, limit: int):
        matched_count = 0
        selected = []
        for offset, event in self.catalog_store.iter_events():
            if not predicate(event):
                continue
            if matched_count >= start and len(selected) < limit:
                selected.append((offset, event))
            matched_count += 1
        next_cursor = str(start + len(selected)) if matched_count > start + len(selected) else None
        return matched_count, selected, next_cursor

    @staticmethod
    def _stream_limitations(truncated: bool = False) -> tuple[str, ...]:
        limitations = [
            "searched the complete normalized trace by streaming; no full trace was materialized",
        ]
        if truncated:
            limitations.append("result truncated; use cursor to continue")
        return tuple(limitations)

    def search_events(self, patterns, fields=None, limit: int = DEFAULT_LIMIT, cursor: str | None = None) -> ToolResult:
        limit = bounded_limit(limit)
        values = [patterns] if isinstance(patterns, str) else list(patterns)
        wanted = [normalize_key(value) for value in values if normalize_key(value)]
        selected_fields = tuple(fields or ("operation", "target", "detail", "process"))
        if not wanted:
            return ToolResult(
                tool_name="search_events",
                query={"patterns": values, "fields": list(selected_fields), "limit": limit, "cursor": cursor},
                limitations=("empty pattern list",),
            )
        matched_count, selected, next_cursor = self._stream_matches(
            lambda event: all(pattern in event_search_text(event, selected_fields) for pattern in wanted),
            parse_cursor(cursor),
            limit,
        )
        return ToolResult(
            tool_name="search_events",
            query={"patterns": values, "fields": list(selected_fields), "limit": limit, "cursor": cursor},
            matched_count=matched_count,
            returned_count=len(selected),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset, _ in selected
            ),
            events=tuple(event for _, event in selected),
            cursor=next_cursor,
            limitations=self._stream_limitations(next_cursor is not None),
        )

    def get_process_timeline(self, process_key=None, pid=None, process_name=None, limit: int = DEFAULT_LIMIT, cursor: str | None = None) -> ToolResult:
        limit = bounded_limit(limit)
        matched_count, selected, next_cursor = self._stream_matches(
            lambda event: process_matches(event, process_key=process_key, pid=pid, process_name=process_name),
            parse_cursor(cursor),
            limit,
        )
        events = tuple(event for _, event in selected)
        return ToolResult(
            tool_name="get_process_timeline",
            query={"process_key": process_key, "pid": pid, "process_name": process_name, "limit": limit, "cursor": cursor},
            matched_count=matched_count,
            returned_count=len(events),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset, _ in selected
            ),
            events=events,
            cursor=next_cursor,
            aggregates={"operation_counts": event_operation_counts(events)},
            limitations=self._stream_limitations(next_cursor is not None),
        )

    def find_target_activity(self, target: str, prefix: bool = True, process_key: str | None = None, limit: int = DEFAULT_LIMIT, cursor: str | None = None) -> ToolResult:
        limit = bounded_limit(limit)
        normalized = normalize_key(target).replace("/", "\\")
        matched_count, selected, next_cursor = self._stream_matches(
            lambda event: (not process_key or process_matches(event, process_key=process_key))
            and target_matches(normalize_key(event.get("target", {}).get("normalized_path") or ""), normalized, prefix),
            parse_cursor(cursor),
            limit,
        )
        events = tuple(event for _, event in selected)
        return ToolResult(
            tool_name="find_target_activity",
            query={"target": target, "prefix": prefix, "process_key": process_key, "limit": limit, "cursor": cursor},
            matched_count=matched_count,
            returned_count=len(events),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset, _ in selected
            ),
            events=events,
            cursor=next_cursor,
            aggregates={"operation_counts": event_operation_counts(events)},
            limitations=self._stream_limitations(next_cursor is not None),
        )

    def find_command_invocations(
        self,
        terms=None,
        process_key=None,
        pid: int | None = None,
        process_name: str | None = None,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        wanted = [
            normalize_key(item)
            for item in ([terms] if isinstance(terms, str) else list(terms or []))
            if normalize_key(item)
        ]

        def matches(event):
            if (process_key or pid is not None or process_name) and not process_matches(
                event,
                process_key=process_key,
                pid=pid,
                process_name=process_name,
            ):
                return False
            text = command_text(event)
            return is_command_invocation(event) and (not wanted or all(term in text for term in wanted))

        matched_count, selected, next_cursor = self._stream_matches(matches, parse_cursor(cursor), limit)
        events = tuple(event for _, event in selected)
        return ToolResult(
            tool_name="find_command_invocations",
            query={"terms": terms, "process_key": process_key, "pid": pid, "process_name": process_name, "limit": limit, "cursor": cursor},
            matched_count=matched_count,
            returned_count=len(events),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset, _ in selected
            ),
            events=events,
            cursor=next_cursor,
            aggregates={"operation_counts": event_operation_counts(events)},
            limitations=self._stream_limitations(next_cursor is not None),
        )

    def find_concealed_script_host_fingerprinting(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        limit = bounded_limit(limit)
        search = search_concealed_script_host_fingerprinting(
            self.catalog_store.iter_events(),
            limit=limit,
        )
        limitations = list(self._stream_limitations(False))
        limitations.extend((
            "decodes bounded Base64 command content without executing it",
            "requires explicit window-concealment semantics and a successful hardware-identifier query",
            "does not establish ransomware impact, encryption, or exfiltration",
        ))
        if search.matched_chain_count > len(search.chains):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_concealed_script_host_fingerprinting",
            query={"limit": limit},
            matched_count=search.matched_chain_count,
            returned_count=len(search.chains),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset in search.representative_offsets
            ),
            events=tuple(
                self.catalog_store.get_event(offset)
                for offset in search.representative_offsets
            ),
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def find_deployed_elevated_autostart_tasks(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        limit = bounded_limit(limit)
        search = search_deployed_elevated_autostart_tasks(
            self.catalog_store.iter_events(),
            limit=limit,
        )
        limitations = list(self._stream_limitations(False))
        limitations.extend((
            "requires a successful executable write in ProgramData or user AppData/Startup",
            "requires paired successful Process Create and Process Start for schtasks /CREATE",
            "requires an ONLOGON or ONSTART task targeting the same executable as SYSTEM at HIGHEST run level",
            "does not establish that the task later ran after reboot or logon",
        ))
        if search.matched_chain_count > len(search.chains):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_deployed_elevated_autostart_tasks",
            query={"limit": limit},
            matched_count=search.matched_chain_count,
            returned_count=len(search.chains),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset in search.representative_offsets
            ),
            events=tuple(
                self.catalog_store.get_event(offset)
                for offset in search.representative_offsets
            ),
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def find_file_extension_transitions(
        self,
        process_key: str | None = None,
        scope: str = TRANSITION_SCOPE_ALL,
        min_pair_count: int = 1,
        max_order_gap: int = 250,
        limit: int = DEFAULT_LIMIT,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        transition = search_file_extension_transitions(
            self.catalog_store.iter_events(),
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
        limitations = list(self._stream_limitations(False)) + list(transition.limitations)
        if not transition.valid_scope:
            return ToolResult(
                tool_name="find_file_extension_transitions",
                query=query,
                limitations=tuple(limitations),
            )
        return ToolResult(
            tool_name="find_file_extension_transitions",
            query=query,
            matched_count=len(transition.groups),
            returned_count=len(transition.groups),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset in transition.representative_offsets
            ),
            events=tuple(
                self.catalog_store.get_event(offset)
                for offset in transition.representative_offsets
            ),
            aggregates=transition.aggregates(),
            limitations=tuple(limitations),
        )

    def find_raw_filesystem_metadata_writes(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        limit = bounded_limit(limit)
        search = search_raw_filesystem_metadata_writes(self.catalog_store.iter_events(), limit=limit)
        limitations = list(self._stream_limitations(False)) + list(search.limitations)
        if search.matched_group_count > len(search.groups):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_raw_filesystem_metadata_writes",
            query={"limit": limit},
            matched_count=search.matched_group_count,
            returned_count=len(search.groups),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset in search.representative_offsets
            ),
            events=tuple(
                self.catalog_store.get_event(offset)
                for offset in search.representative_offsets
            ),
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def find_ransom_note_artifacts(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        limit = bounded_limit(limit)
        search = search_ransom_note_artifacts(self.catalog_store.iter_events(), limit=limit)
        limitations = list(self._stream_limitations(False)) + list(search.limitations)
        if search.matched_artifact_count > len(search.artifacts):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_ransom_note_artifacts",
            query={"limit": limit},
            matched_count=search.matched_artifact_count,
            returned_count=len(search.artifacts),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset in search.representative_offsets
            ),
            events=tuple(
                self.catalog_store.get_event(offset)
                for offset in search.representative_offsets
            ),
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def find_run_key_executable_bindings(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        limit = bounded_limit(limit)
        search = search_run_key_executable_bindings(self.catalog_store.iter_events(), limit=limit)
        limitations = list(self._stream_limitations(False)) + list(search.limitations)
        if search.matched_binding_count > len(search.bindings):
            limitations.append("result truncated by limit")
        return ToolResult(
            tool_name="find_run_key_executable_bindings",
            query={"limit": limit},
            matched_count=search.matched_binding_count,
            returned_count=len(search.bindings),
            evidence_refs=tuple(
                self.catalog_store.evidence_ref_for_event(offset, representative=True)
                for offset in search.representative_offsets
            ),
            events=tuple(
                self.catalog_store.get_event(offset)
                for offset in search.representative_offsets
            ),
            aggregates=search.aggregates(),
            limitations=tuple(limitations),
        )

    def trace_target(self, target: str, prefix: bool = True, limit: int = DEFAULT_LIMIT) -> ToolResult:
        limit = bounded_limit(limit)
        normalized = normalize_key(target).replace("/", "\\")
        matched_count, selected, _ = self._stream_matches(
            lambda event: target_matches(
                normalize_key(event.get("target", {}).get("normalized_path") or ""),
                normalized,
                prefix,
            ),
            0,
            limit,
        )
        matched_blocks = []
        block_level = 'macro_blocks' if self.catalog_store.catalog.get('hierarchical_fragments') else 'phase_blocks'
        for block in self.catalog_store.blocks_payload[block_level]:
            candidates = [normalize_key(block.get("target_scope") or "")]
            candidates.extend(normalize_key(item) for item in block.get("target_examples", []))
            if any(target_matches(candidate, normalized, prefix) for candidate in candidates):
                matched_blocks.append(block)
        selected_blocks = matched_blocks[:limit]
        refs = [
            self.catalog_store.evidence_ref_for_event(offset, representative=True)
            for offset, _ in selected
        ]
        refs.extend(
            self.catalog_store.evidence_ref_for_block(block, representative=True)
            for block in selected_blocks
        )
        limitations = list(
            self._stream_limitations(
                matched_count > len(selected) or len(matched_blocks) > len(selected_blocks)
            )
        )
        limitations.append("block target examples are bounded catalog summaries")
        return ToolResult(
            tool_name="trace_target",
            query={"target": target, "prefix": prefix, "limit": limit},
            matched_count=matched_count + len(matched_blocks),
            returned_count=len(selected) + len(selected_blocks),
            evidence_refs=tuple(refs),
            events=tuple(event for _, event in selected),
            blocks=tuple(compact_block_for_tool(block) for block in selected_blocks),
            aggregates={"matched_event_count": matched_count, "matched_block_count": len(matched_blocks)},
            limitations=tuple(limitations),
        )

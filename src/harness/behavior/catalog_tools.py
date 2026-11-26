"""Evidence-tool adaptations for catalog-backed traces."""
from __future__ import annotations

from dataclasses import replace

from .catalog import phase_target_scope, process_instance
from .blocks import classify_behavior_kind
from .classification import classify_operation_family
from .catalog_store import CatalogEvidenceStore
from .evidence import (
    DEFAULT_LIMIT,
    EvidenceTools,
    ToolResult,
    bounded_limit,
    compact_block_for_tool,
    normalize_key,
    parse_cursor,
)


class CatalogEvidenceTools(EvidenceTools):
    """Keep the established tool contract while exposing catalog limitations."""

    def __init__(self, store: CatalogEvidenceStore) -> None:
        super().__init__(store)

    @property
    def catalog_store(self) -> CatalogEvidenceStore:
        return self.store  # type: ignore[return-value]

    def list_events(
        self,
        index_name: str,
        key: str,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
    ) -> ToolResult:
        limit = bounded_limit(limit)
        normalized_key = normalize_key(key)
        if index_name not in self.catalog_store.index_maps:
            return ToolResult(
                tool_name="list_events",
                query={"index_name": index_name, "key": key, "limit": limit, "cursor": cursor},
                limitations=(f"unknown index: {index_name}",),
            )
        start = parse_cursor(cursor)
        matched_count, selected_offsets, next_cursor, limitations = self.catalog_store.index_event_page(
            index_name,
            normalized_key,
            start,
            limit,
        )
        refs = tuple(
            self.catalog_store.evidence_ref_for_event(offset, representative=True)
            for offset in selected_offsets
        )
        events = tuple(self.catalog_store.get_event(offset) for offset in selected_offsets)
        all_limitations = list(limitations)
        if next_cursor is not None:
            all_limitations.append("result truncated; use cursor to continue through retained representatives")
        return ToolResult(
            tool_name="list_events",
            query={"index_name": index_name, "key": key, "limit": limit, "cursor": cursor},
            matched_count=matched_count,
            returned_count=len(selected_offsets),
            evidence_refs=refs,
            events=events,
            cursor=next_cursor,
            limitations=tuple(all_limitations),
        )

    def list_index_keys(self, index_name: str, pattern: str | None = None, limit: int = DEFAULT_LIMIT, cursor: str | None = None) -> ToolResult:
        result = super().list_index_keys(index_name, pattern=pattern, limit=limit, cursor=cursor)
        return replace(
            result,
            limitations=tuple(dict.fromkeys(result.limitations + self.catalog_store.index_limitations(index_name))),
        )

    def get_block_events(self, block_id: str, representative_only: bool = True, limit: int = DEFAULT_LIMIT) -> ToolResult:
        block = self.catalog_store.get_block(block_id)
        if block.get('level') in ('micro', 'macro'):
            return super().get_block_events(block_id, representative_only=representative_only, limit=limit)
        if representative_only:
            result = super().get_block_events(block_id, representative_only=True, limit=limit)
            return replace(
                result,
                limitations=tuple(dict.fromkeys(result.limitations + (
                    "phase blocks retain bounded representative offsets",
                ))),
            )
        limit = bounded_limit(limit)
        block = self.catalog_store.get_block(block_id)
        if block.get("schema_version") == "behavior-phase-block-v1":
            lower, upper = (int(value) for value in block["order_range"])
            wanted_process = str((block.get("process_instance") or {}).get("key") or "")
            selected = []
            matched_count = 0
            for offset, event in self.catalog_store.iter_events(start=lower, stop=upper + 1):
                action = event.get("action") or {}
                family = str(action.get("operation_family") or "").casefold()
                if not family:
                    family = classify_operation_family(str(action.get("operation") or ""))
                if str(process_instance(event)["key"]) != wanted_process:
                    continue
                if classify_behavior_kind(family, str(action.get("category") or "other")) != block["behavior_kind"]:
                    continue
                if phase_target_scope(event, family) != block["target_scope"]:
                    continue
                matched_count += 1
                if len(selected) < limit:
                    selected.append((offset, event))
            if matched_count != int(block["event_count"]):
                raise ValueError("Reconstructed phase membership differs from the sealed block count")
            limitations = ["phase membership reconstructed from the source trace using process, behavior kind, scope, and order bounds"]
            if matched_count > len(selected):
                limitations.append("result truncated by limit")
            return ToolResult(
                tool_name="get_block_events",
                query={"block_id": block_id, "representative_only": False, "limit": limit},
                matched_count=matched_count,
                returned_count=len(selected),
                evidence_refs=tuple(self.catalog_store.evidence_ref_for_event(offset) for offset, _ in selected),
                events=tuple(event for _, event in selected),
                blocks=(compact_block_for_tool(block),),
                limitations=tuple(limitations),
            )
        offsets = [int(offset) for offset in block.get("representative_offsets") or []][:limit]
        refs = tuple(
            self.catalog_store.evidence_ref_for_event(offset, representative=True)
            for offset in offsets
        )
        return ToolResult(
            tool_name="get_block_events",
            query={"block_id": block_id, "representative_only": False, "limit": limit},
            matched_count=int(block.get("event_count") or 0),
            returned_count=len(offsets),
            evidence_refs=refs,
            events=tuple(self.catalog_store.get_event(offset) for offset in offsets),
            blocks=(compact_block_for_tool(block),),
            limitations=(
                "phase block membership is compressed; only bounded representative events are available",
            ),
        )

    def summarize_operations(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        result = super().summarize_operations(limit=limit)
        return replace(
            result,
            limitations=tuple(dict.fromkeys(result.limitations + self.catalog_store.index_limitations("operation_index"))),
        )

    def summarize_processes(self, limit: int = DEFAULT_LIMIT) -> ToolResult:
        result = super().summarize_processes(limit=limit)
        return replace(
            result,
            limitations=tuple(dict.fromkeys(result.limitations + self.catalog_store.index_limitations("process_name_index"))),
        )

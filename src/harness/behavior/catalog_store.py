"""Read-only catalog access with lazy event iteration and checkpoint-based retrieval."""
from __future__ import annotations

import json
import hashlib
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from .evidence import EvidenceRef


class _CatalogEvents(Sequence[dict[str, Any]]):
    """Lazy sequence interface for evidence-tool iteration."""

    def __init__(self, store: "CatalogEvidenceStore") -> None:
        self.store = store

    def __len__(self) -> int:
        return self.store.event_count

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for _, event in self.store.iter_events():
            yield event

    def __getitem__(self, index: int | slice) -> dict[str, Any] | list[dict[str, Any]]:
        if isinstance(index, slice):
            start, stop, step = index.indices(len(self))
            if step != 1:
                return [self.store.get_event(offset) for offset in range(start, stop, step)]
            return [event for _, event in self.store.iter_events(start=start, stop=stop)]
        offset = int(index)
        if offset < 0:
            offset += len(self)
        return self.store.get_event(offset)


class _RepresentativeOffsets(Sequence[int]):
    """Exact match count plus bounded offsets retained by a catalog index."""

    def __init__(self, event_count: int, offsets: list[int]) -> None:
        self.event_count = int(event_count)
        self.offsets = tuple(sorted(dict.fromkeys(int(offset) for offset in offsets)))

    def __len__(self) -> int:
        return self.event_count

    def __iter__(self) -> Iterator[int]:
        return iter(self.offsets)

    def __getitem__(self, index: int | slice) -> int | tuple[int, ...]:
        return self.offsets[index]


class CatalogEvidenceStore:
    """Read-only, memory-bounded view over one sealed catalog record."""

    def __init__(
        self,
        trace_path: str | Path,
        catalog_path: str | Path,
        phase_blocks_path: str | Path,
        checkpoints_path: str | Path,
    ) -> None:
        self.trace_path = Path(trace_path)
        self.catalog_path = Path(catalog_path)
        self.blocks_path = Path(phase_blocks_path)
        self.checkpoints_path = Path(checkpoints_path)
        self._catalog: dict[str, Any] | None = None
        self._checkpoints: dict[str, Any] | None = None
        self._index_maps: dict[str, dict[str, _RepresentativeOffsets]] | None = None
        self._blocks_payload: dict[str, Any] | None = None
        self._blocks_by_id: dict[str, dict[str, Any]] | None = None
        self._events = _CatalogEvents(self)

    @property
    def catalog_mode(self) -> bool:
        return True

    @property
    def catalog(self) -> dict[str, Any]:
        if self._catalog is None:
            self._catalog = load_json_object(self.catalog_path)
        return self._catalog

    @property
    def checkpoints(self) -> dict[str, Any]:
        if self._checkpoints is None:
            self._checkpoints = load_json_object(self.checkpoints_path)
        return self._checkpoints

    @property
    def events(self) -> _CatalogEvents:
        return self._events

    @property
    def event_count(self) -> int:
        return int(self.catalog.get("event_count") or 0)

    @property
    def index_maps(self) -> dict[str, dict[str, _RepresentativeOffsets]]:
        if self._index_maps is None:
            maps: dict[str, dict[str, _RepresentativeOffsets]] = {}
            for name, payload in (self.catalog.get("indexes") or {}).items():
                if not isinstance(payload, dict):
                    continue
                entries: dict[str, _RepresentativeOffsets] = {}
                for item in payload.get("entries") or []:
                    if not isinstance(item, dict):
                        continue
                    key = normalize_key(item.get("key"))
                    if not key:
                        continue
                    entries[key] = _RepresentativeOffsets(
                        int(item.get("event_count") or 0),
                        list(item.get("representative_offsets") or []),
                    )
                maps[str(name)] = entries
            self._index_maps = maps
        return self._index_maps

    @property
    def blocks_payload(self) -> dict[str, Any]:
        if self._blocks_payload is None:
            blocks = load_jsonl(self.blocks_path)
            hierarchy = self.catalog.get('hierarchical_fragments')
            if hierarchy is None:
                # Older catalogs expose phase fragments through both selectors.
                self._blocks_payload = {'phase_blocks': blocks, 'micro_blocks': blocks, 'macro_blocks': blocks}
            else:
                self._blocks_payload = self._load_hierarchy(hierarchy, blocks)
        return self._blocks_payload

    def _load_hierarchy(self, hierarchy, phases):
        from .hierarchical_fragments import SCHEMA
        if hierarchy.get('schema_version') != SCHEMA or hierarchy.get('event_count') != self.event_count:
            raise ValueError('Invalid hierarchical fragment catalog')
        payload = {'phase_blocks': phases}
        for level in ('micro', 'macro'):
            meta = hierarchy[level]
            name = meta['file']
            if not isinstance(name, str) or not name or Path(name).name != name:
                raise ValueError('Fragment artifact must be a sibling file')
            path = self.catalog_path.parent / name
            if path.is_symlink() or not path.is_file():
                raise ValueError('Fragment artifact is missing or symlinked')
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024*1024), b''):
                    digest.update(chunk)
            if digest.hexdigest() != meta['sha256']:
                raise ValueError('Fragment artifact digest mismatch')
            rows = load_jsonl(path)
            if (len(rows) != meta['count'] or any(row.get('level') != level or row.get('schema_version') != SCHEMA for row in rows)
                    or sum(row['event_count'] for row in rows) != self.event_count):
                raise ValueError('Fragment level or event count mismatch')
            payload[level+'_blocks'] = rows
        micro = {row['block_id']: row for row in payload['micro_blocks']}
        macro = {row['block_id']: row for row in payload['macro_blocks']}
        if (len(micro) != len(payload['micro_blocks']) or len(macro) != len(payload['macro_blocks'])
                or set(micro) & set(macro)):
            raise ValueError('Fragment IDs must be unique across both levels')
        children_seen = set()
        for parent in macro.values():
            children = parent['child_block_ids']
            if not children or len(set(children)) != len(children):
                raise ValueError('Invalid macro child references')
            total = 0
            for child_id in children:
                if child_id not in micro or child_id in children_seen:
                    raise ValueError('Missing or multiply assigned micro fragment')
                child = micro[child_id]
                if child.get('parent_block_id') != parent['block_id'] or child['process_instance']['key'] != parent['process_instance']['key']:
                    raise ValueError('Fragment parent or process mismatch')
                children_seen.add(child_id)
                total += child['event_count']
            if total != parent['event_count']:
                raise ValueError('Macro count differs from its children')
        if children_seen != set(micro):
            raise ValueError('Micro fragment lacks a macro parent')
        return payload

    @property
    def blocks_by_id(self) -> dict[str, dict[str, Any]]:
        if self._blocks_by_id is None:
            self._blocks_by_id = {
                str(block["block_id"]): block
                for level in ("phase_blocks", "micro_blocks", "macro_blocks")
                for block in self.blocks_payload[level]
                if block.get("block_id")
            }
        return self._blocks_by_id

    def get_event(self, offset: int) -> dict[str, Any]:
        if offset < 0 or offset >= self.event_count:
            raise IndexError(f"event offset out of range: {offset}")
        for event_offset, event in self.iter_events(start=offset, stop=offset + 1):
            if event_offset == offset:
                return event
        raise IndexError(f"event offset could not be resolved: {offset}")

    def iter_events(self, start: int = 0, stop: int | None = None) -> Iterator[tuple[int, dict[str, Any]]]:
        lower = max(0, int(start))
        upper = self.event_count if stop is None else min(self.event_count, max(lower, int(stop)))
        checkpoint_offset, byte_offset = self._checkpoint_before(lower)
        with self.trace_path.open("rb") as stream:
            stream.seek(byte_offset)
            while True:
                line = stream.readline()
                if not line:
                    return
                if not line.strip():
                    continue
                event = json.loads(line)
                offset = event_offset(event)
                if offset < checkpoint_offset:
                    raise ValueError("trace offsets regressed after a checkpoint")
                if offset < lower:
                    continue
                if offset >= upper:
                    return
                yield offset, event

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
            source_order=(event.get("order") or {}).get("source"),
            process_instance=event.get("process_context"),
            representative=representative,
        )

    def evidence_ref_for_block(self, block: dict[str, Any], representative: bool = False) -> EvidenceRef:
        return EvidenceRef(
            ref_id=f"block:{block['block_id']}",
            kind="block",
            block_id=str(block["block_id"]),
            process_instance=block.get("process_instance"),
            representative=representative,
        )

    def index_limitations(self, index_name: str) -> tuple[str, ...]:
        payload = (self.catalog.get("indexes") or {}).get(index_name)
        if not isinstance(payload, dict):
            return ()
        limitations = [
            "catalog index stores bounded representative offsets; returned events are navigational rather than exhaustive",
        ]
        if int(payload.get("omitted_event_observations") or 0) > 0:
            limitations.append(
                "catalog key-cardinality limit omitted observations, so this index is not exhaustive for unseen keys"
            )
        return tuple(limitations)

    def index_event_page(
        self,
        index_name: str,
        key: str,
        start: int,
        limit: int,
    ) -> tuple[int, tuple[int, ...], str | None, tuple[str, ...]]:
        entries = self.index_maps.get(index_name)
        if entries is None:
            return 0, (), None, ()
        offsets = entries.get(normalize_key(key))
        if offsets is None:
            return 0, (), None, self.index_limitations(index_name)
        selected = tuple(offsets.offsets[start:start + limit])
        next_cursor = str(start + len(selected)) if start + len(selected) < len(offsets.offsets) else None
        return len(offsets), selected, next_cursor, self.index_limitations(index_name)

    def query_surface(self, limit: int = 40) -> dict[str, Any]:
        compact_indexes = {}
        for name in ("operation_index", "process_name_index", "category_index", "namespace_index", "extension_index", "result_index"):
            entries = self.index_maps.get(name, {})
            compact_indexes[name] = [
                {"key": key, "count": len(offsets)}
                for key, offsets in sorted(entries.items(), key=lambda item: (-len(item[1]), item[0]))[:limit]
            ]
        levels = ('micro', 'macro') if self.catalog.get('hierarchical_fragments') else ('phase',)
        block_kinds = {}
        for level in levels:
            by_kind: dict[str, int] = {}
            for block in self.blocks_payload[level+'_blocks']:
                kind = str(block.get('behavior_kind') or '')
                by_kind[kind] = by_kind.get(kind, 0) + 1
            block_kinds[level] = [{'kind': kind, 'count': count}
                                 for kind, count in sorted(by_kind.items(), key=lambda item: (-item[1], item[0]))]
        return {
            "index_names": sorted(self.index_maps),
            "index_key_counts": {name: len(entries) for name, entries in self.index_maps.items()},
            "common_index_keys": compact_indexes,
            "block_kinds": block_kinds,
            "catalog_mode": True,
            "query_rules": (
                "list_events keys are normalized to lowercase.",
                "Catalog index results are representative navigation, not exhaustive event lists.",
                "Use search_events for arbitrary substrings over the complete streamed trace.",
            ),
        }

    def _checkpoint_before(self, target_offset: int) -> tuple[int, int]:
        selected: tuple[int, int] | None = None
        for row in self.checkpoints.get("checkpoints") or []:
            if not isinstance(row, list) or len(row) != 2:
                continue
            try:
                offset, byte_offset = int(row[0]), int(row[1])
            except (TypeError, ValueError):
                continue
            if offset <= target_offset and (selected is None or offset > selected[0]):
                selected = (offset, byte_offset)
        if selected is None:
            raise ValueError(f"no checkpoint before event offset {target_offset}")
        return selected


def event_offset(event: dict[str, Any]) -> int:
    try:
        return int((event.get("order") or {}).get("filtered"))
    except (TypeError, ValueError) as exc:
        raise ValueError("trace event has no integer filtered offset") from exc


def normalize_key(value: Any) -> str:
    return str(value or "").strip().casefold()


def load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError(f"expected JSON object row: {path}")
                rows.append(row)
    return rows

"""Slice-independent process fact extraction."""
from __future__ import annotations

import csv
import re
from collections.abc import Iterable, Iterator
from pathlib import Path, PureWindowsPath

from .events import EventRecord, PROCESS_CREATE_OPS, extract_child_pid, extract_parent_pid, normalize_event
from .models import ProcessFact, SliceEnvelope, SliceMeta

PROCESS_EXIT_OPS = {"process exit", "process terminate"}


def _basename(path: str) -> str:
    if not path:
        return ""
    clean = path.strip('"')
    try:
        return PureWindowsPath(clean).name
    except Exception:
        return clean.rsplit("\\", 1)[-1]


def _extract_image(detail: str) -> str:
    match = re.search(r"Image:\s*([^,]+)", detail or "", flags=re.IGNORECASE)
    return _basename(match.group(1)) if match else ""


class EventCountSlicer:
    """Creates stable raw slices over event order.

    The slicer only emits metadata and normalized events. It does not decide
    which processes belong to the sample tree.
    """

    def __init__(self, slice_size: int):
        if slice_size <= 0:
            raise ValueError("slice_size must be positive")
        self.slice_size = slice_size

    def iter_slices(self, rows: Iterable[dict], source_ref: str = "") -> Iterator[tuple[SliceMeta, list[EventRecord]]]:
        events: list[EventRecord] = []
        start_index = 0
        slice_index = 0
        total_index = 0
        for row in rows:
            event = normalize_event(row, total_index)
            if not events:
                start_index = total_index
            events.append(event)
            total_index += 1
            if len(events) >= self.slice_size:
                yield self._make_meta(slice_index, start_index, total_index - 1, events, source_ref), events
                slice_index += 1
                events = []
        if events:
            yield self._make_meta(slice_index, start_index, total_index - 1, events, source_ref), events

    def _make_meta(
        self,
        slice_index: int,
        start: int,
        end: int,
        events: list[EventRecord],
        source_ref: str,
    ) -> SliceMeta:
        return SliceMeta(
            slice_id=f"slice_{slice_index:06d}",
            strategy="event_count",
            ordinal=slice_index,
            event_start=start,
            event_end=end,
            time_start=events[0].timestamp if events else None,
            time_end=events[-1].timestamp if events else None,
            event_count=len(events),
            source_ref=source_ref,
        )


class SliceFactExtractor:
    """Converts a raw slice into facts with a stable schema."""

    def extract(self, meta: SliceMeta, events: list[EventRecord]) -> SliceEnvelope:
        facts: list[ProcessFact] = []
        for offset, event in enumerate(events):
            event_index = meta.event_start + offset
            operation = event.operation.lower()
            if operation in PROCESS_CREATE_OPS:
                facts.extend(self._spawn_facts(meta, event, event_index))
            if event.pid:
                facts.append(ProcessFact(
                    fact_id=f"fact_{event_index:08d}_observe",
                    kind="observe",
                    slice_id=meta.slice_id,
                    event_index=event_index,
                    time=event.timestamp,
                    pid=event.pid,
                    process_name=event.process_name,
                    operation=event.operation,
                    result=event.result,
                    source_event_ids=(event.event_id,),
                    source="event_observation",
                ))
            if event.pid and operation in PROCESS_EXIT_OPS:
                facts.append(ProcessFact(
                    fact_id=f"fact_{event_index:08d}_exit",
                    kind="exit",
                    slice_id=meta.slice_id,
                    event_index=event_index,
                    time=event.timestamp,
                    pid=event.pid,
                    process_name=event.process_name,
                    operation=event.operation,
                    result=event.result,
                    source_event_ids=(event.event_id,),
                    source="process_exit",
                ))
        return SliceEnvelope(meta=meta, facts=tuple(sorted(facts, key=lambda fact: fact.sort_key())))

    def _spawn_facts(self, meta: SliceMeta, event: EventRecord, event_index: int) -> list[ProcessFact]:
        facts: list[ProcessFact] = []
        parent_pid = extract_parent_pid(event.detail)
        if parent_pid and event.pid:
            facts.append(ProcessFact(
                fact_id=f"fact_{event_index:08d}_spawn_start",
                kind="spawn",
                slice_id=meta.slice_id,
                event_index=event_index,
                time=event.timestamp,
                pid=event.pid,
                process_name=event.process_name,
                operation=event.operation,
                parent_pid=parent_pid,
                child_pid=event.pid,
                child_name=event.process_name,
                child_path=event.path,
                result=event.result,
                source_event_ids=(event.event_id,),
                source="process_start_parent_pid",
            ))
        child_pid = extract_child_pid(event.detail)
        if child_pid:
            child_name = _basename(event.path) or _extract_image(event.detail)
            facts.append(ProcessFact(
                fact_id=f"fact_{event_index:08d}_spawn_create",
                kind="spawn",
                slice_id=meta.slice_id,
                event_index=event_index,
                time=event.timestamp,
                pid=event.pid,
                process_name=event.process_name,
                operation=event.operation,
                parent_pid=event.pid,
                child_pid=child_pid,
                child_name=child_name,
                child_path=event.path,
                result=event.result,
                source_event_ids=(event.event_id,),
                source="process_create_child_pid",
            ))
        return facts


def iter_csv_slice_envelopes(path: str | Path, slice_size: int) -> Iterator[SliceEnvelope]:
    """Streams slice envelopes from a CSV log."""

    p = Path(path)
    slicer = EventCountSlicer(slice_size)
    extractor = SliceFactExtractor()
    with p.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for meta, events in slicer.iter_slices(reader, source_ref=str(p)):
            yield extractor.extract(meta, events)

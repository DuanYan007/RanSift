"""Reduction of duplicate process-spawn facts."""
from __future__ import annotations

from collections.abc import Iterable, Iterator

from .models import ProcessFact, SliceEnvelope


class SpawnReducer:
    """Merges Procmon Create/Start observations for the same process launch.

    Procmon may expose one launch as a parent-side Process Create event and a
    child-side Process Start event. The reducer keeps one launch fact, but it
    preserves parent-PID disagreement instead of silently choosing one edge.
    """

    def __init__(self, window_seconds: float = 0.5):
        self.window_seconds = window_seconds

    def reduce(self, envelopes: Iterable[SliceEnvelope]) -> Iterator[ProcessFact]:
        yield from self.reduce_facts(fact for envelope in envelopes for fact in envelope.facts)

    def reduce_facts(self, facts: Iterable[ProcessFact]) -> Iterator[ProcessFact]:
        pending: ProcessFact | None = None
        for fact in facts:
            if pending is not None:
                if fact.kind == "spawn" and self._same_spawn(pending, fact):
                    pending = self._merge(pending, fact)
                    continue
                if self._must_flush_before(pending, fact):
                    yield pending
                    pending = None
            if fact.kind == "spawn":
                pending = fact
            else:
                yield fact
        if pending is not None:
            yield pending

    def _same_spawn(self, left: ProcessFact, right: ProcessFact) -> bool:
        if left.kind != "spawn" or right.kind != "spawn":
            return False
        if abs(right.time - left.time) > self.window_seconds:
            return False
        if left.child_pid != right.child_pid:
            return False
        if left.parent_pid == right.parent_pid:
            return True
        left_name = left.child_name.lower()
        right_name = right.child_name.lower()
        return bool(left_name and right_name and left_name == right_name)

    def _must_flush_before(self, pending: ProcessFact, fact: ProcessFact) -> bool:
        if fact.time - pending.time > self.window_seconds:
            return True
        if fact.kind in {"observe", "exit"} and fact.pid == pending.child_pid and fact.time >= pending.time:
            return True
        return False

    @staticmethod
    def _merge(left: ProcessFact, right: ProcessFact) -> ProcessFact:
        source_event_ids = tuple(dict.fromkeys((*left.source_event_ids, *right.source_event_ids)))
        source = "+".join(dict.fromkeys((left.source, right.source)))
        parent_candidates = _parent_candidates(left, right)
        parent_conflict = left.parent_pid_conflict or right.parent_pid_conflict or len(parent_candidates) > 1
        result = left.result or right.result
        if left.result and right.result and left.result != right.result:
            result = f"{left.result}+{right.result}"
        return ProcessFact(
            fact_id=left.fact_id,
            kind="spawn",
            slice_id=left.slice_id,
            event_index=min(left.event_index, right.event_index),
            time=min(left.time, right.time),
            pid=left.pid or right.pid,
            process_name=left.process_name or right.process_name,
            operation=left.operation or right.operation,
            parent_pid=left.parent_pid or right.parent_pid,
            child_pid=left.child_pid or right.child_pid,
            child_name=left.child_name or right.child_name,
            child_path=left.child_path or right.child_path,
            result=result,
            parent_pid_conflict=parent_conflict,
            parent_pid_candidates=parent_candidates if parent_conflict else (),
            source_event_ids=source_event_ids,
            source=source,
        )


def _parent_candidates(left: ProcessFact, right: ProcessFact) -> tuple[int, ...]:
    candidates: list[int] = []
    for fact in (left, right):
        if fact.parent_pid:
            candidates.append(fact.parent_pid)
        candidates.extend(pid for pid in fact.parent_pid_candidates if pid)
    return tuple(dict.fromkeys(candidates))

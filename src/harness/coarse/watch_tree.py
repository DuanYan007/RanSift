"""Watch-set driven rooted process tree construction."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any

from .fact_stream import iter_csv_slice_envelopes
from .models import NodeProcess, ProcessFact, ProcessTreeNode, ProcessTreeOutput, SliceEnvelope, TreeDiagnostic
from .spawn_reducer import SpawnReducer

SUCCESS_RESULTS = {"", "success"}
TOP_ROOT_CANDIDATE_LIMIT = 8


@dataclass(frozen=True)
class RootCandidate:
    fact: ProcessFact
    pid: int
    process_name: str
    score: int
    reason: str

    def sort_key(self) -> tuple[int, float, int, str]:
        return (-self.score, self.fact.time, self.fact.event_index, self.fact.fact_id)

    def confidence(self) -> str:
        if self.score >= 900:
            return "high"
        if self.score >= 800:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "score": self.score,
            "confidence": self.confidence(),
            "reason": self.reason,
            "fact_id": self.fact.fact_id,
            "event_index": self.fact.event_index,
            "time": self.fact.time,
            "operation": self.fact.operation,
            "result": self.fact.result,
            "parent_pid": self.fact.parent_pid,
            "child_path": self.fact.child_path,
        }


class WatchTreeBuilder:
    """Builds a sample process tree by expanding only watched descendants."""

    def __init__(
        self,
        trace_id: str,
        sample_hint: str = "",
        root_pid: int | None = None,
        reducer: SpawnReducer | None = None,
    ):
        self.trace_id = trace_id
        self.sample_hint = sample_hint
        self.root_pid = root_pid
        self.reducer = reducer or SpawnReducer()

    def build(self, envelope_factory: Callable[[], Iterable[SliceEnvelope]]) -> ProcessTreeOutput:
        return self.build_from_fact_factory(lambda: _facts_from_envelopes(envelope_factory()))

    def build_from_envelopes(self, envelopes: Iterable[SliceEnvelope]) -> ProcessTreeOutput:
        # Compatibility path for callers that only have a one-shot iterable.
        # The task graph uses build_from_fact_factory() over a fact JSONL file.
        cached_facts = tuple(_facts_from_envelopes(envelopes))
        return self.build_from_fact_factory(lambda: iter(cached_facts))

    def build_from_facts(self, facts: Iterable[ProcessFact]) -> ProcessTreeOutput:
        cached_facts = tuple(facts)
        return self.build_from_fact_factory(lambda: iter(cached_facts))

    def build_from_fact_factory(self, fact_factory: Callable[[], Iterable[ProcessFact]]) -> ProcessTreeOutput:
        reduced_factory = lambda: self.reducer.reduce_facts(fact_factory())
        root, root_diags, attribution = self._discover_root(reduced_factory())
        if root is None:
            return ProcessTreeOutput(
                trace_id=self.trace_id,
                root_nodes=[],
                node_index={},
                diagnostics=[TreeDiagnostic("root_not_found", "sample root process could not be resolved"), *root_diags],
                slice_count=int(attribution.get("scanned_slice_count") or 0),
                fact_count=int(attribution.get("scanned_fact_count") or 0),
                ignored_fact_count=0,
                attribution=attribution,
            )
        materializer = _TreeMaterializer(self.trace_id, root, root_diags, attribution)
        return materializer.build(reduced_factory())

    def tree_hash(self, tree: ProcessTreeOutput) -> str:
        payload = json.dumps(tree.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _discover_root(self, facts: Iterable[ProcessFact]) -> tuple[RootCandidate | None, list[TreeDiagnostic], dict[str, Any]]:
        candidates: list[RootCandidate] = []
        fact_count = 0
        slice_ids: set[str] = set()
        for fact in facts:
            fact_count += 1
            slice_ids.add(fact.slice_id)
            candidate = self._candidate_from_fact(fact)
            if candidate is None or candidate.score <= 0:
                continue
            candidates.append(candidate)
        candidates = dedupe_root_candidates(candidates)
        if not candidates:
            attribution = {
                "schema_version": "coarse-attribution-v1",
                "status": "root_absent",
                "confidence": "absent",
                "selected_root": None,
                "candidate_count": 0,
                "root_candidates": [],
                "scanned_fact_count": fact_count,
                "scanned_slice_count": len(slice_ids),
            }
            return None, [], attribution

        selected = candidates[0]
        top = candidates[:TOP_ROOT_CANDIDATE_LIMIT]
        confidence = selected.confidence()
        diagnostics = [TreeDiagnostic(
            "root_selected",
            "root discovery selected the highest-scoring runtime process candidate",
            fact_id=selected.fact.fact_id,
            metadata={"selected": selected.to_dict(), "candidate_count": len(candidates)},
        )]
        competing = [item for item in candidates[1:] if item.score == selected.score and item.pid != selected.pid]
        if competing:
            confidence = min_confidence(confidence, "medium")
            diagnostics.append(TreeDiagnostic(
                "root_ambiguous",
                "multiple root candidates had the same score",
                fact_id=selected.fact.fact_id,
                metadata={"competing_candidates": [item.to_dict() for item in competing[:TOP_ROOT_CANDIDATE_LIMIT]]},
            ))
        if confidence != "high":
            diagnostics.append(TreeDiagnostic(
                "root_lower_confidence",
                "root was selected from a non-explicit or ambiguous candidate set",
                fact_id=selected.fact.fact_id,
                metadata={"confidence": confidence, "reason": selected.reason},
            ))
        attribution = {
            "schema_version": "coarse-attribution-v1",
            "status": "root_selected",
            "confidence": confidence,
            "selected_root": selected.to_dict(),
            "candidate_count": len(candidates),
            "root_candidates": [item.to_dict() for item in top],
            "scanned_fact_count": fact_count,
            "scanned_slice_count": len(slice_ids),
        }
        return selected, diagnostics, attribution

    def _candidate_from_fact(self, fact: ProcessFact) -> RootCandidate | None:
        if fact.kind == "spawn":
            pid = fact.child_pid
            name = fact.child_name
            path = fact.child_path
        elif fact.kind == "observe":
            pid = fact.pid
            name = fact.process_name
            path = ""
        else:
            return None
        if not pid:
            return None
        controlled = self._controlled_path(path)
        hint_match = self._matches_hint(name)
        score = 0
        reason = "fallback_candidate"
        if controlled and hint_match:
            score = 950
            reason = "sample_hint+controlled_path"
        elif controlled:
            score = 900
            reason = "controlled_path"
        elif hint_match:
            score = 850
            reason = "sample_hint"
        if self.root_pid is not None and pid == self.root_pid:
            score = 1000
            reason = "explicit_root_pid"
        if fact.kind == "spawn" and not _successful_result(fact.result):
            score = max(0, score - 500)
            reason = f"{reason}:non_success_result"
        return RootCandidate(fact=fact, pid=pid, process_name=name, score=score, reason=reason)

    def _matches_hint(self, process_name: str) -> bool:
        hint = self.sample_hint.lower().strip()
        if not hint:
            return False
        hint_base = _basename(hint).lower()
        name = (process_name or "").lower()
        return name == hint_base or name == f"{hint_base}.exe" or hint_base in name

    @staticmethod
    def _controlled_path(path: str) -> bool:
        normalized = (path or "").replace("/", "\\").lower()
        return "\\analyst\\" in normalized


class _TreeMaterializer:
    def __init__(self, trace_id: str, root: RootCandidate, diagnostics: list[TreeDiagnostic], attribution: dict[str, Any]):
        self.trace_id = trace_id
        self.root_candidate = root
        self.diagnostics = list(diagnostics)
        self.attribution = dict(attribution)
        self.node_index: dict[str, ProcessTreeNode] = {}
        self.active_by_pid: dict[int, str] = {}
        self.pid_generation: dict[int, int] = defaultdict(int)
        self.node_counter = 0
        self.ignored_fact_count = 0
        self.pid_reuse_count = 0
        self.launch_merge_count = 0
        self.parent_conflict_count = 0
        self.failed_spawn_count = 0
        self.last_time = root.fact.time
        self.last_event_index = root.fact.event_index

    def build(self, facts: Iterable[ProcessFact]) -> ProcessTreeOutput:
        root = self._create_node(
            parent=None,
            pid=self.root_candidate.pid,
            process_name=self.root_candidate.process_name,
            start_time=self.root_candidate.fact.time,
            start_event_index=self.root_candidate.fact.event_index,
            source_fact_id=self.root_candidate.fact.fact_id,
        )
        self.active_by_pid[root.process.pid] = root.node_id
        slice_ids: set[str] = set()
        fact_count = 0
        for fact in facts:
            fact_count += 1
            slice_ids.add(fact.slice_id)
            self.last_time = max(self.last_time, fact.time)
            self.last_event_index = max(self.last_event_index, fact.event_index)
            if fact.event_index < root.process.start_event_index:
                continue
            if fact.kind == "spawn":
                self._handle_spawn(fact)
            elif fact.kind == "observe":
                self._handle_observe(fact)
            elif fact.kind == "exit":
                self._handle_exit(fact)
        for node_id in list(self.active_by_pid.values()):
            node = self.node_index[node_id]
            self._close_node(node, max(node.process.end_time, self.last_time), self.last_event_index, "log_end")
        self.active_by_pid.clear()
        self._append_diagnostics()
        return ProcessTreeOutput(
            trace_id=self.trace_id,
            root_nodes=[root],
            node_index=self.node_index,
            diagnostics=self.diagnostics,
            slice_count=len(slice_ids),
            fact_count=fact_count,
            ignored_fact_count=self.ignored_fact_count,
            attribution=self.attribution,
        )

    def _handle_spawn(self, fact: ProcessFact) -> None:
        if not fact.parent_pid or not fact.child_pid or fact.parent_pid == fact.child_pid:
            self.ignored_fact_count += 1
            return
        if not _successful_result(fact.result):
            self.failed_spawn_count += 1
            self.ignored_fact_count += 1
            return
        if fact.parent_pid_conflict:
            self.parent_conflict_count += 1
        existing_id = self.active_by_pid.get(fact.child_pid)
        if existing_id and fact.fact_id not in self.node_index[existing_id].source_facts:
            existing = self.node_index[existing_id]
            if self._can_merge_launch_fact(existing, fact):
                self._merge_launch_fact(existing, fact)
                self.launch_merge_count += 1
                return
            self._close_node(existing, fact.time, fact.event_index, "pid_reuse")
            self.active_by_pid.pop(fact.child_pid, None)
            self.pid_reuse_count += 1
        parent_id = self._resolve_parent_id(fact)
        if parent_id is None:
            self.ignored_fact_count += 1
            return
        parent = self.node_index[parent_id]
        child = self._create_node(
            parent=parent,
            pid=fact.child_pid,
            process_name=fact.child_name,
            start_time=fact.time,
            start_event_index=fact.event_index,
            source_fact_id=fact.fact_id,
        )
        parent.children.append(child)
        self.active_by_pid[child.process.pid] = child.node_id

    def _resolve_parent_id(self, fact: ProcessFact) -> str | None:
        parent_id = self.active_by_pid.get(fact.parent_pid)
        if parent_id is not None:
            return parent_id
        if not fact.parent_pid_conflict:
            return None
        for candidate_pid in fact.parent_pid_candidates:
            parent_id = self.active_by_pid.get(candidate_pid)
            if parent_id is not None:
                return parent_id
        return None

    def _handle_observe(self, fact: ProcessFact) -> None:
        node_id = self.active_by_pid.get(fact.pid)
        if node_id is None:
            self.ignored_fact_count += 1
            return
        node = self.node_index[node_id]
        if not node.process.name and fact.process_name:
            node.process.name = fact.process_name
        node.process.observed_events += 1
        node.process.end_time = max(node.process.end_time, fact.time)
        node.process.end_event_index = max(node.process.end_event_index, fact.event_index)

    def _handle_exit(self, fact: ProcessFact) -> None:
        node_id = self.active_by_pid.get(fact.pid)
        if node_id is None:
            self.ignored_fact_count += 1
            return
        node = self.node_index[node_id]
        self._close_node(node, fact.time, fact.event_index, "process_exit")
        self.active_by_pid.pop(fact.pid, None)

    def _create_node(
        self,
        parent: ProcessTreeNode | None,
        pid: int,
        process_name: str,
        start_time: float,
        start_event_index: int,
        source_fact_id: str,
    ) -> ProcessTreeNode:
        self.node_counter += 1
        generation = self.pid_generation[pid]
        self.pid_generation[pid] += 1
        node = ProcessTreeNode(
            node_id=f"node_{self.node_counter:06d}",
            parent_node_id=parent.node_id if parent else None,
            depth=parent.depth + 1 if parent else 0,
            status="open",
            process=NodeProcess(
                pid=pid,
                name=process_name,
                start_time=start_time,
                end_time=start_time,
                pid_generation=generation,
                start_event_index=start_event_index,
                end_event_index=start_event_index,
            ),
            source_facts=[source_fact_id],
        )
        self.node_index[node.node_id] = node
        return node

    @staticmethod
    def _close_node(node: ProcessTreeNode, time: float, event_index: int, reason: str) -> None:
        node.status = "closed"
        node.process.end_time = max(node.process.end_time, time)
        node.process.end_event_index = max(node.process.end_event_index, event_index)
        node.process.close_reason = reason

    @staticmethod
    def _can_merge_launch_fact(node: ProcessTreeNode, fact: ProcessFact) -> bool:
        if fact.kind != "spawn" or fact.child_pid != node.process.pid:
            return False
        if any("_spawn_" in source_fact for source_fact in node.source_facts):
            return False
        if fact.event_index < node.process.start_event_index:
            return False
        if fact.time - node.process.start_time > 2.0:
            return False
        return _compatible_process_name(node.process.name, fact.child_name)

    @staticmethod
    def _merge_launch_fact(node: ProcessTreeNode, fact: ProcessFact) -> None:
        node.source_facts.append(fact.fact_id)
        if fact.child_name:
            node.process.name = fact.child_name
        node.process.end_time = max(node.process.end_time, fact.time)
        node.process.end_event_index = max(node.process.end_event_index, fact.event_index)

    def _append_diagnostics(self) -> None:
        if self.pid_reuse_count:
            self.diagnostics.append(TreeDiagnostic(
                "pid_reuse",
                "active watched PID was closed because the same PID was spawned again",
                metadata={"count": self.pid_reuse_count},
            ))
        if self.launch_merge_count:
            self.diagnostics.append(TreeDiagnostic(
                "launch_fact_merged",
                "observed process node was upgraded with its later spawn/start fact",
                metadata={"count": self.launch_merge_count},
            ))
        if self.parent_conflict_count:
            self.diagnostics.append(TreeDiagnostic(
                "spawn_parent_conflict",
                "merged process launch facts disagreed on parent PID",
                metadata={"count": self.parent_conflict_count},
            ))
        if self.failed_spawn_count:
            self.diagnostics.append(TreeDiagnostic(
                "failed_spawn_ignored",
                "non-success process launch facts were ignored during tree expansion",
                metadata={"count": self.failed_spawn_count},
            ))
        if self.ignored_fact_count:
            self.diagnostics.append(TreeDiagnostic(
                "ignored_facts",
                "facts outside the active watch set were ignored",
                metadata={"count": self.ignored_fact_count},
            ))


def build_tree_from_csv(
    log_path: str,
    sample_hint: str,
    trace_id: str = "",
    slice_size: int = 1000,
    root_pid: int | None = None,
) -> ProcessTreeOutput:
    trace = trace_id or _trace_id_from_path(log_path)
    builder = WatchTreeBuilder(trace_id=trace, sample_hint=sample_hint, root_pid=root_pid)
    return builder.build(lambda: iter_csv_slice_envelopes(log_path, slice_size))


def _facts_from_envelopes(envelopes: Iterable[SliceEnvelope]) -> Iterator[ProcessFact]:
    for envelope in envelopes:
        yield from envelope.facts


def _basename(path: str) -> str:
    if not path:
        return ""
    clean = path.strip('"')
    try:
        return PureWindowsPath(clean).name
    except Exception:
        return clean.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _compatible_process_name(left: str, right: str) -> bool:
    left_name = (left or "").casefold()
    right_name = (right or "").casefold()
    if not left_name or not right_name:
        return True
    if left_name == right_name:
        return True
    left_base = left_name[:-4] if left_name.endswith(".exe") else left_name
    right_base = right_name[:-4] if right_name.endswith(".exe") else right_name
    return left_base == right_base


def _successful_result(result: str) -> bool:
    return str(result or "").strip().casefold() in SUCCESS_RESULTS


def dedupe_root_candidates(candidates: list[RootCandidate]) -> list[RootCandidate]:
    best: dict[tuple[int, str], RootCandidate] = {}
    for candidate in candidates:
        key = (candidate.pid, candidate.process_name.casefold())
        current = best.get(key)
        if current is None or candidate.sort_key() < current.sort_key():
            best[key] = candidate
    return sorted(best.values(), key=lambda item: item.sort_key())


def min_confidence(left: str, right: str) -> str:
    rank = {"absent": 0, "low": 1, "medium": 2, "high": 3}
    return left if rank[left] <= rank[right] else right


def _trace_id_from_path(path: str) -> str:
    return PureWindowsPath(path).stem or "trace"

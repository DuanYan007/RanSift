"""Deterministic same-process behavior block construction."""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any

from .classification import classify_operation_family
from .models import BehaviorEvent

DEFAULT_MICRO_TIME_GAP_S = 2.0
DEFAULT_MICRO_ORDER_GAP = 25
DEFAULT_MACRO_TIME_GAP_S = 10.0
DEFAULT_MACRO_ORDER_GAP = 250
REPRESENTATIVE_LIMIT = 5

FILE_CHAIN_FAMILIES = {
    "file_open",
    "file_read",
    "file_write",
    "file_rename",
    "file_delete",
    "file_close",
    "file_metadata_query",
    "directory_enum",
}
REGISTRY_CHAIN_FAMILIES = {"registry_open", "registry_query", "registry_write"}
PROCESS_CHAIN_FAMILIES = {"process_start", "image_load", "runtime_probe", "runtime_activity"}
HIGH_SIGNAL_FAMILIES = {
    "file_write",
    "file_rename",
    "file_delete",
    "registry_write",
    "process_start",
    "network_connect",
}
BEHAVIOR_PRIORITY = {
    "file_transformation": 90,
    "process_execution": 80,
    "network_activity": 70,
    "registry_modification": 65,
    "file_content_access": 60,
    "file_discovery": 50,
    "registry_discovery": 45,
    "image_loading": 40,
    "runtime_activity": 30,
    "file_lifecycle": 20,
    "other": 0,
}


@dataclass(frozen=True)
class ProcessInstance:
    node_id: str
    pid: int
    process_name: str

    @property
    def key(self) -> str:
        node = self.node_id or "node_unknown"
        return f"{node}|{self.pid}|{self.process_name.casefold()}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "key": self.key,
        }


@dataclass(frozen=True)
class BehaviorAtom:
    offset: int
    source: str
    timestamp: float
    process_instance: ProcessInstance
    category: str
    operation: str
    operation_family: str
    behavior_kind: str
    target_key: str
    target_scope: str
    namespace: str
    extension: str
    result: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "source": self.source,
            "timestamp": self.timestamp,
            "process_instance": self.process_instance.to_dict(),
            "category": self.category,
            "operation": self.operation,
            "operation_family": self.operation_family,
            "behavior_kind": self.behavior_kind,
            "target_key": self.target_key,
            "target_scope": self.target_scope,
            "namespace": self.namespace,
            "extension": self.extension,
            "result": self.result,
        }


@dataclass(frozen=True)
class ProcessBehaviorBlock:
    block_id: str
    level: str
    process_instance: ProcessInstance
    behavior_kind: str
    category: str
    target_scope: str
    target_examples: tuple[str, ...]
    time_start: float
    time_end: float
    order_start: int
    order_end: int
    event_count: int
    operation_families: tuple[str, ...]
    operation_counts: dict[str, int]
    result_counts: dict[str, int]
    representative_offsets: tuple[int, ...]
    source_offsets: tuple[int, ...]
    child_block_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def to_dict(self, inline_source_offsets_limit: int = 500) -> dict[str, Any]:
        data: dict[str, Any] = {
            "block_id": self.block_id,
            "level": self.level,
            "process_instance": self.process_instance.to_dict(),
            "behavior_kind": self.behavior_kind,
            "category": self.category,
            "target_scope": self.target_scope,
            "target_examples": list(self.target_examples),
            "time_range": [self.time_start, self.time_end],
            "order_range": [self.order_start, self.order_end],
            "event_count": self.event_count,
            "operation_families": list(self.operation_families),
            "operation_counts": self.operation_counts,
            "result_counts": self.result_counts,
            "representative_offsets": list(self.representative_offsets),
            "source_offset_ranges": offset_ranges(self.source_offsets),
            "child_block_ids": list(self.child_block_ids),
            "limitations": list(self.limitations),
        }
        if len(self.source_offsets) <= inline_source_offsets_limit:
            data["source_offsets"] = list(self.source_offsets)
        else:
            data["source_offsets_omitted"] = len(self.source_offsets)
        return data


@dataclass(frozen=True)
class BehaviorBlockSet:
    micro_blocks: tuple[ProcessBehaviorBlock, ...]
    macro_blocks: tuple[ProcessBehaviorBlock, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "behavior-blocks-v1",
            "micro_block_count": len(self.micro_blocks),
            "macro_block_count": len(self.macro_blocks),
            "micro_blocks": [block.to_dict() for block in self.micro_blocks],
            "macro_blocks": [block.to_dict() for block in self.macro_blocks],
        }

    def summary(self, top_n: int = 10) -> dict[str, Any]:
        kinds = Counter(block.behavior_kind for block in self.macro_blocks)
        categories = Counter(block.category for block in self.macro_blocks)
        return {
            "schema_version": "behavior-blocks-v1",
            "micro_block_count": len(self.micro_blocks),
            "macro_block_count": len(self.macro_blocks),
            "macro_behavior_kind_counts": dict(sorted(kinds.items())),
            "macro_category_counts": dict(sorted(categories.items())),
            "top_macro_blocks": [compact_block(block) for block in top_blocks(self.macro_blocks, top_n)],
        }


def build_process_behavior_blocks(
    events: Iterable[BehaviorEvent],
    micro_time_gap_s: float = DEFAULT_MICRO_TIME_GAP_S,
    micro_order_gap: int = DEFAULT_MICRO_ORDER_GAP,
    macro_time_gap_s: float = DEFAULT_MACRO_TIME_GAP_S,
    macro_order_gap: int = DEFAULT_MACRO_ORDER_GAP,
) -> BehaviorBlockSet:
    atoms_by_process: dict[str, list[BehaviorAtom]] = defaultdict(list)
    for event in events:
        atom = event_to_atom(event)
        atoms_by_process[atom.process_instance.key].append(atom)

    micro_blocks: list[ProcessBehaviorBlock] = []
    micro_counter = 1
    for atoms in sorted(atoms_by_process.values(), key=lambda rows: rows[0].offset if rows else -1):
        atoms.sort(key=lambda atom: atom.offset)
        process_blocks = build_micro_blocks_for_process(
            atoms,
            start_index=micro_counter,
            max_time_gap_s=micro_time_gap_s,
            max_order_gap=micro_order_gap,
        )
        micro_blocks.extend(process_blocks)
        micro_counter += len(process_blocks)

    macro_blocks = build_macro_blocks(micro_blocks, macro_time_gap_s, macro_order_gap)
    return BehaviorBlockSet(tuple(micro_blocks), tuple(macro_blocks))


def build_micro_blocks_for_process(
    atoms: list[BehaviorAtom],
    start_index: int,
    max_time_gap_s: float,
    max_order_gap: int,
) -> list[ProcessBehaviorBlock]:
    blocks: list[ProcessBehaviorBlock] = []
    current: list[BehaviorAtom] = []
    next_id = start_index
    for atom in atoms:
        if not current:
            current = [atom]
            continue
        if compatible_micro(current, atom, max_time_gap_s, max_order_gap):
            current.append(atom)
        else:
            blocks.append(block_from_atoms(f"micro_{next_id:06d}", "micro", current))
            next_id += 1
            current = [atom]
    if current:
        blocks.append(block_from_atoms(f"micro_{next_id:06d}", "micro", current))
    return blocks


def build_macro_blocks(
    micro_blocks: list[ProcessBehaviorBlock], max_time_gap_s: float, max_order_gap: int) -> list[ProcessBehaviorBlock]:
    by_process: dict[str, list[ProcessBehaviorBlock]] = defaultdict(list)
    for block in micro_blocks:
        by_process[block.process_instance.key].append(block)

    macro_blocks: list[ProcessBehaviorBlock] = []
    next_id = 1
    for blocks in sorted(by_process.values(), key=lambda rows: rows[0].order_start if rows else -1):
        blocks.sort(key=lambda block: block.order_start)
        current: list[ProcessBehaviorBlock] = []
        for block in blocks:
            if not current:
                current = [block]
                continue
            if compatible_macro(current[-1], block, max_time_gap_s, max_order_gap):
                current.append(block)
            else:
                macro_blocks.append(block_from_children(f"macro_{next_id:06d}", current))
                next_id += 1
                current = [block]
        if current:
            macro_blocks.append(block_from_children(f"macro_{next_id:06d}", current))
            next_id += 1
    return macro_blocks


def event_to_atom(event: BehaviorEvent) -> BehaviorAtom:
    operation_family = classify_operation_family(event.action.operation)
    behavior_kind = classify_behavior_kind(operation_family, event.action.category)
    target_key = make_target_key(event)
    target_scope = make_target_scope(event, operation_family)
    return BehaviorAtom(
        offset=event.order.filtered,
        source=event.order.source,
        timestamp=event.time.timestamp,
        process_instance=ProcessInstance(
            node_id=event.process_context.node_id,
            pid=event.process_context.pid,
            process_name=event.process_context.process_name,
        ),
        category=event.action.category,
        operation=event.action.operation,
        operation_family=operation_family,
        behavior_kind=behavior_kind,
        target_key=target_key,
        target_scope=target_scope,
        namespace=event.target.namespace,
        extension=event.target.extension,
        result=event.action.result,
    )


def compatible_micro(current: list[BehaviorAtom], atom: BehaviorAtom, max_time_gap_s: float, max_order_gap: int) -> bool:
    last = current[-1]
    if last.process_instance.key != atom.process_instance.key:
        return False
    if atom.offset - last.offset > max_order_gap:
        return False
    if positive_gap(atom.timestamp, last.timestamp) > max_time_gap_s:
        return False

    current_kind = merged_behavior_kind(item.behavior_kind for item in current)
    same_kind = current_kind == atom.behavior_kind
    chain = allowed_chain(last.operation_family, atom.operation_family)

    if last.target_key and atom.target_key:
        same_target = last.target_key == atom.target_key
        if same_target and (same_kind or chain or same_family_group(last.operation_family, atom.operation_family)):
            return True
        return False

    if not last.target_key and not atom.target_key:
        return same_kind and last.operation_family == atom.operation_family

    return False


def compatible_macro(previous: ProcessBehaviorBlock, block: ProcessBehaviorBlock, max_time_gap_s: float, max_order_gap: int) -> bool:
    if previous.process_instance.key != block.process_instance.key:
        return False
    if previous.behavior_kind != block.behavior_kind:
        return False
    if previous.category != block.category:
        return False
    if previous.target_scope != block.target_scope:
        return False
    if block.order_start - previous.order_end > max_order_gap:
        return False
    if positive_gap(block.time_start, previous.time_end) > max_time_gap_s:
        return False
    return True


def block_from_atoms(block_id: str, level: str, atoms: list[BehaviorAtom]) -> ProcessBehaviorBlock:
    source_offsets = tuple(atom.offset for atom in atoms)
    target_examples = tuple(top_values((atom.target_key for atom in atoms if atom.target_key), limit=5))
    operation_counts = dict(sorted(Counter(atom.operation for atom in atoms).items()))
    result_counts = dict(sorted(Counter(atom.result for atom in atoms).items()))
    families = tuple(sorted(set(atom.operation_family for atom in atoms)))
    kind = merged_behavior_kind(atom.behavior_kind for atom in atoms)
    category = dominant_value(atom.category for atom in atoms)
    target_scope = dominant_value(atom.target_scope for atom in atoms)
    limitations = limitations_for_atoms(atoms)
    return ProcessBehaviorBlock(
        block_id=block_id,
        level=level,
        process_instance=atoms[0].process_instance,
        behavior_kind=kind,
        category=category,
        target_scope=target_scope,
        target_examples=target_examples,
        time_start=min(atom.timestamp for atom in atoms),
        time_end=max(atom.timestamp for atom in atoms),
        order_start=min(source_offsets),
        order_end=max(source_offsets),
        event_count=len(atoms),
        operation_families=families,
        operation_counts=operation_counts,
        result_counts=result_counts,
        representative_offsets=tuple(select_representative_offsets(atoms)),
        source_offsets=source_offsets,
        limitations=limitations,
    )


def block_from_children(block_id: str, children: list[ProcessBehaviorBlock]) -> ProcessBehaviorBlock:
    source_offsets = tuple(offset for child in children for offset in child.source_offsets)
    target_examples = tuple(top_values((example for child in children for example in child.target_examples), limit=5))
    operation_counts = merge_counters(child.operation_counts for child in children)
    result_counts = merge_counters(child.result_counts for child in children)
    families = tuple(sorted(set(family for child in children for family in child.operation_families)))
    representative_offsets = tuple(select_representative_offsets_from_blocks(children))
    limitations = tuple(sorted(set(limit for child in children for limit in child.limitations)))
    return ProcessBehaviorBlock(
        block_id=block_id,
        level="macro",
        process_instance=children[0].process_instance,
        behavior_kind=children[0].behavior_kind,
        category=children[0].category,
        target_scope=children[0].target_scope,
        target_examples=target_examples,
        time_start=min(child.time_start for child in children),
        time_end=max(child.time_end for child in children),
        order_start=min(child.order_start for child in children),
        order_end=max(child.order_end for child in children),
        event_count=sum(child.event_count for child in children),
        operation_families=families,
        operation_counts=operation_counts,
        result_counts=result_counts,
        representative_offsets=representative_offsets,
        source_offsets=tuple(sorted(source_offsets)),
        child_block_ids=tuple(child.block_id for child in children),
        limitations=limitations,
    )




def classify_behavior_kind(operation_family: str, category: str) -> str:
    if operation_family in {"directory_enum", "file_metadata_query"}:
        return "file_discovery"
    if operation_family == "file_read":
        return "file_content_access"
    if operation_family in {"file_write", "file_rename", "file_delete"}:
        return "file_transformation"
    if operation_family in {"file_open", "file_close"}:
        return "file_lifecycle"
    if operation_family in {"registry_open", "registry_query"}:
        return "registry_discovery"
    if operation_family == "registry_write":
        return "registry_modification"
    if operation_family == "process_start":
        return "process_execution"
    if operation_family == "image_load":
        return "image_loading"
    if operation_family == "network_connect":
        return "network_activity"
    if operation_family in {"runtime_probe", "runtime_activity"}:
        return "runtime_activity"
    if category == "registry":
        return "registry_discovery"
    return "other"


def make_target_key(event: BehaviorEvent) -> str:
    return event.target.normalized_path or ""


def make_target_scope(event: BehaviorEvent, operation_family: str) -> str:
    path = event.target.normalized_path
    namespace = event.target.namespace
    extension = event.target.extension or "noext"
    if not path:
        return f"{event.action.category}:empty"
    if namespace == "registry":
        parts = [part for part in path.replace("/", "\\").split("\\") if part]
        return "registry:" + "\\".join(parts[:3])
    if event.action.category == "network":
        return "network:" + path
    if operation_family == "image_load":
        return f"image:{parent_dir(path)}"
    if event.action.category == "file":
        if operation_family == "directory_enum":
            return f"dir:{path}"
        return f"file:{parent_dir(path)}|ext:{extension}"
    if event.action.category == "process":
        return f"process:{parent_dir(path)}" if path else "process:empty"
    return f"{event.action.category}:{namespace}"


def parent_dir(path: str) -> str:
    try:
        parent = str(PureWindowsPath(path).parent)
    except Exception:
        parent = path.rsplit("\\", 1)[0] if "\\" in path else path
    if parent == ".":
        return ""
    return parent.casefold()


def allowed_chain(left: str, right: str) -> bool:
    if left in FILE_CHAIN_FAMILIES and right in FILE_CHAIN_FAMILIES:
        return True
    if left in REGISTRY_CHAIN_FAMILIES and right in REGISTRY_CHAIN_FAMILIES:
        return True
    if left in PROCESS_CHAIN_FAMILIES and right in PROCESS_CHAIN_FAMILIES:
        return True
    return False


def same_family_group(left: str, right: str) -> bool:
    groups = (FILE_CHAIN_FAMILIES, REGISTRY_CHAIN_FAMILIES, PROCESS_CHAIN_FAMILIES)
    return any(left in group and right in group for group in groups)


def merged_behavior_kind(kinds: Iterable[str]) -> str:
    return max(kinds, key=lambda kind: BEHAVIOR_PRIORITY.get(kind, 0))


def dominant_value(values: Iterable[str]) -> str:
    counter = Counter(values)
    if not counter:
        return ""
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[0][0]


def top_values(values: Iterable[str], limit: int) -> list[str]:
    counter = Counter(value for value in values if value)
    return [value for value, _ in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def merge_counters(counters: Iterable[dict[str, int]]) -> dict[str, int]:
    merged: Counter[str] = Counter()
    for counter in counters:
        merged.update(counter)
    return dict(sorted(merged.items()))


def select_representative_offsets(atoms: list[BehaviorAtom], limit: int = REPRESENTATIVE_LIMIT) -> list[int]:
    selected: list[int] = []

    def add(offset: int) -> None:
        if offset not in selected and len(selected) < limit:
            selected.append(offset)

    add(atoms[0].offset)
    add(atoms[-1].offset)
    failed = next((atom.offset for atom in atoms if atom.result.casefold() not in {"success", ""}), None)
    if failed is not None:
        add(failed)
    high_signal = next((atom.offset for atom in atoms if atom.operation_family in HIGH_SIGNAL_FAMILIES), None)
    if high_signal is not None:
        add(high_signal)
    add(atoms[len(atoms) // 2].offset)
    return sorted(selected)


def select_representative_offsets_from_blocks(blocks: list[ProcessBehaviorBlock], limit: int = REPRESENTATIVE_LIMIT) -> list[int]:
    selected: list[int] = []

    def add(offset: int) -> None:
        if offset not in selected and len(selected) < limit:
            selected.append(offset)

    add(blocks[0].representative_offsets[0])
    add(blocks[-1].representative_offsets[-1])
    for block in blocks:
        failed = any(result.casefold() not in {"success", ""} for result in block.result_counts)
        if failed:
            add(block.representative_offsets[0])
            break
    for block in blocks:
        if any(family in HIGH_SIGNAL_FAMILIES for family in block.operation_families):
            add(block.representative_offsets[0])
            break
    mid = blocks[len(blocks) // 2]
    add(mid.representative_offsets[0])
    return sorted(selected)


def limitations_for_atoms(atoms: list[BehaviorAtom]) -> tuple[str, ...]:
    limitations: list[str] = []
    if any(atom.timestamp < atoms[index - 1].timestamp for index, atom in enumerate(atoms[1:], start=1)):
        limitations.append("timestamp inversion inside block; order.filtered is authoritative")
    if len({atom.target_key for atom in atoms if atom.target_key}) > 1:
        limitations.append("multiple exact targets; inspect target_examples before claim use")
    if any(atom.result.casefold() not in {"success", ""} for atom in atoms):
        limitations.append("contains non-success results")
    return tuple(limitations)


def positive_gap(current: float, previous: float) -> float:
    return max(0.0, current - previous)


def offset_ranges(offsets: tuple[int, ...]) -> list[list[int]]:
    if not offsets:
        return []
    ordered = sorted(offsets)
    ranges: list[list[int]] = []
    start = previous = ordered[0]
    for offset in ordered[1:]:
        if offset == previous + 1:
            previous = offset
            continue
        ranges.append([start, previous])
        start = previous = offset
    ranges.append([start, previous])
    return ranges


def top_blocks(blocks: tuple[ProcessBehaviorBlock, ...], limit: int) -> list[ProcessBehaviorBlock]:
    return sorted(blocks, key=lambda block: (-block.event_count, block.order_start, block.block_id))[:limit]


def compact_block(block: ProcessBehaviorBlock) -> dict[str, Any]:
    return {
        "block_id": block.block_id,
        "behavior_kind": block.behavior_kind,
        "category": block.category,
        "target_scope": block.target_scope,
        "event_count": block.event_count,
        "order_range": [block.order_start, block.order_end],
        "operation_families": list(block.operation_families),
        "representative_offsets": list(block.representative_offsets),
        "child_block_count": len(block.child_block_ids),
    }

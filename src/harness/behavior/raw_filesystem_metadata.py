"""Deterministic evidence for writes to raw filesystem metadata objects."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .classification import (
    DETERMINISTIC_RAW_FILESYSTEM_METADATA_WRITE_RULE,
    classify_operation_family,
)
from .file_transitions import (
    is_success_result,
    transition_process_instance,
    transition_process_key,
    transition_target_path,
)


RAW_FILESYSTEM_METADATA_OBJECTS = frozenset({
    "$attrdef",
    "$badclus",
    "$bitmap",
    "$boot",
    "$extend",
    "$logfile",
    "$mft",
    "$mftmirr",
    "$secure",
    "$upcase",
    "$usnjrnl",
    "$volume",
})

# A few successful $LogFile writes are observable during ordinary installer and
# crash-reporting activity. A malicious certificate therefore requires a
# repeated write pattern against a structural NTFS object, rather than treating
# every metadata write as destructive tampering.
STRUCTURAL_RAW_FILESYSTEM_METADATA_OBJECTS = frozenset({
    "$attrdef",
    "$badclus",
    "$bitmap",
    "$boot",
    "$mft",
    "$mftmirr",
    "$secure",
    "$upcase",
    "$usnjrnl",
    "$volume",
})
MIN_STRUCTURAL_METADATA_WRITE_COUNT = 20
MIN_STRUCTURAL_METADATA_EVIDENCE_REFS = 2


@dataclass(frozen=True)
class RawFilesystemMetadataWriteSearch:
    """Bounded groups of successful writes to NTFS metadata objects."""

    groups: tuple[dict[str, Any], ...]
    representative_offsets: tuple[int, ...]
    matched_write_count: int
    matched_group_count: int
    qualifying_processes: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]

    def aggregates(self) -> dict[str, Any]:
        supports = [
            {
                "rule_id": DETERMINISTIC_RAW_FILESYSTEM_METADATA_WRITE_RULE,
                "evidence_ref_ids": [
                    f"event:{int(offset)}"
                    for offset in process["representative_offsets"]
                ],
                "metadata_objects": list(process["metadata_objects"]),
                "structural_write_count": int(process["structural_write_count"]),
                "qualification": str(process["qualification"]),
                "process_instance": dict(process.get("process_instance") or {}),
            }
            for process in self.qualifying_processes
        ]
        return {
            "raw_filesystem_metadata_write_summary": {
                "matched_group_count": self.matched_group_count,
                "returned_group_count": len(self.groups),
                "matched_write_count": self.matched_write_count,
                "qualifying_process_count": len(self.qualifying_processes),
                "minimum_structural_write_count": MIN_STRUCTURAL_METADATA_WRITE_COUNT,
            },
            "groups": [dict(group) for group in self.groups],
            "deterministic_rule_supports": supports,
        }


def search_raw_filesystem_metadata_writes(
    events: Iterable[tuple[int, dict[str, Any]]],
    limit: int,
) -> RawFilesystemMetadataWriteSearch:
    """Find sample-attributed successful writes to raw filesystem metadata.

    Reading ``$MFT`` or other metadata can occur in forensic and administration
    tools. This certificate intentionally requires a successful content write,
    which establishes a write observation but does not by itself establish deliberate raw access or destruction.
    """

    groups_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    matched_write_count = 0
    for offset, event in events:
        if not is_successful_metadata_write(event):
            continue
        metadata_object = raw_filesystem_metadata_object(transition_target_path(event))
        if not metadata_object:
            continue
        process_key = transition_process_key(event)
        if not process_key:
            continue
        matched_write_count += 1
        group = groups_by_key.setdefault(
            (process_key, metadata_object),
            {
                "process_instance": transition_process_instance(event, process_key),
                "metadata_object": metadata_object,
                "write_offsets": [],
            },
        )
        group["write_offsets"].append(int(offset))

    matched = []
    for group in groups_by_key.values():
        offsets = sorted(set(int(offset) for offset in group["write_offsets"]))
        if not offsets:
            continue
        matched.append(
            {
                "summary": (
                    f"process={group['process_instance'].get('key')}; "
                    f"metadata_object={group['metadata_object']}; write_count={len(offsets)}"
                ),
                "process_instance": dict(group["process_instance"]),
                "metadata_object": str(group["metadata_object"]),
                "write_count": len(offsets),
                "representative_offset": offsets[0],
                "representative_write_offsets": offsets[:3],
            }
        )
    matched.sort(
        key=lambda group: (
            -int(group["write_count"]),
            int(group["representative_offset"]),
            str(group["metadata_object"]),
        )
    )
    qualifying_processes = qualifying_structural_metadata_processes(matched)
    selected = tuple(matched[: max(0, int(limit))])
    representative_offsets = list(
        dict.fromkeys(int(group["representative_offset"]) for group in selected)
    )
    for process in qualifying_processes:
        for offset in process["representative_offsets"]:
            if int(offset) not in representative_offsets:
                representative_offsets.append(int(offset))
    return RawFilesystemMetadataWriteSearch(
        groups=selected,
        representative_offsets=tuple(representative_offsets),
        matched_write_count=matched_write_count,
        matched_group_count=len(matched),
        qualifying_processes=qualifying_processes,
        limitations=(
            "reports successful sample-attributed content writes, not metadata reads or opens",
            "the repeated-write support records at least 20 structural NTFS metadata writes in one process; it does not establish intent or raw-device access",
            "isolated and repeated metadata writes can reflect filesystem maintenance; assess request context before inferring corruption",
        ),
    )


def qualifying_structural_metadata_processes(
    groups: list[dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Return high-confidence repeated structural metadata write certificates."""

    by_process: dict[str, list[dict[str, Any]]] = {}
    for group in groups:
        if str(group.get("metadata_object") or "") not in STRUCTURAL_RAW_FILESYSTEM_METADATA_OBJECTS:
            continue
        process = group.get("process_instance")
        process_key = str(process.get("key") or "") if isinstance(process, dict) else ""
        if process_key:
            by_process.setdefault(process_key, []).append(group)

    qualifying = []
    for process_key, process_groups in by_process.items():
        ordered = sorted(
            process_groups,
            key=lambda group: (
                -int(group["write_count"]),
                str(group["metadata_object"]),
                int(group["representative_offset"]),
            ),
        )
        structural_write_count = sum(int(group["write_count"]) for group in ordered)
        largest_object_write_count = max(int(group["write_count"]) for group in ordered)
        if structural_write_count < MIN_STRUCTURAL_METADATA_WRITE_COUNT:
            continue
        metadata_objects = tuple(str(group["metadata_object"]) for group in ordered)
        qualification = (
            "repeated_single_structural_object"
            if largest_object_write_count >= MIN_STRUCTURAL_METADATA_WRITE_COUNT
            else "repeated_multiple_structural_objects"
        )
        offsets: list[int] = []
        for group in ordered:
            for offset in group.get("representative_write_offsets") or ():
                if int(offset) not in offsets:
                    offsets.append(int(offset))
                if len(offsets) == MIN_STRUCTURAL_METADATA_EVIDENCE_REFS:
                    break
            if len(offsets) == MIN_STRUCTURAL_METADATA_EVIDENCE_REFS:
                break
        if len(offsets) != MIN_STRUCTURAL_METADATA_EVIDENCE_REFS:
            continue
        qualifying.append(
            {
                "process_key": process_key,
                "process_instance": dict(ordered[0]["process_instance"]),
                "metadata_objects": metadata_objects,
                "structural_write_count": structural_write_count,
                "qualification": qualification,
                "representative_offsets": tuple(offsets),
            }
        )
    qualifying.sort(
        key=lambda process: (
            -int(process["structural_write_count"]),
            str(process["process_key"]),
        )
    )
    return tuple(qualifying)


def is_successful_metadata_write(event: dict[str, Any]) -> bool:
    action = event.get("action") or {}
    operation = str(action.get("operation") or "")
    family = str(action.get("operation_family") or "") or classify_operation_family(operation)
    return family == "file_write" and is_success_result(action.get("result"))


def raw_filesystem_metadata_object(path: str) -> str:
    normalized = str(path or "").replace("/", "\\").casefold()
    if "\\$extend\\$usnjrnl" in normalized:
        return "$usnjrnl"
    leaf = normalized.rsplit("\\", 1)[-1].split(":", 1)[0]
    return leaf if leaf in RAW_FILESYSTEM_METADATA_OBJECTS else ""

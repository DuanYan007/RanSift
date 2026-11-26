"""Deterministic, process-scoped extension-changing rename evidence."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from .classification import (
    DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE,
    DETERMINISTIC_REPEATED_EXTENSION_RENAME_TRANSFORMATION_RULE,
    classify_operation_family,
)
from .file_transitions import (
    BENIGN_ADDED_EXTENSION_SUFFIXES,
    TRANSITION_SCOPE_ALL,
    TRANSITION_SCOPE_DIRECT_USER_SHARED,
    bounded_positive_int,
    direct_user_shared_target_scope,
    is_success_result,
    normalize_transition_scope,
    transition_process_instance,
    transition_process_key,
    transition_target_path,
)


RENAME_REPRESENTATIVE_EVENT_LIMIT = 3
MIN_DETERMINISTIC_RENAME_SCOPE_COUNT = 2
MIN_DETERMINISTIC_REPLACEMENT_RENAME_COUNT = 20
MIN_BROAD_REPEATED_EXTENSION_APPEND_RENAME_COUNT = 20
MAX_RENAME_SCOPE_COUNT = 20


@dataclass(frozen=True)
class FileExtensionRenameSearch:
    scope: str
    min_rename_count: int
    min_scope_count: int
    groups: tuple[dict[str, Any], ...]
    representative_offsets: tuple[int, ...]
    matched_rename_count: int
    valid_scope: bool = True
    limitations: tuple[str, ...] = ()

    def aggregates(self) -> dict[str, Any]:
        payload = {
            "rename_summary": {
                "matched_rename_count": self.matched_rename_count,
                "matched_group_count": len(self.groups),
                "scope": self.scope,
                "min_rename_count": self.min_rename_count,
                "min_scope_count": self.min_scope_count,
            },
            "group_summaries": [str(group.get("summary") or "") for group in self.groups],
            "groups": list(self.groups),
        }
        payload["deterministic_rule_supports"] = [
            dict(item) for item in self.deterministic_rule_supports()
        ]
        return payload

    def deterministic_rule_supports(self) -> tuple[dict[str, Any], ...]:
        if (
            self.scope == TRANSITION_SCOPE_ALL
            and self.min_rename_count >= MIN_BROAD_REPEATED_EXTENSION_APPEND_RENAME_COUNT
        ):
            supports: list[dict[str, Any]] = []
            for group in self.groups:
                destination_extension = str(group.get("destination_extension") or "").casefold()
                if (
                    str(group.get("rename_kind") or "") != "extension_append"
                    or destination_extension in BENIGN_ADDED_EXTENSION_SUFFIXES
                    or int(group.get("rename_count") or 0) < MIN_BROAD_REPEATED_EXTENSION_APPEND_RENAME_COUNT
                    or int(group.get("unique_original_count") or 0) < MIN_BROAD_REPEATED_EXTENSION_APPEND_RENAME_COUNT
                ):
                    continue
                renames = group.get("representative_renames")
                if not isinstance(renames, list) or len(renames) < 2:
                    continue
                try:
                    offsets = tuple(int(rename["rename_offset"]) for rename in renames[:2])
                except (KeyError, TypeError, ValueError):
                    continue
                if offsets[0] == offsets[1]:
                    continue
                process = group.get("process_instance")
                process_key = str(process.get("key") or "") if isinstance(process, dict) else ""
                if not process_key:
                    continue
                supports.append(
                    {
                        "rule_id": DETERMINISTIC_REPEATED_EXTENSION_RENAME_TRANSFORMATION_RULE,
                        "evidence_ref_ids": tuple(f"event:{offset}" for offset in offsets),
                        "process_key": process_key,
                        "target_scope": str(group.get("target_scope") or ""),
                        "destination_extension": destination_extension,
                        "rename_kind": "extension_append",
                        "rename_count": int(group.get("rename_count") or 0),
                        "unique_original_count": int(group.get("unique_original_count") or 0),
                        "process_instance": dict(process) if isinstance(process, dict) else {},
                    }
                )
            return tuple(supports)
        if (
            self.scope != TRANSITION_SCOPE_DIRECT_USER_SHARED
            or self.min_rename_count < 3
            or self.min_scope_count < MIN_DETERMINISTIC_RENAME_SCOPE_COUNT
        ):
            return ()

        groups_by_contract: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for group in self.groups:
            if int(group.get("unique_original_count") or 0) < self.min_rename_count:
                continue
            process = group.get("process_instance")
            process_key = str(process.get("key") or "") if isinstance(process, dict) else ""
            destination_extension = str(group.get("destination_extension") or "")
            if process_key and destination_extension:
                groups_by_contract[(process_key, destination_extension)].append(group)

        supports: list[dict[str, Any]] = []
        for (process_key, destination_extension), process_groups in sorted(groups_by_contract.items()):
            distinct_scopes = {
                str(group.get("target_scope") or "")
                for group in process_groups
                if str(group.get("target_scope") or "")
            }
            if len(distinct_scopes) < self.min_scope_count:
                continue
            rename_count = sum(int(group.get("rename_count") or 0) for group in process_groups)
            rename_kinds = {
                str(group.get("rename_kind") or "")
                for group in process_groups
                if str(group.get("rename_kind") or "")
            }
            if "extension_replacement" in rename_kinds and rename_count < MIN_DETERMINISTIC_REPLACEMENT_RENAME_COUNT:
                continue
            ordered_groups = sorted(
                process_groups,
                key=lambda group: (
                    -int(group.get("unique_original_count") or 0),
                    str(group.get("target_scope") or ""),
                ),
            )
            selected_groups = ordered_groups[:2]
            if len(selected_groups) != 2:
                continue
            offsets: list[int] = []
            for group in selected_groups:
                renames = group.get("representative_renames")
                if not isinstance(renames, list) or not renames or not isinstance(renames[0], dict):
                    break
                try:
                    offsets.append(int(renames[0]["rename_offset"]))
                except (KeyError, TypeError, ValueError):
                    break
            if len(offsets) != 2 or offsets[0] == offsets[1]:
                continue
            process = selected_groups[0].get("process_instance")
            supports.append(
                {
                    "rule_id": DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE,
                    "evidence_ref_ids": tuple(f"event:{offset}" for offset in offsets),
                    "process_key": process_key,
                    "target_scopes": tuple(
                        str(group.get("target_scope") or "") for group in selected_groups
                    ),
                    "qualifying_scope_count": len(distinct_scopes),
                    "rename_count": rename_count,
                    "destination_extension": destination_extension,
                    "rename_kind": (
                        "extension_replacement"
                        if "extension_replacement" in rename_kinds
                        else "extension_append"
                    ),
                    "process_instance": dict(process) if isinstance(process, dict) else {},
                }
            )
        return tuple(supports)


def search_file_extension_renames(
    events: Iterable[dict[str, Any]],
    process_key: str | None = None,
    scope: str = TRANSITION_SCOPE_ALL,
    min_rename_count: int = 1,
    min_scope_count: int = 1,
    group_limit: int = 20,
) -> FileExtensionRenameSearch:
    """Find successful same-process renames that change file extensions in place."""
    normalized_scope = normalize_transition_scope(scope)
    minimum = bounded_positive_int(min_rename_count, maximum=200, default=1)
    scope_minimum = bounded_positive_int(
        min_scope_count,
        maximum=MAX_RENAME_SCOPE_COUNT,
        default=1,
    )
    limit = bounded_positive_int(group_limit, maximum=200, default=20)
    if normalized_scope is None:
        return FileExtensionRenameSearch(
            scope=str(scope),
            min_rename_count=minimum,
            min_scope_count=scope_minimum,
            groups=(),
            representative_offsets=(),
            matched_rename_count=0,
            valid_scope=False,
            limitations=(
                f"unknown rename scope: {scope!r}; expected one of "
                f"{sorted((TRANSITION_SCOPE_ALL, TRANSITION_SCOPE_DIRECT_USER_SHARED))}",
            ),
        )

    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for offset, event in enumerate(events):
        event_process_key = transition_process_key(event)
        if not event_process_key or (process_key and event_process_key != process_key):
            continue
        if not is_successful_extension_rename(event):
            continue
        source_path = transition_target_path(event)
        destination_path = rename_destination_path(event)
        extension_change = extension_change_from_rename(source_path, destination_path)
        if extension_change is None:
            continue
        destination_extension, rename_kind = extension_change
        target_scope = direct_user_shared_target_scope(source_path)
        if normalized_scope == TRANSITION_SCOPE_DIRECT_USER_SHARED and not target_scope:
            continue
        group_scope = target_scope or "other"
        group = groups.setdefault(
            (event_process_key, group_scope, destination_extension, rename_kind),
            {
                "process_instance": transition_process_instance(event, event_process_key),
                "target_scope": group_scope,
                "destination_extension": destination_extension,
                "rename_kind": rename_kind,
                "renames": [],
            },
        )
        group["renames"].append(
            {
                "source_path": source_path,
                "destination_path": destination_path,
                "destination_extension": destination_extension,
                "rename_kind": rename_kind,
                "rename_offset": offset,
                "operation": str(event.get("action", {}).get("operation") or ""),
            }
        )

    matched = [
        group
        for group in groups.values()
        if len({str(rename["source_path"]) for rename in group["renames"]}) >= minimum
    ]
    matched.sort(
        key=lambda group: (
            -len({str(rename["source_path"]) for rename in group["renames"]}),
            str(group["process_instance"].get("key") or ""),
            str(group["target_scope"]),
            str(group["destination_extension"]),
        )
    )
    selected = matched[:limit]
    rows: list[dict[str, Any]] = []
    offsets: list[int] = []
    for group in selected:
        renames = sorted(group["renames"], key=lambda item: int(item["rename_offset"]))
        representatives = renames[:RENAME_REPRESENTATIVE_EVENT_LIMIT]
        unique_sources = {str(rename["source_path"]) for rename in renames}
        rows.append(
            {
                "summary": (
                    f"process={group['process_instance'].get('key')}; "
                    f"target_scope={group['target_scope']}; "
                    f"destination_extension={group['destination_extension']}; "
                    f"rename_kind={group['rename_kind']}; "
                    f"rename_count={len(renames)}; "
                    f"unique_original_count={len(unique_sources)}"
                ),
                "representative_renames": representatives,
                "process_instance": group["process_instance"],
                "target_scope": group["target_scope"],
                "destination_extension": group["destination_extension"],
                "rename_kind": group["rename_kind"],
                "rename_count": len(renames),
                "unique_original_count": len(unique_sources),
                "destination_extension_examples": [str(group["destination_extension"])],
            }
        )
        offsets.extend(int(rename["rename_offset"]) for rename in representatives)

    limitations = [
        "matches only successful same-process SetRenameInformation events with a parseable destination path",
        "requires the source and destination to remain in the same directory while changing extension",
        "direct user/shared scope excludes profile metadata, AppData, ProgramData, and system paths",
        "replacement-extension policy support requires at least 20 repeated direct-user renames across scopes",
        "broad policy support requires at least 20 same-process non-transient extension-append renames of distinct originals",
        "rename evidence does not prove file-content encryption or malicious intent",
    ]
    if len(selected) < len(matched):
        limitations.append("result truncated by group limit")
    if any(
        len(group["renames"]) > RENAME_REPRESENTATIVE_EVENT_LIMIT
        for group in selected
    ):
        limitations.append("representative renames are bounded per group")
    return FileExtensionRenameSearch(
        scope=normalized_scope,
        min_rename_count=minimum,
        min_scope_count=scope_minimum,
        groups=tuple(rows),
        representative_offsets=tuple(dict.fromkeys(offsets)),
        matched_rename_count=sum(len(group["renames"]) for group in matched),
        limitations=tuple(limitations),
    )

def is_successful_extension_rename(event: dict[str, Any]) -> bool:
    action = event.get("action", {})
    operation = str(action.get("operation") or "").casefold()
    family = str(action.get("operation_family") or "") or classify_operation_family(operation)
    return (
        family == "file_rename"
        and "setrenameinformation" in operation
        and is_success_result(action.get("result"))
    )


def rename_destination_path(event: dict[str, Any]) -> str:
    detail = event.get("detail", {})
    parsed = detail.get("parsed")
    raw_destination = ""
    if isinstance(parsed, dict):
        raw_destination = str(parsed.get("rename_destination") or "")
    if not raw_destination:
        raw_detail = str(detail.get("raw_detail") or "")
        marker = "filename:"
        marker_index = raw_detail.casefold().rfind(marker)
        if marker_index >= 0:
            raw_destination = raw_detail[marker_index + len(marker):].strip()
    normalized = raw_destination.replace("/", "\\").strip().casefold()
    if normalized.startswith("\\??\\"):
        normalized = normalized[4:]
    return normalized


def extension_change_from_rename(
    source_path: str,
    destination_path: str,
) -> tuple[str, str] | None:
    if not source_path or not destination_path:
        return None
    source_parent, source_separator, source_name = source_path.rpartition("\\")
    destination_parent, destination_separator, destination_name = destination_path.rpartition("\\")
    if not source_separator or not destination_separator or source_parent != destination_parent:
        return None
    source_extension = source_name.rpartition(".")[2] if "." in source_name else ""
    destination_extension = destination_name.rpartition(".")[2] if "." in destination_name else ""
    if not destination_extension or destination_extension == source_extension:
        return None
    if destination_path.startswith(source_path + "."):
        return destination_extension, "extension_append"
    return destination_extension, "extension_replacement"

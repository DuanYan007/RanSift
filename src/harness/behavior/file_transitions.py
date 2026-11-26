"""Deterministic, process-scoped file-extension transition evidence."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from .classification import (
    DETERMINISTIC_DIRECT_USER_EXTENSION_TRANSITION_RULE,
    DETERMINISTIC_REPEATED_EXTENSION_TRANSFORMATION_RULE,
)
from .classification import classify_operation_family


MAX_TRANSITION_ORDER_GAP = 5000
TRANSITION_REPRESENTATIVE_PAIR_LIMIT = 3
MIN_BROAD_DESTRUCTIVE_TRANSFORMATION_PAIR_COUNT = 20
TRANSITION_SCOPE_ALL = "all"
TRANSITION_SCOPE_DIRECT_USER_SHARED = "direct_user_shared"
TRANSITION_SCOPES = {TRANSITION_SCOPE_ALL, TRANSITION_SCOPE_DIRECT_USER_SHARED}
DIRECT_USER_PROFILE_FOLDERS = {
    "desktop",
    "documents",
    "downloads",
    "music",
    "onedrive",
    "pictures",
    "videos",
}
PROFILE_METADATA_FILENAMES = {
    "desktop.ini",
    "thumbs.db",
    "ntuser.dat",
    "ntuser.ini",
}


BENIGN_ADDED_EXTENSION_SUFFIXES = {
    "bak",
    "backup",
    "cache",
    "crdownload",
    "download",
    "journal",
    "lck",
    "log",
    "new",
    "old",
    "part",
    "partial",
    "temp",
    "tmp",
}

@dataclass(frozen=True)
class FileExtensionTransitionSearch:
    scope: str
    min_pair_count: int
    max_order_gap: int
    groups: tuple[dict[str, Any], ...]
    representative_offsets: tuple[int, ...]
    matched_pair_count: int
    valid_scope: bool = True
    limitations: tuple[str, ...] = ()

    def aggregates(self) -> dict[str, Any]:
        payload = {
            "transition_summary": {
                "matched_pair_count": self.matched_pair_count,
                "matched_group_count": len(self.groups),
                "scope": self.scope,
                "min_pair_count": self.min_pair_count,
                "max_order_gap": self.max_order_gap,
            },
            "group_summaries": [str(group.get("summary") or "") for group in self.groups],
            "groups": list(self.groups),
        }
        payload["deterministic_rule_supports"] = [dict(item) for item in self.deterministic_rule_supports()]
        return payload


    def deterministic_rule_supports(self) -> tuple[dict[str, Any], ...]:
        """Return high-precision transition pairs eligible for policy enforcement."""
        direct_user_rule = (
            self.scope == TRANSITION_SCOPE_DIRECT_USER_SHARED
            and self.min_pair_count >= 3
        )
        broad_repeated_rule = (
            self.scope == TRANSITION_SCOPE_ALL
            and self.min_pair_count >= MIN_BROAD_DESTRUCTIVE_TRANSFORMATION_PAIR_COUNT
        )
        if not direct_user_rule and not broad_repeated_rule:
            return ()
        supports: list[dict[str, Any]] = []
        for group in self.groups:
            pair_count = int(group.get("pair_count") or 0)
            extension = str(group.get("extension") or "").casefold()
            if direct_user_rule and pair_count < self.min_pair_count:
                continue
            if broad_repeated_rule and (
                pair_count < MIN_BROAD_DESTRUCTIVE_TRANSFORMATION_PAIR_COUNT
                or extension in BENIGN_ADDED_EXTENSION_SUFFIXES
            ):
                continue
            pairs = group.get("representative_pairs")
            if not isinstance(pairs, list) or not pairs:
                continue
            pair = pairs[0]
            if not isinstance(pair, dict):
                continue
            try:
                write_offset = int(pair["write_offset"])
                delete_offset = int(pair["delete_offset"])
            except (KeyError, TypeError, ValueError):
                continue
            process = group.get("process_instance")
            supports.append(
                {
                    "rule_id": (
                        DETERMINISTIC_DIRECT_USER_EXTENSION_TRANSITION_RULE
                        if direct_user_rule
                        else DETERMINISTIC_REPEATED_EXTENSION_TRANSFORMATION_RULE
                    ),
                    "evidence_ref_ids": (f"event:{write_offset}", f"event:{delete_offset}"),
                    "process_key": str(process.get("key") or "") if isinstance(process, dict) else "",
                    "target_scope": str(group.get("target_scope") or ""),
                    "extension": str(group.get("extension") or ""),
                    "pair_count": pair_count,
                }
            )
        return tuple(supports)

def search_file_extension_transitions(
    events: Iterable[dict[str, Any] | tuple[int, dict[str, Any]]],
    process_key: str | None = None,
    scope: str = TRANSITION_SCOPE_ALL,
    min_pair_count: int = 1,
    max_order_gap: int = 250,
    group_limit: int = 20,
) -> FileExtensionTransitionSearch:
    """Find write-to-added-extension then delete-original pairs in one process.

    A result exposes the event pairs that establish the transition, while the
    caller remains responsible for any behavioral or intent judgment.
    """
    normalized_scope = normalize_transition_scope(scope)
    minimum = bounded_positive_int(min_pair_count, maximum=200, default=1)
    maximum_gap = bounded_positive_int(max_order_gap, maximum=MAX_TRANSITION_ORDER_GAP, default=250)
    limit = bounded_positive_int(group_limit, maximum=200, default=20)
    if normalized_scope is None:
        return FileExtensionTransitionSearch(
            scope=str(scope),
            min_pair_count=minimum,
            max_order_gap=maximum_gap,
            groups=(),
            representative_offsets=(),
            matched_pair_count=0,
            valid_scope=False,
            limitations=(
                f"unknown transition scope: {scope!r}; expected one of {sorted(TRANSITION_SCOPES)}",
            ),
        )

    latest_writes: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for offset, event in iter_numbered_events(events):
        event_process_key = transition_process_key(event)
        if not event_process_key or (process_key and event_process_key != process_key):
            continue
        target = transition_target_path(event)
        if not target:
            continue

        if is_successful_content_write(event):
            split = split_added_extension(target)
            if split is None:
                continue
            original_path, extension = split
            latest_writes[(event_process_key, original_path)][extension] = {
                "write_offset": offset,
                "derived_path": target,
                "write_time": transition_timestamp(event),
                "write_operation": str(event.get("action", {}).get("operation") or ""),
            }
            continue

        if not is_successful_file_delete(event):
            continue
        candidates = latest_writes.get((event_process_key, target))
        if not candidates:
            continue
        target_scope = direct_user_shared_target_scope(target)
        if normalized_scope == TRANSITION_SCOPE_DIRECT_USER_SHARED and not target_scope:
            continue
        group_scope = target_scope or "other"
        for extension, write in tuple(candidates.items()):
            order_gap = offset - int(write["write_offset"])
            if order_gap <= 0:
                continue
            if order_gap > maximum_gap:
                del candidates[extension]
                continue
            pair = {
                "original_path": target,
                "derived_path": str(write["derived_path"]),
                "write_offset": int(write["write_offset"]),
                "delete_offset": offset,
                "order_gap": order_gap,
                "time_gap_s": transition_time_gap(write["write_time"], transition_timestamp(event)),
                "write_operation": str(write["write_operation"]),
                "delete_operation": str(event.get("action", {}).get("operation") or ""),
            }
            group_key = (event_process_key, extension, group_scope)
            group = groups.setdefault(
                group_key,
                {
                    "process_instance": transition_process_instance(event, event_process_key),
                    "extension": extension,
                    "target_scope": group_scope,
                    "pairs": [],
                },
            )
            group["pairs"].append(pair)
            del candidates[extension]

    matched = [group for group in groups.values() if len(group["pairs"]) >= minimum]
    matched.sort(
        key=lambda group: (
            -len(group["pairs"]),
            str(group["process_instance"].get("key") or ""),
            str(group["extension"]),
            str(group["target_scope"]),
        )
    )
    selected = matched[:limit]
    rows: list[dict[str, Any]] = []
    offsets: list[int] = []
    for group in selected:
        pairs = sorted(group["pairs"], key=lambda pair: (pair["delete_offset"], pair["write_offset"]))
        representative_pairs = pairs[:TRANSITION_REPRESENTATIVE_PAIR_LIMIT]
        rows.append(
            {
                "summary": (
                    f"process={group['process_instance'].get('key')}; extension={group['extension']}; "
                    f"target_scope={group['target_scope']}; pair_count={len(pairs)}; "
                    f"unique_original_count={len({pair['original_path'] for pair in pairs})}"
                ),
                "representative_pairs": representative_pairs,
                "process_instance": group["process_instance"],
                "extension": group["extension"],
                "target_scope": group["target_scope"],
                "pair_count": len(pairs),
                "unique_original_count": len({pair["original_path"] for pair in pairs}),
            }
        )
        for pair in representative_pairs:
            offsets.extend((pair["write_offset"], pair["delete_offset"]))
    limitations = [
        "matches only same-process successful WriteFile events followed by successful original-file deletion",
        f"write and delete must occur within {maximum_gap} retained-event positions",
        "paired transitions do not prove file content encryption or malicious intent",
    ]
    if broad_repeated_transition_query(normalized_scope, minimum):
        limitations.append(
            "broad destructive-policy support requires at least 20 repeated non-transient added-extension transitions"
        )
    if len(selected) < len(matched):
        limitations.append("result truncated by group limit")
    if any(len(group["pairs"]) > TRANSITION_REPRESENTATIVE_PAIR_LIMIT for group in selected):
        limitations.append("representative pairs are bounded per group")
    return FileExtensionTransitionSearch(
        scope=normalized_scope,
        min_pair_count=minimum,
        max_order_gap=maximum_gap,
        groups=tuple(rows),
        representative_offsets=tuple(dict.fromkeys(offsets)),
        matched_pair_count=sum(len(group["pairs"]) for group in matched),
        limitations=tuple(limitations),
    )


def normalize_transition_scope(scope: str) -> str | None:
    value = str(scope or TRANSITION_SCOPE_ALL).strip().casefold()
    return value if value in TRANSITION_SCOPES else None


def bounded_positive_int(value: Any, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, maximum))


def iter_numbered_events(
    events: Iterable[dict[str, Any] | tuple[int, dict[str, Any]]],
):
    """Preserve catalog offsets while retaining list-backed compatibility."""
    for fallback_offset, item in enumerate(events):
        if (
            isinstance(item, tuple)
            and len(item) == 2
            and isinstance(item[0], int)
            and isinstance(item[1], dict)
        ):
            yield int(item[0]), item[1]
        elif isinstance(item, dict):
            yield fallback_offset, item


def broad_repeated_transition_query(scope: str, minimum: int) -> bool:
    return (
        scope == TRANSITION_SCOPE_ALL
        and minimum >= MIN_BROAD_DESTRUCTIVE_TRANSFORMATION_PAIR_COUNT
    )


def transition_process_key(event: dict[str, Any]) -> str:
    process = event.get("process_context", {})
    process_key = str(process.get("process_key") or process.get("key") or "").strip()
    if process_key:
        return process_key
    node_id = str(process.get("node_id") or "").strip()
    process_name = str(process.get("process_name") or "").strip().casefold()
    try:
        pid = int(process.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    if not node_id and not process_name and not pid:
        return ""
    return f"{node_id or 'node_unknown'}|{pid}|{process_name}"


def transition_process_instance(event: dict[str, Any], process_key: str) -> dict[str, Any]:
    process = event.get("process_context", {})
    return {
        "key": process_key,
        "node_id": process.get("node_id"),
        "pid": process.get("pid"),
        "process_name": process.get("process_name"),
    }


def transition_target_path(event: dict[str, Any]) -> str:
    target = event.get("target", {})
    value = target.get("normalized_path") or target.get("path") or ""
    return str(value).strip().replace("/", "\\").casefold()


def is_successful_content_write(event: dict[str, Any]) -> bool:
    action = event.get("action", {})
    return str(action.get("operation") or "").casefold() == "writefile" and is_success_result(action.get("result"))


def is_successful_file_delete(event: dict[str, Any]) -> bool:
    action = event.get("action", {})
    family = str(action.get("operation_family") or "") or classify_operation_family(str(action.get("operation") or ""))
    return family == "file_delete" and is_success_result(action.get("result"))


def is_success_result(value: Any) -> bool:
    return str(value or "").strip().casefold() == "success"


def split_added_extension(path: str) -> tuple[str, str] | None:
    original_path, separator, extension = path.rpartition(".")
    if not separator or not original_path or not extension or "\\" in extension:
        return None
    return original_path, extension


def direct_user_shared_target_scope(path: str) -> str:
    normalized = str(path).strip().replace("/", "\\").casefold()
    if is_profile_metadata_path(normalized):
        return ""
    if normalized.startswith("\\\\"):
        return "network_share"
    if normalized.startswith(("c:\\share\\", "c:\\shares\\", "c:\\shared\\")):
        return "local_share"
    users_prefix = "c:\\users\\"
    if not normalized.startswith(users_prefix):
        return ""
    segments = [segment for segment in normalized[len(users_prefix):].split("\\") if segment]
    if len(segments) < 2:
        return ""
    if segments[0] == "public":
        return "public"
    folder = segments[1]
    if folder in DIRECT_USER_PROFILE_FOLDERS:
        return f"user_{folder}"
    return ""


def is_profile_metadata_path(path: str) -> bool:
    return path.rsplit("\\", 1)[-1] in PROFILE_METADATA_FILENAMES


def transition_timestamp(event: dict[str, Any]) -> float | None:
    try:
        return float(event.get("time", {}).get("timestamp"))
    except (TypeError, ValueError):
        return None


def transition_time_gap(start: float | None, end: float | None) -> float | None:
    if start is None or end is None:
        return None
    return round(end - start, 6)

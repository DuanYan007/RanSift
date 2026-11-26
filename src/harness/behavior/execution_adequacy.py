"""Conservative checks for whether a retained execution can support no-risk."""
from __future__ import annotations

import re
from typing import Any, Iterable

from .concealed_execution import command_line, event_time


EXECUTION_OBSERVATION_SCHEMA = "harness-execution-observation-v2"
EARLY_ROOT_EXIT_SECONDS = 5.0
RECAPTURE_REASON_CODES = (
    "root_process_or_timing_not_observed",
    "root_early_abnormal_exit_with_linked_werfault",
    "root_early_abnormal_exit_without_payload_descendant",
)
EXIT_STATUS = re.compile(r"\bExit Status:\s*(?P<status>-?(?:0x)?[0-9a-f]+)\b", re.IGNORECASE)
WERFAULT_PID_ARGUMENT = re.compile(r"(?:^|\s)-p\s+(?P<pid>\d+)\b", re.IGNORECASE)


def assess_root_execution_adequacy(
    events: Iterable[tuple[int, dict[str, Any]]],
) -> dict[str, Any]:
    """Reject executions with a deterministic early root-launch failure.

    A linked WerFault remains the strongest crash signal, but it is not required:
    a nonzero root exit before any non-crash descendant is also insufficient.
    Normal quick exits remain adequate until a separate activation contract can
    distinguish them from intentionally short-lived benign programs.
    """
    root: dict[str, Any] | None = None
    root_start_time: float | None = None
    exit_events: list[tuple[int, dict[str, Any], float | None, int | None]] = []
    werfault_events: list[tuple[int, dict[str, Any]]] = []
    attributed_processes: dict[str, dict[str, Any]] = {}

    for offset, event in events:
        context = event.get("process_context") or {}
        if not isinstance(context, dict):
            continue
        identity = process_identity(context)
        if identity:
            attributed_processes.setdefault(identity, dict(context))
        if root is None and process_depth(context) == 0 and root_pid(context) is not None:
            root = dict(context)

        if root is None or not same_process(context, root):
            continue
        timestamp = event_time(event)
        if timestamp is not None and (root_start_time is None or timestamp < root_start_time):
            root_start_time = timestamp
        operation = str((event.get("action") or {}).get("operation") or "").casefold().strip()
        if operation == "process exit":
            exit_events.append((int(offset), event, timestamp, exit_status(event)))
        elif operation in {"process create", "process start"} and is_linked_werfault(event, root_pid(root)):
            werfault_events.append((int(offset), event))

    if root is None or root_start_time is None:
        return insufficient_observation(
            "root_process_or_timing_not_observed",
            [],
            "The retained trace does not identify a timed root-process execution.",
        )

    linked_exit = next(
        (
            item
            for item in exit_events
            if item[2] is not None
            and item[3] not in {None, 0}
            and 0.0 <= float(item[2]) - root_start_time <= EARLY_ROOT_EXIT_SECONDS
        ),
        None,
    )
    if linked_exit is None:
        return adequate_observation("no_linked_early_abnormal_root_exit")

    root_identity = process_identity(root)
    werfault_identities = {
        identity
        for identity, context in attributed_processes.items()
        if "werfault" in str(context.get("process_name") or "").casefold()
    }
    non_crash_descendants = {
        identity
        for identity in attributed_processes
        if identity and identity != root_identity and identity not in werfault_identities
    }
    if non_crash_descendants:
        return adequate_observation("additional_attributed_descendants_observed")

    exit_offset, exit_event, exit_time, status = linked_exit
    runtime_seconds = round(float(exit_time) - root_start_time, 6)
    reason = (
        "root_early_abnormal_exit_with_linked_werfault"
        if werfault_events
        else "root_early_abnormal_exit_without_payload_descendant"
    )
    evidence_ref_ids = [f"event:{exit_offset}"]
    if werfault_events:
        evidence_ref_ids.append(f"event:{werfault_events[0][0]}")
    return insufficient_observation(
        reason,
        evidence_ref_ids,
        (
            "The root process exited abnormally within the early observation window before "
            "any non-crash attributed descendant was observed."
        ),
        root_process={
            "pid": root_pid(root),
            "process_name": str(root.get("process_name") or ""),
            "process_key": str(root.get("process_key") or root.get("key") or ""),
        },
        root_runtime_seconds=runtime_seconds,
        exit_status=status,
        observed_process_count=len(attributed_processes),
    )


def insufficient_observation(
    reason: str,
    evidence_ref_ids: list[str],
    summary: str,
    *,
    root_process: dict[str, Any] | None = None,
    root_runtime_seconds: float | None = None,
    exit_status: int | None = None,
    observed_process_count: int = 0,
) -> dict[str, Any]:
    observation = {
        "schema_version": EXECUTION_OBSERVATION_SCHEMA,
        "status": "insufficient",
        "reason_codes": [reason],
        "evidence_ref_ids": evidence_ref_ids,
        "summary": summary,
    }
    if root_process is not None:
        observation.update({
            "root_process": root_process,
            "root_runtime_seconds": root_runtime_seconds,
            "exit_status": exit_status,
            "observed_process_count": int(observed_process_count),
        })
    return observation


def adequate_observation(reason: str) -> dict[str, Any]:
    return {
        "schema_version": EXECUTION_OBSERVATION_SCHEMA,
        "status": "adequate",
        "reason_codes": [reason],
        "evidence_ref_ids": [],
    }


def process_depth(context: dict[str, Any]) -> int:
    try:
        return int(context.get("depth") or 0)
    except (TypeError, ValueError):
        return 0


def root_pid(context: dict[str, Any]) -> int | None:
    try:
        value = int(context.get("pid") or 0)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def process_identity(context: dict[str, Any]) -> str:
    key = str(context.get("process_key") or context.get("key") or "").strip()
    if key:
        return key
    pid = root_pid(context)
    name = str(context.get("process_name") or "").casefold().strip()
    return f"{pid}:{name}" if pid is not None else ""


def same_process(context: dict[str, Any], root: dict[str, Any]) -> bool:
    root_identity = process_identity(root)
    return bool(root_identity) and process_identity(context) == root_identity


def exit_status(event: dict[str, Any]) -> int | None:
    detail = event.get("detail") or {}
    raw = str(detail.get("raw_detail") or "") if isinstance(detail, dict) else ""
    match = EXIT_STATUS.search(raw)
    if match is None:
        return None
    try:
        return int(match.group("status"), 0)
    except ValueError:
        return None


def is_linked_werfault(event: dict[str, Any], expected_root_pid: int | None) -> bool:
    if expected_root_pid is None:
        return False
    action = event.get("action") or {}
    if str(action.get("result") or "").casefold().strip() != "success":
        return False
    command = command_line(event)
    target = event.get("target") or {}
    target_path = str(target.get("normalized_path") or target.get("path") or "")
    if "werfault" not in command.casefold() and "werfault" not in target_path.casefold():
        return False
    match = WERFAULT_PID_ARGUMENT.search(command)
    return match is not None and int(match.group("pid")) == expected_root_pid

"""Deterministic evidence for deployed elevated scheduled-task persistence."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .classification import DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE
from .concealed_execution import command_line, event_time, process_instance


MAX_DEPLOYMENT_TO_TASK_SECONDS = 120.0
AUTOSTART_TRIGGERS = frozenset({"onlogon", "onstart"})
SCHEDULED_TASK_COMMAND = re.compile(
    r"(?:^|\s)(?:[^\s]*\\)?schtasks(?:\.exe)?(?:\s|$)",
    re.IGNORECASE,
)
CREATE_SWITCH = re.compile(r"(?:^|\s)/create(?:\s|$)", re.IGNORECASE)
SCHEDULE_SWITCH = re.compile(r"(?:^|\s)/sc\s+(?P<trigger>onlogon|onstart)\b", re.IGNORECASE)
TASK_TARGET_SWITCH = re.compile(
    r"(?:^|\s)/tr\s+(?P<value>\"[^\"]+\"|'[^']+'|\S+)",
    re.IGNORECASE,
)
EXECUTABLE_PATH = re.compile(
    r"(?P<path>(?:[a-z]:\\|%[^%]+%\\)[^\"']*?\.(?:exe|com|scr))(?=\s|[\"']|$)",
    re.IGNORECASE,
)
RUN_AS_SYSTEM_SWITCH = re.compile(r"(?:^|\s)/ru\s+\"?system\"?(?=\s|$)", re.IGNORECASE)
RUN_LEVEL_HIGHEST_SWITCH = re.compile(r"(?:^|\s)/rl\s+highest(?=\s|$)", re.IGNORECASE)


@dataclass(frozen=True)
class AutostartPersistenceSearch:
    chains: tuple[dict[str, Any], ...]
    representative_offsets: tuple[int, ...]
    matched_chain_count: int

    def aggregates(self) -> dict[str, Any]:
        supports = [
            {
                "rule_id": DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE,
                "evidence_ref_ids": list(chain["evidence_ref_ids"]),
                "deployment_offset": int(chain["deployment_offset"]),
                "task_create_offset": int(chain["task_create_offset"]),
                "task_start_offset": int(chain["task_start_offset"]),
                "deployed_path": str(chain["deployed_path"]),
                "task_target": str(chain["task_target"]),
                "task_trigger": str(chain["task_trigger"]),
                "run_as_system": bool(chain["run_as_system"]),
                "run_level_highest": bool(chain["run_level_highest"]),
            }
            for chain in self.chains
        ]
        return {
            "deployed_elevated_autostart_task_summary": {
                "matched_chain_count": self.matched_chain_count,
                "returned_chain_count": len(self.chains),
            },
            "chains": [dict(chain) for chain in self.chains],
            "deterministic_rule_supports": supports,
        }


def search_deployed_elevated_autostart_tasks(
    events: Iterable[tuple[int, dict[str, Any]]],
    limit: int,
) -> AutostartPersistenceSearch:
    """Find a deployed executable followed by an executed elevated autostart task.

    The trace is already restricted to the submitted sample's process tree. A
    match still requires three concrete events: a successful executable write in
    a user-writable deployment location, a successful Process Create for an
    elevated ``schtasks /CREATE`` command, and that child command interpreter's
    successful Process Start. The task target must equal the deployed path.
    """
    deployments_by_path: dict[str, list[dict[str, Any]]] = {}
    creates_by_child: dict[tuple[str, int], list[dict[str, Any]]] = {}
    chains: list[dict[str, Any]] = []
    used_start_offsets: set[int] = set()

    for offset, event in events:
        if is_executable_deployment(event):
            path = normalized_target_path(event)
            deployments_by_path.setdefault(path, []).append(
                {
                    "offset": int(offset),
                    "time": event_time(event),
                    "path": path,
                    "process_instance": process_instance(event),
                }
            )

        task = parse_elevated_autostart_task(command_line(event))
        if task is None or not is_successful_process_event(event):
            continue

        operation = normalized_operation(event)
        if operation == "process create":
            child_pid = created_process_pid(event)
            if child_pid is not None:
                creates_by_child.setdefault((task["target"], child_pid), []).append(
                    {
                        "offset": int(offset),
                        "time": event_time(event),
                        "task": task,
                        "process_instance": process_instance(event),
                    }
                )
            continue

        if operation != "process start" or int(offset) in used_start_offsets:
            continue
        child_pid = current_process_pid(event)
        if child_pid is None:
            continue
        candidates = creates_by_child.get((task["target"], child_pid), [])
        create = next(
            (
                item
                for item in reversed(candidates)
                if int(item["offset"]) < int(offset)
                and same_task_shape(item["task"], task)
            ),
            None,
        )
        if create is None:
            continue
        deployment = nearest_deployment(
            deployments_by_path.get(task["target"], []),
            create,
        )
        if deployment is None:
            continue
        used_start_offsets.add(int(offset))
        chains.append(
            {
                "rule_id": DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE,
                "evidence_ref_ids": [
                    f"event:{deployment['offset']}",
                    f"event:{create['offset']}",
                    f"event:{int(offset)}",
                ],
                "deployment_offset": int(deployment["offset"]),
                "task_create_offset": int(create["offset"]),
                "task_start_offset": int(offset),
                "deployed_path": str(deployment["path"]),
                "task_target": str(task["target"]),
                "task_trigger": str(task["trigger"]),
                "run_as_system": bool(task["run_as_system"]),
                "run_level_highest": bool(task["run_level_highest"]),
                "deployment_process_instance": dict(deployment["process_instance"]),
                "task_create_process_instance": dict(create["process_instance"]),
                "task_start_process_instance": process_instance(event),
            }
        )

    selected = chains[: max(0, int(limit))]
    representative_offsets = tuple(
        dict.fromkeys(
            offset
            for chain in selected
            for offset in (
                int(chain["deployment_offset"]),
                int(chain["task_create_offset"]),
                int(chain["task_start_offset"]),
            )
        )
    )
    return AutostartPersistenceSearch(
        chains=tuple(selected),
        representative_offsets=representative_offsets,
        matched_chain_count=len(chains),
    )


def is_executable_deployment(event: dict[str, Any]) -> bool:
    action = event.get("action") or {}
    if str(action.get("result") or "").casefold().strip() != "success":
        return False
    if str(action.get("operation_family") or "").casefold().strip() != "file_write":
        return False
    path = normalized_target_path(event)
    return path.endswith((".exe", ".com", ".scr")) and is_user_writable_deployment_path(path)


def is_user_writable_deployment_path(path: str) -> bool:
    if path.startswith("c:\\programdata\\"):
        return True
    if not path.startswith("c:\\users\\"):
        return False
    return "\\appdata\\" in path or "\\start menu\\programs\\startup\\" in path


def is_successful_process_event(event: dict[str, Any]) -> bool:
    action = event.get("action") or {}
    return str(action.get("result") or "").casefold().strip() == "success"


def normalized_operation(event: dict[str, Any]) -> str:
    action = event.get("action") or {}
    return str(action.get("operation") or "").casefold().strip()


def normalized_target_path(event: dict[str, Any]) -> str:
    target = event.get("target") or {}
    raw = str(target.get("normalized_path") or target.get("path") or "")
    return normalize_windows_path(raw)


def parse_elevated_autostart_task(command: str) -> dict[str, Any] | None:
    text = str(command or "").strip()
    if not text or not SCHEDULED_TASK_COMMAND.search(text) or not CREATE_SWITCH.search(text):
        return None
    trigger_match = SCHEDULE_SWITCH.search(text)
    if trigger_match is None:
        return None
    target_match = TASK_TARGET_SWITCH.search(text)
    if target_match is None:
        return None
    target = executable_path_from_task_target(target_match.group("value"))
    if not target:
        return None
    run_as_system = bool(RUN_AS_SYSTEM_SWITCH.search(text))
    run_level_highest = bool(RUN_LEVEL_HIGHEST_SWITCH.search(text))
    if not (run_as_system and run_level_highest):
        return None
    trigger = trigger_match.group("trigger").casefold()
    if trigger not in AUTOSTART_TRIGGERS:
        return None
    return {
        "target": target,
        "trigger": trigger,
        "run_as_system": run_as_system,
        "run_level_highest": run_level_highest,
    }


def executable_path_from_task_target(value: str) -> str:
    text = str(value or "").strip().strip("\"'")
    match = EXECUTABLE_PATH.search(text)
    if match is None:
        return ""
    return normalize_windows_path(match.group("path"))


def normalize_windows_path(value: str) -> str:
    path = str(value or "").strip().strip("\"'").replace("/", "\\").casefold()
    if path.startswith("%programdata%\\"):
        path = "c:\\programdata\\" + path[len("%programdata%\\"):]
    return path


def created_process_pid(event: dict[str, Any]) -> int | None:
    parsed = (event.get("detail") or {}).get("parsed") or {}
    if not isinstance(parsed, dict):
        return None
    try:
        value = int(parsed.get("child_pid") or 0)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def current_process_pid(event: dict[str, Any]) -> int | None:
    context = event.get("process_context") or {}
    if not isinstance(context, dict):
        return None
    try:
        value = int(context.get("pid") or 0)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def same_task_shape(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        str(left.get("target") or "") == str(right.get("target") or "")
        and str(left.get("trigger") or "") == str(right.get("trigger") or "")
        and bool(left.get("run_as_system")) == bool(right.get("run_as_system"))
        and bool(left.get("run_level_highest")) == bool(right.get("run_level_highest"))
    )


def nearest_deployment(
    deployments: list[dict[str, Any]],
    task_create: dict[str, Any],
) -> dict[str, Any] | None:
    eligible = [
        deployment
        for deployment in deployments
        if int(deployment["offset"]) < int(task_create["offset"])
        and within_deployment_window(deployment, task_create)
    ]
    if not eligible:
        return None
    return max(eligible, key=lambda item: int(item["offset"]))


def within_deployment_window(deployment: dict[str, Any], task_create: dict[str, Any]) -> bool:
    deployment_time = deployment.get("time")
    task_time = task_create.get("time")
    if isinstance(deployment_time, float) and isinstance(task_time, float):
        return 0.0 <= task_time - deployment_time <= MAX_DEPLOYMENT_TO_TASK_SECONDS
    return True

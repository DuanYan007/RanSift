"""Deterministic candidate evidence for executable Run and RunOnce bindings."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .classification import DETERMINISTIC_RUN_KEY_EXECUTABLE_BINDING_RULE
from .file_transitions import (
    is_success_result,
    transition_process_instance,
    transition_process_key,
    transition_target_path,
)


RUN_KEY_PATTERN = re.compile(
    r"(?:^|\\)software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\run(?:once)?(?:\\|$)",
    re.IGNORECASE,
)
EXECUTABLE_PAYLOAD_PATTERN = re.compile(
    r"(?P<path>(?:[a-z]:\\|%[^%]+%\\|\\\\[^\\]+\\[^\\]+\\)[^\"'\r\n]*?\.(?:com|exe|pif|scr))(?=(?:[\"'\s,]|$))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RunKeyExecutableBindingSearch:
    bindings: tuple[dict[str, Any], ...]
    representative_offsets: tuple[int, ...]
    matched_binding_count: int
    limitations: tuple[str, ...]

    def aggregates(self) -> dict[str, Any]:
        supports = [
            {
                "rule_id": DETERMINISTIC_RUN_KEY_EXECUTABLE_BINDING_RULE,
                "evidence_ref_ids": [f"event:{int(binding['event_offset'])}"],
                "registry_key": str(binding["registry_key"]),
                "payload_path": str(binding["payload_path"]),
                "process_instance": dict(binding.get("process_instance") or {}),
            }
            for binding in self.bindings
        ]
        return {
            "run_key_executable_binding_summary": {
                "matched_binding_count": self.matched_binding_count,
                "returned_binding_count": len(self.bindings),
            },
            "bindings": [dict(binding) for binding in self.bindings],
            "deterministic_rule_supports": supports,
        }


def search_run_key_executable_bindings(
    events: Iterable[tuple[int, dict[str, Any]]],
    limit: int,
) -> RunKeyExecutableBindingSearch:
    """Find successful RegSetValue events that bind Run/RunOnce to an executable.

    Key creation is intentionally excluded. The observation must be a successful
    value write to a recognized autostart key and the written value must expose a
    concrete executable path.
    """

    bindings = []
    for offset, event in events:
        if not is_successful_run_value_write(event):
            continue
        registry_key = transition_target_path(event)
        if not is_run_key(registry_key):
            continue
        payload_path = executable_payload_path(event)
        if not payload_path:
            continue
        process_key = transition_process_key(event)
        if not process_key:
            continue
        bindings.append(
            {
                "summary": (
                    f"process={process_key}; registry_key={registry_key}; "
                    f"payload_path={payload_path}"
                ),
                "process_instance": transition_process_instance(event, process_key),
                "registry_key": registry_key,
                "payload_path": payload_path,
                "event_offset": int(offset),
            }
        )
    bindings.sort(key=lambda binding: (int(binding["event_offset"]), str(binding["registry_key"])))
    selected = tuple(bindings[: max(0, int(limit))])
    return RunKeyExecutableBindingSearch(
        bindings=selected,
        representative_offsets=tuple(int(binding["event_offset"]) for binding in selected),
        matched_binding_count=len(bindings),
        limitations=(
            "requires successful RegSetValue, a recognized Run or RunOnce key, and an executable payload path",
            "does not establish that the configured payload later ran at logon or reboot",
        ),
    )


def is_successful_run_value_write(event: dict[str, Any]) -> bool:
    action = event.get("action") or {}
    return (
        str(action.get("operation") or "").casefold() == "regsetvalue"
        and is_success_result(action.get("result"))
    )


def is_run_key(registry_key: str) -> bool:
    return bool(RUN_KEY_PATTERN.search(str(registry_key or "").replace("/", "\\")))


def executable_payload_path(event: dict[str, Any]) -> str:
    detail = str((event.get("detail") or {}).get("raw_detail") or "")
    data_match = re.search(r"(?:^|,)\s*data:\s*(?P<data>.+)$", detail, re.IGNORECASE)
    if data_match is None:
        return ""
    payload_match = EXECUTABLE_PAYLOAD_PATTERN.search(data_match.group("data"))
    if payload_match is None:
        return ""
    return payload_match.group("path").replace("/", "\\").casefold()

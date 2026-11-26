"""Deterministic evidence for concealed, encoded script execution chains."""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .classification import DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE


MAX_DECODED_LAYER_COUNT = 3
MAX_DECODED_PAYLOAD_CHARS = 65_536
MAX_BASE64_CANDIDATES_PER_LAYER = 8
MAX_CHAIN_TIME_GAP_SECONDS = 120.0

ENCODED_POWERSHELL_ARGUMENT = re.compile(
    r"(?:^|\s)-(?:encodedcommand|encoded|enc)(?:\s+|:)(?P<payload>[\"']?[A-Za-z0-9+/=]{16,}[\"']?)",
    re.IGNORECASE,
)
BASE64_LITERAL = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
SHOW_WINDOW_HIDDEN = re.compile(
    r"\bshowwindow(?:async)?\s*\([^)]*,\s*(?:0|sw_hide)\s*\)",
    re.IGNORECASE,
)
WINDOW_STYLE_HIDDEN = re.compile(r"(?:-windowstyle|-w)\s+hidden\b", re.IGNORECASE)


@dataclass(frozen=True)
class ConcealedScriptHostFingerprintSearch:
    chains: tuple[dict[str, Any], ...]
    representative_offsets: tuple[int, ...]
    matched_chain_count: int

    def aggregates(self) -> dict[str, Any]:
        supports = [
            {
                "rule_id": DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE,
                "evidence_ref_ids": list(chain["evidence_ref_ids"]),
                "encoded_execution_offset": int(chain["encoded_execution_offset"]),
                "host_fingerprint_offset": int(chain["host_fingerprint_offset"]),
                "concealment_markers": list(chain["concealment_markers"]),
                "host_fingerprint_kind": str(chain["host_fingerprint_kind"]),
                "decoded_layer_count": int(chain["decoded_layer_count"]),
            }
            for chain in self.chains
        ]
        return {
            "concealed_script_host_fingerprinting_summary": {
                "matched_chain_count": self.matched_chain_count,
                "returned_chain_count": len(self.chains),
            },
            "chains": [dict(chain) for chain in self.chains],
            "deterministic_rule_supports": supports,
        }


def search_concealed_script_host_fingerprinting(
    events: Iterable[tuple[int, dict[str, Any]]],
    limit: int,
) -> ConcealedScriptHostFingerprintSearch:
    """Find attributed encoded-script execution combined with concealment and host fingerprinting.

    The detector never executes decoded content. It only decodes bounded Base64 layers
    from successful PowerShell process-start command lines, then requires an explicit
    window-concealment semantic and a separate successful hardware-identifier query.
    """
    encoded_executions: list[dict[str, Any]] = []
    fingerprint_queries: list[dict[str, Any]] = []
    for offset, event in events:
        if not is_successful_process_start(event):
            continue
        command = command_line(event)
        if not command:
            continue
        decoded_layers = decode_encoded_powershell(command)
        concealment = concealment_markers(decoded_layers)
        if decoded_layers and concealment:
            encoded_executions.append(
                {
                    "offset": int(offset),
                    "time": event_time(event),
                    "concealment_markers": concealment,
                    "decoded_layer_count": len(decoded_layers),
                    "process_instance": process_instance(event),
                }
            )
        fingerprint_kind = host_fingerprint_kind(command)
        if fingerprint_kind:
            fingerprint_queries.append(
                {
                    "offset": int(offset),
                    "time": event_time(event),
                    "host_fingerprint_kind": fingerprint_kind,
                    "process_instance": process_instance(event),
                }
            )

    chains: list[dict[str, Any]] = []
    used_fingerprint_offsets: set[int] = set()
    for execution in sorted(encoded_executions, key=lambda item: int(item["offset"])):
        fingerprint = nearest_fingerprint_query(
            execution,
            fingerprint_queries,
            used_fingerprint_offsets,
        )
        if fingerprint is None:
            continue
        encoded_offset = int(execution["offset"])
        fingerprint_offset = int(fingerprint["offset"])
        if encoded_offset == fingerprint_offset:
            continue
        used_fingerprint_offsets.add(fingerprint_offset)
        chains.append(
            {
                "rule_id": DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE,
                "evidence_ref_ids": [f"event:{encoded_offset}", f"event:{fingerprint_offset}"],
                "encoded_execution_offset": encoded_offset,
                "host_fingerprint_offset": fingerprint_offset,
                "concealment_markers": list(execution["concealment_markers"]),
                "host_fingerprint_kind": str(fingerprint["host_fingerprint_kind"]),
                "decoded_layer_count": int(execution["decoded_layer_count"]),
                "encoded_process_instance": dict(execution["process_instance"]),
                "fingerprint_process_instance": dict(fingerprint["process_instance"]),
            }
        )

    selected = chains[: max(0, int(limit))]
    representative_offsets = tuple(
        dict.fromkeys(
            offset
            for chain in selected
            for offset in (
                int(chain["encoded_execution_offset"]),
                int(chain["host_fingerprint_offset"]),
            )
        )
    )
    return ConcealedScriptHostFingerprintSearch(
        chains=tuple(selected),
        representative_offsets=representative_offsets,
        matched_chain_count=len(chains),
    )


def is_successful_process_start(event: dict[str, Any]) -> bool:
    action = event.get("action") or {}
    return (
        str(action.get("operation") or "").casefold().strip() == "process start"
        and str(action.get("result") or "").casefold().strip() == "success"
    )


def command_line(event: dict[str, Any]) -> str:
    detail = event.get("detail") or {}
    parsed = detail.get("parsed") if isinstance(detail, dict) else None
    if isinstance(parsed, dict):
        command = str(parsed.get("command_line") or "").strip()
        if command:
            return command
    raw_detail = str(detail.get("raw_detail") or "") if isinstance(detail, dict) else ""
    marker = "command line:"
    index = raw_detail.casefold().find(marker)
    if index < 0:
        return ""
    command = raw_detail[index + len(marker):].strip()
    for delimiter in (", current directory:", ", environment:", "\r", "\n"):
        delimiter_index = command.casefold().find(delimiter)
        if delimiter_index >= 0:
            command = command[:delimiter_index]
    return command.strip()


def decode_encoded_powershell(command: str) -> tuple[str, ...]:
    if "powershell" not in command.casefold():
        return ()
    match = ENCODED_POWERSHELL_ARGUMENT.search(command)
    if match is None:
        return ()
    initial = decode_base64_texts(match.group("payload").strip("\"'"))
    if not initial:
        return ()
    decoded: list[str] = []
    queue: list[tuple[int, str]] = [(1, value) for value in initial]
    seen: set[str] = set()
    while queue:
        depth, text = queue.pop(0)
        if text in seen:
            continue
        seen.add(text)
        decoded.append(text)
        if depth >= MAX_DECODED_LAYER_COUNT:
            continue
        candidates = BASE64_LITERAL.findall(text)[:MAX_BASE64_CANDIDATES_PER_LAYER]
        for candidate in candidates:
            for nested in decode_base64_texts(candidate):
                if nested not in seen:
                    queue.append((depth + 1, nested))
    return tuple(decoded)


def decode_base64_texts(value: str) -> tuple[str, ...]:
    token = str(value or "").strip().strip("\"'")
    if len(token) < 16 or len(token) > MAX_DECODED_PAYLOAD_CHARS:
        return ()
    token += "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return ()
    if not raw or len(raw) > MAX_DECODED_PAYLOAD_CHARS:
        return ()
    values: list[str] = []
    for encoding in ("utf-16le", "utf-8", "utf-16"):
        try:
            decoded = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if looks_like_text(decoded) and decoded not in values:
            values.append(decoded)
    return tuple(values)


def looks_like_text(value: str) -> bool:
    if not value or len(value) > MAX_DECODED_PAYLOAD_CHARS:
        return False
    visible = sum(character.isprintable() or character in "\r\n\t" for character in value)
    return visible / len(value) >= 0.85


def concealment_markers(decoded_layers: tuple[str, ...]) -> tuple[str, ...]:
    markers: list[str] = []
    for layer in decoded_layers:
        if SHOW_WINDOW_HIDDEN.search(layer):
            markers.append("win32_showwindow_hidden")
        if WINDOW_STYLE_HIDDEN.search(layer):
            markers.append("powershell_windowstyle_hidden")
    return tuple(dict.fromkeys(markers))


def host_fingerprint_kind(command: str) -> str | None:
    text = command.casefold()
    if "wmic" in text and "csproduct" in text and "uuid" in text:
        return "wmic_csproduct_uuid"
    if "win32_computersystemproduct" in text and "uuid" in text:
        return "wmi_computer_system_product_uuid"
    if "wmic" in text and "bios" in text and "serial" in text:
        return "wmic_bios_serial"
    if "wmic" in text and "diskdrive" in text and "serial" in text:
        return "wmic_disk_serial"
    if "wmic" in text and "baseboard" in text and "serial" in text:
        return "wmic_baseboard_serial"
    return None


def nearest_fingerprint_query(
    execution: dict[str, Any],
    candidates: list[dict[str, Any]],
    used_offsets: set[int],
) -> dict[str, Any] | None:
    eligible = [
        candidate
        for candidate in candidates
        if int(candidate["offset"]) not in used_offsets and within_execution_window(execution, candidate)
    ]
    if not eligible:
        return None
    return min(eligible, key=lambda candidate: chain_distance(execution, candidate))


def within_execution_window(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_time = left.get("time")
    right_time = right.get("time")
    if isinstance(left_time, float) and isinstance(right_time, float):
        return abs(left_time - right_time) <= MAX_CHAIN_TIME_GAP_SECONDS
    return True


def chain_distance(left: dict[str, Any], right: dict[str, Any]) -> tuple[float, int]:
    left_time = left.get("time")
    right_time = right.get("time")
    if isinstance(left_time, float) and isinstance(right_time, float):
        return (abs(left_time - right_time), abs(int(left["offset"]) - int(right["offset"])))
    return (float(abs(int(left["offset"]) - int(right["offset"]))), 0)


def event_time(event: dict[str, Any]) -> float | None:
    time = event.get("time") or {}
    try:
        return float(time.get("timestamp"))
    except (AttributeError, TypeError, ValueError):
        return None


def process_instance(event: dict[str, Any]) -> dict[str, Any]:
    context = event.get("process_context") or {}
    if not isinstance(context, dict):
        return {}
    return {
        key: context[key]
        for key in ("key", "process_key", "node_id", "pid", "process_name", "depth")
        if context.get(key) is not None
    }

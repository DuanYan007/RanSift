"""Deterministic candidate evidence for ransom-note-like file artifacts."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .classification import DETERMINISTIC_RANSOM_NOTE_ARTIFACT_RULE
from .file_transitions import (
    is_success_result,
    transition_process_instance,
    transition_process_key,
    transition_target_path,
)


NOTE_FILE_EXTENSIONS = frozenset({"htm", "html", "hta", "md", "msg", "readme", "rtf", "txt", "url"})
NOTE_SEMANTIC_TERMS = ("decrypt", "decryption", "ransom", "recover", "recovery", "restore")
NOTE_CONTEXT_TERMS = ("files", "file", "how", "instruction", "instructions", "note", "readme")


@dataclass(frozen=True)
class RansomNoteArtifactSearch:
    artifacts: tuple[dict[str, Any], ...]
    representative_offsets: tuple[int, ...]
    matched_artifact_count: int
    matched_event_count: int
    limitations: tuple[str, ...]

    def aggregates(self) -> dict[str, Any]:
        supports = []
        for artifact in self.artifacts:
            refs = [f"event:{int(offset)}" for offset in artifact["representative_offsets"]]
            supports.append(
                {
                    "rule_id": DETERMINISTIC_RANSOM_NOTE_ARTIFACT_RULE,
                    "evidence_ref_ids": refs,
                    "note_path": str(artifact["note_path"]),
                    "note_basename": str(artifact["note_basename"]),
                    "operation_kinds": list(artifact["operation_kinds"]),
                    "process_instance": dict(artifact.get("process_instance") or {}),
                }
            )
        return {
            "ransom_note_artifact_summary": {
                "matched_artifact_count": self.matched_artifact_count,
                "returned_artifact_count": len(self.artifacts),
                "matched_event_count": self.matched_event_count,
            },
            "artifacts": [dict(artifact) for artifact in self.artifacts],
            "deterministic_rule_supports": supports,
        }


def search_ransom_note_artifacts(
    events: Iterable[tuple[int, dict[str, Any]]],
    limit: int,
) -> RansomNoteArtifactSearch:
    """Find note-like filenames that were successfully created or written.

    This is deliberately a candidate certificate. A filename can be reused by
    benign documentation, so it blocks a no-risk result but does not alone
    establish extortion or file impact.
    """

    artifacts_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    matched_event_count = 0
    for offset, event in events:
        path = transition_target_path(event)
        note_basename = note_like_basename(path)
        if not note_basename:
            continue
        operation_kind = successful_note_artifact_operation(event)
        if not operation_kind:
            continue
        process_key = transition_process_key(event)
        if not process_key:
            continue
        matched_event_count += 1
        artifact = artifacts_by_key.setdefault(
            (process_key, path),
            {
                "process_instance": transition_process_instance(event, process_key),
                "note_path": path,
                "note_basename": note_basename,
                "create_offsets": [],
                "write_offsets": [],
            },
        )
        artifact[f"{operation_kind}_offsets"].append(int(offset))

    matched = []
    for artifact in artifacts_by_key.values():
        create_offsets = sorted(set(int(offset) for offset in artifact["create_offsets"]))
        write_offsets = sorted(set(int(offset) for offset in artifact["write_offsets"]))
        representative_offsets = (write_offsets[:1] or create_offsets[:1]) + create_offsets[:1]
        representative_offsets = list(dict.fromkeys(representative_offsets))
        if not representative_offsets:
            continue
        operation_kinds = []
        if create_offsets:
            operation_kinds.append("create")
        if write_offsets:
            operation_kinds.append("write")
        matched.append(
            {
                "summary": (
                    f"process={artifact['process_instance'].get('key')}; "
                    f"note_basename={artifact['note_basename']}; "
                    f"operations={','.join(operation_kinds)}"
                ),
                "process_instance": dict(artifact["process_instance"]),
                "note_path": str(artifact["note_path"]),
                "note_basename": str(artifact["note_basename"]),
                "operation_kinds": operation_kinds,
                "create_count": len(create_offsets),
                "write_count": len(write_offsets),
                "representative_offsets": representative_offsets,
            }
        )
    matched.sort(
        key=lambda artifact: (
            -int(artifact["write_count"]),
            -int(artifact["create_count"]),
            int(artifact["representative_offsets"][0]),
            str(artifact["note_path"]),
        )
    )
    selected = tuple(matched[: max(0, int(limit))])
    return RansomNoteArtifactSearch(
        artifacts=selected,
        representative_offsets=tuple(
            offset for artifact in selected for offset in artifact["representative_offsets"]
        ),
        matched_artifact_count=len(matched),
        matched_event_count=matched_event_count,
        limitations=(
            "matches note-like basenames with a successful create or content-write event",
            "generic README-style filenames without recovery or extortion semantics are excluded",
            "does not inspect note content or establish file encryption by itself",
        ),
    )


def note_like_basename(path: str) -> str:
    normalized = str(path or "").replace("/", "\\").casefold()
    basename = normalized.rsplit("\\", 1)[-1]
    stem, separator, extension = basename.rpartition(".")
    if not separator or extension not in NOTE_FILE_EXTENSIONS:
        return ""
    tokens = set(re.findall(r"[a-z0-9]+", stem))
    if not any(term in tokens for term in NOTE_SEMANTIC_TERMS):
        return ""
    if not any(term in tokens for term in NOTE_CONTEXT_TERMS):
        return ""
    return basename


def successful_note_artifact_operation(event: dict[str, Any]) -> str:
    action = event.get("action") or {}
    if not is_success_result(action.get("result")):
        return ""
    operation = str(action.get("operation") or "").casefold()
    if operation == "writefile":
        return "write"
    if operation != "createfile":
        return ""
    detail = str((event.get("detail") or {}).get("raw_detail") or "").casefold()
    return "create" if "openresult: created" in detail or "disposition: create" in detail else ""

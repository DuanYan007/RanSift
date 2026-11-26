"""Separate session metadata from model-visible behavioral evidence."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

PROVENANCE_KEYS = frozenset({
    "snapshot", "sample_key", "sample_class", "source_class", "ground_truth_class",
    "ground_truth", "ground_truth_label", "expected_label", "class_label", "label",
    "family", "malware_family", "ransomware_family", "group", "dataset_class",
    "source_raw_csv", "source_normalized_path", "trace_id", "is_malicious",
})
CLASS_IDENTIFIER = re.compile(r"(?:^|[/\\:])(?:benign|ransomware)(?:[/\\:_-]|$)", re.I)
INPUT_CONTRACT = "model-input-v027"
METADATA_FIELDS = frozenset({
    "schema_version", "event_count", "process_count", "node_count", "block_count",
    "slice_count", "catalog_mode", "catalog_backed", "index_mode", "operation_counts",
    "operation_family_counts", "category_counts", "namespace_counts", "time_start",
    "time_end", "duration_s", "time_inversions", "byte_size", "sha256",
    "trace_sha256", "index_sha256", "blocks_sha256",
})


def model_sample_id(value: str) -> str:
    if CLASS_IDENTIFIER.search(value):
        return "sample-" + hashlib.sha256(value.encode()).hexdigest()[:16]
    return value


def project_session_context(value: Any) -> Any:
    """Scrub only the session/provenance packet, never tool events or claims."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in PROVENANCE_KEYS:
                continue
            if key == "metadata" and isinstance(item, dict):
                item = {k: v for k, v in item.items() if k in METADATA_FIELDS}
            result[key] = project_session_context(item)
        return result
    if isinstance(value, (list, tuple)):
        return [project_session_context(item) for item in value]
    if isinstance(value, str):
        if value.startswith("/"):
            value = PurePosixPath(value).name
        return model_sample_id(value)
    return value


def assert_blind_model_messages(messages) -> None:
    """Reject unsanitized provenance even when a custom caller bypasses composition.

    Inspect session metadata only. A real observed Windows filename containing
    'ransomware', or a behavioral claim's text, must remain evidence.
    """
    def check(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in PROVENANCE_KEYS:
                    raise ValueError("Experiment provenance field remains in model session context: " + key)
                if key == "metadata" and isinstance(item, dict) and set(item) - METADATA_FIELDS:
                    raise ValueError("Unprojected artifact metadata remains in model session context")
                check(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                check(item)
        elif isinstance(value, str) and (CLASS_IDENTIFIER.search(value) or value.startswith("/")):
            raise ValueError("Experiment class identifier or host path remains in model session context")

    for message in messages:
        if message.get("role") != "user":
            continue
        try:
            payload = json.loads(message.get("content", ""))
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        if isinstance(payload.get("sample_id"), str) and CLASS_IDENTIFIER.search(payload["sample_id"]):
            raise ValueError("Class-bearing sample identifier remains in model request")
        pre = payload.get("pre_review", {})
        if isinstance(pre, dict) and isinstance(pre.get("sample_id"), str) and CLASS_IDENTIFIER.search(pre["sample_id"]):
            raise ValueError("Class-bearing sample identifier remains in model pre-review")
        working = payload.get("working_context", {})
        if isinstance(working, dict):
            check(working.get("session_context", {}))
        if "session_context" in payload:
            check(payload["session_context"])


def assert_current_investigations(state) -> None:
    """Require investigations to use the current model-input contract."""
    from pathlib import Path
    for task_id, result in state.task_results.items():
        if not task_id.startswith("evidence_") or result.status != "completed":
            continue
        ref = result.artifacts.get("llm_context_final")
        if ref is None:
            raise ValueError("Investigation lacks its model-input provenance: " + task_id)
        saved = json.loads(Path(ref.path).read_text())
        if saved.get("working_context", {}).get("input_contract_version") != INPUT_CONTRACT:
            raise ValueError("Investigation predates the current input contract; rerun it: " + task_id)
        assert_blind_model_messages(({"role": "user", "content": json.dumps(saved)},))

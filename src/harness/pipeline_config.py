"""Input configuration for one harness pipeline run."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PipelineInputConfig:
    sample_id: str
    raw_log_path: str = ""
    static_sample_path: str = ""
    stage_bundle_path: str = ""
    behavior_snapshot_path: str = ""
    behavior_sample_key: str = ""
    sample_hint: str = ""
    family: str = ""
    trace_id: str = ""
    slice_size: int = 250
    root_pid: int | None = None
    grace_seconds: float = 0.5
    write_events: bool = True
    evidence_agent_ids: tuple[str, ...] | None = None
    run_verdict: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    source_path: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: str = "") -> "PipelineInputConfig":
        schema = str(data.get("schema_version") or "harness-pipeline-input-v1")
        if schema != "harness-pipeline-input-v1":
            raise ValueError(f"unsupported pipeline input schema: {schema!r}")
        sample_id = required_string(data, "sample_id")
        behavior_snapshot_path = str(data.get("behavior_snapshot_path") or "").strip()
        raw_log_path = str(data.get("raw_log_path") or "").strip()
        if not raw_log_path and not behavior_snapshot_path:
            raise ValueError(
                "pipeline input config requires raw_log_path unless behavior_snapshot_path is set"
            )
        sample_hint = str(data.get("sample_hint") or sample_id)
        static_sample_path = str(data.get("static_sample_path") or "")
        stage_bundle_path = str(data.get("stage_bundle_path") or "").strip()
        behavior_sample_key = str(data.get("behavior_sample_key") or "").strip()
        family = str(data.get("family") or "")
        trace_id = str(data.get("trace_id") or sample_id)
        return cls(
            sample_id=sample_id,
            raw_log_path=raw_log_path,
            static_sample_path=static_sample_path,
            stage_bundle_path=stage_bundle_path,
            behavior_snapshot_path=behavior_snapshot_path,
            behavior_sample_key=behavior_sample_key,
            sample_hint=sample_hint,
            family=family,
            trace_id=trace_id,
            slice_size=int(data.get("slice_size") or 250),
            root_pid=optional_int(data.get("root_pid")),
            grace_seconds=float(data.get("grace_seconds") if data.get("grace_seconds") is not None else 0.5),
            write_events=bool(data.get("write_events", True)),
            evidence_agent_ids=optional_string_tuple(data.get("evidence_agent_ids")),
            run_verdict=bool(data.get("run_verdict", True)),
            metadata=dict(data.get("metadata") or {}),
            source_path=source_path,
        )

    def to_pipeline_kwargs(self) -> dict[str, Any]:
        metadata = dict(self.metadata)
        if self.family:
            metadata.setdefault("family", self.family)
        if self.source_path:
            metadata.setdefault("pipeline_input_config", self.source_path)
        return {
            "raw_log_path": self.raw_log_path,
            "static_sample_path": self.static_sample_path,
            "stage_bundle_path": self.stage_bundle_path,
            "behavior_snapshot_path": self.behavior_snapshot_path,
            "behavior_sample_key": self.behavior_sample_key,
            "sample_id": self.sample_id,
            "sample_hint": self.sample_hint,
            "trace_id": self.trace_id,
            "slice_size": self.slice_size,
            "root_pid": self.root_pid,
            "grace_seconds": self.grace_seconds,
            "write_events": self.write_events,
            "evidence_agent_ids": self.evidence_agent_ids,
            "run_verdict": self.run_verdict,
            "input_metadata": metadata,
        }


def load_pipeline_input_config(path: str | Path) -> PipelineInputConfig:
    config_path = Path(path)
    data = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("pipeline input config must be a JSON object")
    return PipelineInputConfig.from_dict(data, source_path=str(config_path))


def pipeline_input_from_args(
    raw_log_path: str,
    sample_id: str,
    sample_hint: str = "",
    static_sample_path: str = "",
    stage_bundle_path: str = "",
    behavior_snapshot_path: str = "",
    behavior_sample_key: str = "",
    family: str = "",
    trace_id: str = "",
    slice_size: int = 250,
    root_pid: int | None = None,
    grace_seconds: float = 0.5,
    write_events: bool = True,
    evidence_agent_ids: tuple[str, ...] | None = None,
    run_verdict: bool = True,
    metadata: dict[str, Any] | None = None,
) -> PipelineInputConfig:
    return PipelineInputConfig(
        sample_id=sample_id,
        raw_log_path=raw_log_path,
        static_sample_path=static_sample_path,
        stage_bundle_path=stage_bundle_path,
        behavior_snapshot_path=behavior_snapshot_path,
        behavior_sample_key=behavior_sample_key,
        sample_hint=sample_hint or sample_id,
        family=family,
        trace_id=trace_id or sample_id,
        slice_size=slice_size,
        root_pid=root_pid,
        grace_seconds=grace_seconds,
        write_events=write_events,
        evidence_agent_ids=evidence_agent_ids,
        run_verdict=run_verdict,
        metadata=metadata or {},
    )


def required_string(data: dict[str, Any], key: str) -> str:
    value = str(data.get(key) or "").strip()
    if not value:
        raise ValueError(f"pipeline input config requires {key}")
    return value


def optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def optional_string_tuple(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        items = [item.strip() for item in value.split(",")]
    elif isinstance(value, list):
        items = [str(item).strip() for item in value]
    else:
        raise ValueError("evidence_agent_ids must be null, string, or list")
    return tuple(item for item in items if item)

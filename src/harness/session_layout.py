"""Config-driven output layout for harness analysis sessions."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REQUIRED_DIRECTORIES = ("inputs", "first_layer", "behavior", "static", "agents", "audit", "verdict")
REQUIRED_AGENT_DIRECTORIES = (
    "file_discovery",
    "file_transformation",
    "ransom_note",
    "registry",
    "process",
    "recovery",
    "anti_analysis",
)
REQUIRED_FILES = ("session_state", "summary")

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "output_layout.json"
DEFAULT_HARNESS_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class OutputLayoutConfig:
    schema_version: str
    output_root: str
    session_dir_template: str
    directories: dict[str, str]
    agent_directories: dict[str, str]
    files: dict[str, str]
    task_stage_map: dict[str, str] = field(default_factory=dict)
    description: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OutputLayoutConfig":
        config = cls(
            schema_version=str(data.get("schema_version") or ""),
            output_root=str(data.get("output_root") or ""),
            session_dir_template=str(data.get("session_dir_template") or "{sample_id}"),
            directories=string_map(data.get("directories")),
            agent_directories=string_map(data.get("agent_directories")),
            files=string_map(data.get("files")),
            task_stage_map=string_map(data.get("task_stage_map")),
            description=string_map(data.get("description")),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if self.schema_version != "harness-output-layout-v1":
            raise ValueError(f"unsupported output-layout schema: {self.schema_version!r}")
        validate_relative_path(self.output_root, field_name="output_root")
        if "{sample_id}" not in self.session_dir_template:
            raise ValueError("session_dir_template must contain {sample_id}")
        missing_dirs = [name for name in REQUIRED_DIRECTORIES if name not in self.directories]
        if missing_dirs:
            raise ValueError(f"missing required output directories: {missing_dirs}")
        missing_agents = [name for name in REQUIRED_AGENT_DIRECTORIES if name not in self.agent_directories]
        if missing_agents:
            raise ValueError(f"missing required agent directories: {missing_agents}")
        missing_files = [name for name in REQUIRED_FILES if name not in self.files]
        if missing_files:
            raise ValueError(f"missing required output files: {missing_files}")
        for name, value in self.directories.items():
            validate_relative_path(value, field_name=f"directories.{name}")
        for name, value in self.agent_directories.items():
            validate_relative_path(value, field_name=f"agent_directories.{name}")
        for name, value in self.files.items():
            validate_relative_path(value, field_name=f"files.{name}")
        for name, value in self.task_stage_map.items():
            validate_relative_path(value, field_name=f"task_stage_map.{name}")


@dataclass(frozen=True)
class SessionOutputLayout:
    sample_id: str
    harness_root: Path
    config: OutputLayoutConfig
    session_name: str

    @property
    def output_root(self) -> Path:
        return self.harness_root / self.config.output_root

    @property
    def session_dir(self) -> Path:
        return self.output_root / self.session_name

    @property
    def top_level_directories(self) -> dict[str, Path]:
        return {name: self.session_dir / rel_path for name, rel_path in self.config.directories.items()}

    @property
    def agent_directories(self) -> dict[str, Path]:
        agents_root = self.directory("agents")
        return {name: agents_root / rel_path for name, rel_path in self.config.agent_directories.items()}

    @property
    def files(self) -> dict[str, Path]:
        return {name: self.session_dir / rel_path for name, rel_path in self.config.files.items()}

    def directory(self, name: str) -> Path:
        if name in self.config.directories:
            return self.session_dir / self.config.directories[name]
        if name in self.config.agent_directories:
            return self.directory("agents") / self.config.agent_directories[name]
        raise KeyError(f"unknown layout directory: {name}")

    def file(self, name: str) -> Path:
        try:
            return self.session_dir / self.config.files[name]
        except KeyError as exc:
            raise KeyError(f"unknown layout file: {name}") from exc

    def task_dir(self, task_id: str) -> Path:
        relative = self.config.task_stage_map.get(task_id, task_id)
        validate_relative_path(relative, field_name=f"task_dir.{task_id}")
        return self.session_dir / relative

    def create(self) -> "SessionOutputLayout":
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        for path in self.top_level_directories.values():
            path.mkdir(parents=True, exist_ok=True)
        for path in self.agent_directories.values():
            path.mkdir(parents=True, exist_ok=True)
        for path in self.files.values():
            path.parent.mkdir(parents=True, exist_ok=True)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.config.schema_version,
            "sample_id": self.sample_id,
            "session_name": self.session_name,
            "output_root": str(self.output_root),
            "session_dir": str(self.session_dir),
            "directories": {name: str(path) for name, path in sorted(self.top_level_directories.items())},
            "agent_directories": {name: str(path) for name, path in sorted(self.agent_directories.items())},
            "files": {name: str(path) for name, path in sorted(self.files.items())},
        }


def load_output_layout_config(config_path: str | Path | None = None) -> OutputLayoutConfig:
    path = Path(config_path) if config_path is not None else DEFAULT_CONFIG_PATH
    with path.open("r", encoding="utf-8") as src:
        data = json.load(src)
    if not isinstance(data, dict):
        raise ValueError("output layout config must be a JSON object")
    return OutputLayoutConfig.from_dict(data)


def build_output_layout(
    sample_id: str,
    harness_root: str | Path | None = None,
    config: OutputLayoutConfig | None = None,
    config_path: str | Path | None = None,
) -> SessionOutputLayout:
    loaded = config or load_output_layout_config(config_path)
    root = Path(harness_root) if harness_root is not None else DEFAULT_HARNESS_ROOT
    session_name = loaded.session_dir_template.format(sample_id=safe_session_name(sample_id))
    validate_relative_path(session_name, field_name="session_dir")
    return SessionOutputLayout(
        sample_id=sample_id,
        harness_root=root,
        config=loaded,
        session_name=session_name,
    )


def create_output_layout(
    sample_id: str,
    harness_root: str | Path | None = None,
    config: OutputLayoutConfig | None = None,
    config_path: str | Path | None = None,
) -> SessionOutputLayout:
    return build_output_layout(
        sample_id=sample_id,
        harness_root=harness_root,
        config=config,
        config_path=config_path,
    ).create()


def safe_session_name(sample_id: str) -> str:
    text = str(sample_id).strip()
    if not text:
        raise ValueError("sample_id must not be empty")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._")
    if not safe or safe in {".", ".."}:
        raise ValueError(f"sample_id does not produce a safe session name: {sample_id!r}")
    return safe


def string_map(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return {str(key): str(item) for key, item in value.items()}


def validate_relative_path(value: str, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    path = Path(value)
    if path.is_absolute():
        raise ValueError(f"{field_name} must be relative: {value!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{field_name} must not contain empty, current, or parent path segments: {value!r}")

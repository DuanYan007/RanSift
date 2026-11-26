"""Task graph primitives for harness analysis sessions."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Mapping

TaskStatus = Literal["pending", "running", "completed", "failed", "skipped"]


@dataclass(frozen=True)
class ArtifactRef:
    artifact_id: str
    kind: str
    path: str
    producer_task_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "path": self.path,
            "producer_task_id": self.producer_task_id,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class SessionFact:
    fact_id: str
    kind: str
    data: dict[str, Any]
    source_task_id: str
    artifact_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "kind": self.kind,
            "data": self.data,
            "source_task_id": self.source_task_id,
            "artifact_ids": list(self.artifact_ids),
        }


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    task_type: str
    profile: str = "deterministic"
    dependencies: tuple[str, ...] = ()
    input_artifacts: dict[str, str] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    output_names: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    context_policy: dict[str, Any] = field(default_factory=dict)
    budget: dict[str, Any] = field(default_factory=dict)
    acceptance_criteria: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "profile": self.profile,
            "dependencies": list(self.dependencies),
            "input_artifacts": dict(self.input_artifacts),
            "parameters": self.parameters,
            "output_names": list(self.output_names),
            "allowed_tools": list(self.allowed_tools),
            "context_policy": self.context_policy,
            "budget": self.budget,
            "acceptance_criteria": list(self.acceptance_criteria),
        }


@dataclass(frozen=True)
class TaskResult:
    task_id: str
    status: TaskStatus
    artifacts: dict[str, ArtifactRef] = field(default_factory=dict)
    facts: tuple[SessionFact, ...] = ()
    diagnostics: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @classmethod
    def completed(
        cls,
        task_id: str,
        artifacts: dict[str, ArtifactRef] | None = None,
        facts: tuple[SessionFact, ...] = (),
        diagnostics: dict[str, Any] | None = None,
    ) -> "TaskResult":
        return cls(
            task_id=task_id,
            status="completed",
            artifacts=artifacts or {},
            facts=facts,
            diagnostics=diagnostics or {},
        )

    @classmethod
    def failed(cls, task_id: str, error: str, diagnostics: dict[str, Any] | None = None) -> "TaskResult":
        return cls(task_id=task_id, status="failed", error=error, diagnostics=diagnostics or {})

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "artifacts": {name: ref.to_dict() for name, ref in self.artifacts.items()},
            "facts": [fact.to_dict() for fact in self.facts],
            "diagnostics": self.diagnostics,
            "error": self.error,
        }


class ArtifactStore:
    """Filesystem-backed artifact registry for a single session run."""

    def __init__(
        self,
        root: str | Path,
        task_directories: Mapping[str, str | Path] | None = None,
    ) -> None:
        self.root = Path(root)
        self.task_directories = {str(task_id): Path(path) for task_id, path in (task_directories or {}).items()}
        self.root.mkdir(parents=True, exist_ok=True)

    def task_dir(self, task_id: str) -> Path:
        relative = self.task_directories.get(task_id, Path(task_id))
        validate_relative_task_dir(relative, task_id)
        path = self.root / relative
        path.mkdir(parents=True, exist_ok=True)
        return path

    def path_for(self, task_id: str, filename: str) -> Path:
        return self.task_dir(task_id) / filename

    def artifact_ref(
        self,
        task_id: str,
        name: str,
        kind: str,
        path: str | Path,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        return ArtifactRef(
            artifact_id=f"{task_id}:{name}",
            kind=kind,
            path=str(Path(path)),
            producer_task_id=task_id,
            metadata=metadata or {},
        )


@dataclass
class AnalysisSessionState:
    sample_id: str
    work_dir: str | Path
    task_directories: dict[str, str] = field(default_factory=dict)
    artifacts: dict[str, ArtifactRef] = field(default_factory=dict)
    facts: list[SessionFact] = field(default_factory=list)
    task_results: dict[str, TaskResult] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.work_dir = Path(self.work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)

    @property
    def store(self) -> ArtifactStore:
        return ArtifactStore(self.work_dir, task_directories=self.task_directories)

    def register_input_artifact(
        self,
        artifact_id: str,
        kind: str,
        path: str | Path,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        ref = ArtifactRef(
            artifact_id=artifact_id,
            kind=kind,
            path=str(Path(path)),
            producer_task_id="input",
            metadata=metadata or {},
        )
        self.artifacts[ref.artifact_id] = ref
        return ref

    def artifact(self, artifact_id: str) -> ArtifactRef:
        try:
            return self.artifacts[artifact_id]
        except KeyError as exc:
            raise KeyError(f"unknown artifact: {artifact_id}") from exc

    def commit(self, result: TaskResult) -> None:
        self.task_results[result.task_id] = result
        if result.status != "completed":
            return
        for ref in result.artifacts.values():
            self.artifacts[ref.artifact_id] = ref
        self.facts.extend(result.facts)

    def facts_by_kind(self, kind: str) -> list[SessionFact]:
        return [fact for fact in self.facts if fact.kind == kind]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "work_dir": str(self.work_dir),
            "task_directories": dict(sorted(self.task_directories.items())),
            "artifacts": {artifact_id: ref.to_dict() for artifact_id, ref in sorted(self.artifacts.items())},
            "facts": [fact.to_dict() for fact in self.facts],
            "task_results": {task_id: result.to_dict() for task_id, result in sorted(self.task_results.items())},
        }


@dataclass(frozen=True)
class TaskContext:
    spec: TaskSpec
    state: AnalysisSessionState
    store: ArtifactStore

    def input_ref(self, name: str) -> ArtifactRef:
        try:
            artifact_id = self.spec.input_artifacts[name]
        except KeyError as exc:
            raise KeyError(f"task {self.spec.task_id} has no input artifact named {name!r}") from exc
        return self.state.artifact(artifact_id)

    def input_path(self, name: str) -> Path:
        return Path(self.input_ref(name).path)


TaskHandler = Callable[[TaskContext], TaskResult]


def validate_relative_task_dir(path: Path, task_id: str) -> None:
    if path.is_absolute():
        raise ValueError(f"task {task_id!r} directory must be relative: {path}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"task {task_id!r} directory contains an invalid path segment: {path}")

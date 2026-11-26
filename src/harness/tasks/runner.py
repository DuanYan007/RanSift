"""Deterministic task graph runner."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from .models import AnalysisSessionState, TaskContext, TaskHandler, TaskResult, TaskSpec

if TYPE_CHECKING:
    from harness.monitor import HarnessMonitor


class TaskRunner:
    def __init__(
        self,
        handlers: dict[str, TaskHandler],
        state: AnalysisSessionState,
        monitor: HarnessMonitor | None = None,
        resume: bool = False,
    ) -> None:
        self.handlers = dict(handlers)
        self.state = state
        self.store = state.store
        self.monitor = monitor
        self.resume = resume

    def run(self, spec: TaskSpec) -> TaskResult:
        if self.resume and self._can_reuse_completed_result(spec):
            result = self.state.task_results[spec.task_id]
            if self.monitor is not None:
                self.monitor.task_skipped(spec, "completed task result already present in session state")
            return result
        missing = [task_id for task_id in spec.dependencies if self.state.task_results.get(task_id, None) is None]
        if missing:
            raise ValueError(f"task {spec.task_id} has unresolved dependencies: {missing}")
        failed = [task_id for task_id in spec.dependencies if self.state.task_results[task_id].status != "completed"]
        if failed:
            result = TaskResult.failed(spec.task_id, f"dependency failed: {failed}")
            self.state.commit(result)
            if self.monitor is not None:
                self.monitor.task_skipped(spec, result.error)
            return result
        if spec.task_type not in self.handlers:
            raise KeyError(f"no handler registered for task type: {spec.task_type}")
        if self.monitor is not None:
            self.monitor.task_started(spec)
        try:
            result = self.handlers[spec.task_type](TaskContext(spec=spec, state=self.state, store=self.store))
        except Exception as exc:  # noqa: BLE001 - task failures must be checkpointed by the harness.
            result = TaskResult.failed(
                spec.task_id,
                str(exc),
                diagnostics={"exception_type": exc.__class__.__name__},
            )
            self.state.commit(result)
            if self.monitor is not None:
                self.monitor.task_finished(spec, result, self.state)
            return result
        self.state.commit(result)
        if self.monitor is not None:
            self.monitor.task_finished(spec, result, self.state)
        return result

    def run_all(self, specs: Iterable[TaskSpec]) -> list[TaskResult]:
        return [self.run(spec) for spec in specs]

    def _can_reuse_completed_result(self, spec: TaskSpec) -> bool:
        result = self.state.task_results.get(spec.task_id)
        if result is None or result.status != "completed":
            return False
        return all(ref.path and Path(ref.path).exists() for ref in result.artifacts.values())


class FactBroker:
    """Read-only session facts and artifacts for context composition."""

    def __init__(self, state: AnalysisSessionState) -> None:
        self.state = state

    def list_facts(self, kind: str | None = None, source_task_id: str | None = None) -> list[dict]:
        facts = self.state.facts
        if kind is not None:
            facts = [fact for fact in facts if fact.kind == kind]
        if source_task_id is not None:
            facts = [fact for fact in facts if fact.source_task_id == source_task_id]
        return [fact.to_dict() for fact in facts]

    def list_artifacts(self, kind: str | None = None) -> list[dict]:
        refs = self.state.artifacts.values()
        if kind is not None:
            refs = [ref for ref in refs if ref.kind == kind]
        return [ref.to_dict() for ref in refs]

    def artifact(self, artifact_id: str) -> dict:
        return self.state.artifact(artifact_id).to_dict()

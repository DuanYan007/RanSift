"""Bounded task-context composition for LLM-backed analysis tasks."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import AnalysisSessionState, ArtifactRef, SessionFact, TaskSpec
from harness.model_context import project_session_context

DEFAULT_MAX_ARTIFACTS = 24
DEFAULT_MAX_FACTS = 16
DEFAULT_MAX_ITEMS = 12
DEFAULT_MAX_DEPTH = 4


@dataclass(frozen=True)
class ContextComposer:
    """Builds a compact, read-only session packet for one task invocation."""

    state: AnalysisSessionState

    def compose(self, spec: TaskSpec) -> dict[str, Any]:
        policy = dict(spec.context_policy)
        return project_session_context({
            "sample_id": self.state.sample_id,
            "task": {
                "task_id": spec.task_id,
                "task_type": spec.task_type,
                "profile": spec.profile,
                "acceptance_criteria": list(spec.acceptance_criteria),
            },
            "budget": compact_value(spec.budget),
            "inputs": {
                name: artifact_to_context(self.state.artifact(artifact_id))
                for name, artifact_id in sorted(spec.input_artifacts.items())
            },
            "available_artifacts": self._select_artifacts(policy),
            "relevant_facts": self._select_facts(policy),
            "context_policy": compact_value(policy),
        })

    def _select_artifacts(self, policy: dict[str, Any]) -> list[dict[str, Any]]:
        refs = list(self.state.artifacts.values())
        kinds = string_tuple(policy.get("artifact_kinds") or policy.get("include_artifact_kinds"))
        if kinds:
            refs = [ref for ref in refs if ref.kind in kinds]
        max_artifacts = int(policy.get("max_artifacts") or DEFAULT_MAX_ARTIFACTS)
        refs = sorted(refs, key=lambda ref: ref.artifact_id)[-max_artifacts:]
        return [artifact_to_context(ref) for ref in refs]

    def _select_facts(self, policy: dict[str, Any]) -> list[dict[str, Any]]:
        facts = list(self.state.facts)
        kinds = string_tuple(policy.get("fact_kinds") or policy.get("include_fact_kinds"))
        if kinds:
            facts = [fact for fact in facts if fact.kind in kinds]
        source_task_ids = string_tuple(policy.get("source_task_ids") or policy.get("include_source_task_ids"))
        if source_task_ids:
            facts = [fact for fact in facts if fact.source_task_id in source_task_ids]
        max_facts = int(policy.get("max_facts") or DEFAULT_MAX_FACTS)
        facts = facts[-max_facts:]
        return [fact_to_context(fact) for fact in facts]


def artifact_to_context(ref: ArtifactRef) -> dict[str, Any]:
    return {
        "artifact_id": ref.artifact_id,
        "kind": ref.kind,
        "producer_task_id": ref.producer_task_id,
        "path_name": Path(ref.path).name,
        "metadata": compact_value(project_session_context({"metadata": ref.metadata})["metadata"]),
    }


def fact_to_context(fact: SessionFact) -> dict[str, Any]:
    return {
        "fact_id": fact.fact_id,
        "kind": fact.kind,
        "source_task_id": fact.source_task_id,
        "artifact_ids": list(fact.artifact_ids),
        "data": compact_value(project_session_context(fact.data)),
    }


def compact_value(value: Any, depth: int = 0) -> Any:
    if depth >= DEFAULT_MAX_DEPTH:
        return "..."
    if isinstance(value, dict):
        items = list(value.items())
        compact = {
            str(key): compact_value(item, depth + 1)
            for key, item in items[:DEFAULT_MAX_ITEMS]
        }
        if len(items) > DEFAULT_MAX_ITEMS:
            compact["_omitted"] = len(items) - DEFAULT_MAX_ITEMS
        return compact
    if isinstance(value, (list, tuple)):
        values = list(value)
        compact_items = [compact_value(item, depth + 1) for item in values[:DEFAULT_MAX_ITEMS]]
        if len(values) > DEFAULT_MAX_ITEMS:
            compact_items.append({"_omitted": len(values) - DEFAULT_MAX_ITEMS})
        return compact_items
    if isinstance(value, set):
        values = sorted(str(item) for item in value)
        compact_items = values[:DEFAULT_MAX_ITEMS]
        if len(values) > DEFAULT_MAX_ITEMS:
            compact_items.append(f"_omitted:{len(values) - DEFAULT_MAX_ITEMS}")
        return compact_items
    return value


def string_tuple(value: Any) -> tuple[str, ...]:
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value if item is not None and str(item) != "")

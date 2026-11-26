"""Task handler for LLM evidence-profile analysis."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness.behavior import (
    EvidenceStore,
    EvidenceTools,
    LLMEvidenceAgentRunner,
    LLMEvidenceLoopConfig,
    LLMEvidenceLoopResult,
    ToolCallPlan,
    ToolRegistry,
)
from harness.behavior.llm_loop import JSONChatClient
from harness.behavior.catalog_store import CatalogEvidenceStore
from harness.behavior.catalog_streaming_tools import StreamingCatalogEvidenceTools
from harness.behavior.agent_prompts import AgentPrompt
from harness.behavior.coverage import build_role_coverage_certificate
from harness.behavior.execution_adequacy import assess_root_execution_adequacy
from harness.behavior.file_discovery_scope import apply_file_discovery_scope_certificates
from harness.query_timing import ToolQueryTiming

from .context_composer import ContextComposer
from .models import SessionFact, TaskContext, TaskHandler, TaskResult, TaskSpec

TASK_RUN_EVIDENCE_PROFILE = "run_evidence_profile"
DEFAULT_EVIDENCE_OUTPUTS = (
    "candidate_claims",
    "scope_certificates",
    "coverage_certificate",
    "tool_history",
    "local_memory",
    "llm_context_final",
    "model_responses",
    "evidence_loop_result",
)
COMPLETED_EVIDENCE_LOOP_STATUSES = frozenset({"completed", "completed_no_evidence"})


class TaskScopedToolRegistry:
    """Narrows an agent registry with a task-level tool allow-list."""

    def __init__(self, base: ToolRegistry, allowed_tools: tuple[str, ...] = (),
                 timing: ToolQueryTiming | None = None) -> None:
        self.base = base
        self.allowed_tools = tuple(allowed_tools)
        self.timing = timing

    @property
    def tools(self):
        return self.base.tools

    def specs_for_agent(self, agent_id: str):
        specs = self.base.specs_for_agent(agent_id)
        if not self.allowed_tools:
            return specs
        allowed = set(self.allowed_tools)
        return [spec for spec in specs if spec.name in allowed]

    def tool_names_for_agent(self, agent_id: str) -> list[str]:
        return [spec.name for spec in self.specs_for_agent(agent_id)]

    def validate_arguments(self, name: str, arguments: dict[str, Any]) -> None:
        self.base.validate_arguments(name, arguments)

    def call_for_agent(self, agent_id: str, name: str, **kwargs: Any):
        if self.timing is not None:
            return self.timing.invoke(name, kwargs, lambda: self._call_for_agent(agent_id, name, **kwargs))
        return self._call_for_agent(agent_id, name, **kwargs)

    def _call_for_agent(self, agent_id: str, name: str, **kwargs: Any):
        if name not in set(self.tool_names_for_agent(agent_id)):
            raise PermissionError(f"tool {name!r} is not allowed by task {agent_id!r}")
        return self.base.call_for_agent(agent_id, name, **kwargs)


def evidence_task_handlers(
    client: JSONChatClient,
    loop_config: LLMEvidenceLoopConfig | None = None,
    agent_prompts: dict[str, AgentPrompt] | None = None,
    analysis_protocol: str = "legacy-v1",
) -> dict[str, TaskHandler]:
    return {
        TASK_RUN_EVIDENCE_PROFILE: lambda context: run_evidence_profile_task(
            context,
            client=client,
            loop_config=loop_config,
            agent_prompts=agent_prompts,
            analysis_protocol=analysis_protocol,
        )
    }


def build_evidence_profile_task_spec(
    agent_id: str,
    task_id: str | None = None,
    dependencies: tuple[str, ...] = ("normalize_behavior_trace", "build_behavior_index", "build_behavior_blocks"),
    behavior_trace_artifact_id: str = "normalize_behavior_trace:behavior_trace",
    behavior_index_artifact_id: str = "build_behavior_index:behavior_index",
    behavior_blocks_artifact_id: str = "build_behavior_blocks:behavior_blocks",
    allowed_tools: tuple[str, ...] = (),
    context_policy: dict[str, Any] | None = None,
    budget: dict[str, Any] | None = None,
    task_prompt: str | None = None,
    seed_tool_calls: tuple[dict[str, Any], ...] | None = None,
) -> TaskSpec:
    parameters: dict[str, Any] = {"agent_id": agent_id}
    seed_calls = default_seed_tool_calls(agent_id) if seed_tool_calls is None else seed_tool_calls
    seed_calls = filter_seed_tool_calls(seed_calls, allowed_tools)
    if seed_calls:
        parameters["seed_tool_calls"] = [dict(item) for item in seed_calls]
    if task_prompt:
        parameters["task_prompt"] = task_prompt
    return TaskSpec(
        task_id=task_id or f"evidence_{agent_id}",
        task_type=TASK_RUN_EVIDENCE_PROFILE,
        profile=agent_id,
        dependencies=dependencies,
        input_artifacts={
            "behavior_trace": behavior_trace_artifact_id,
            "behavior_index": behavior_index_artifact_id,
            "behavior_blocks": behavior_blocks_artifact_id,
        },
        parameters=parameters,
        output_names=DEFAULT_EVIDENCE_OUTPUTS,
        allowed_tools=allowed_tools,
        context_policy=context_policy or default_evidence_context_policy(),
        budget=budget or {"max_rounds": 6, "max_tool_calls": 10},
        acceptance_criteria=(
            "agent uses only task-allowed tools",
            "seed observations are recorded before model turns when configured",
            "claims cite evidence references returned during the loop",
            "raw trace payloads are not copied into shared session context",
        ),
    )


def default_seed_tool_calls(agent_id: str) -> tuple[dict[str, Any], ...]:
    plans: dict[str, tuple[dict[str, Any], ...]] = {
        "file_discovery": (
            seed_call("summarize_blocks", {"level": "macro", "limit": 8}, "summarize attributed behavior spans before judging discovery"),
            seed_call("list_blocks", {"behavior_kind": "file_discovery", "level": "macro", "min_event_count": 1, "limit": 8}, "retrieve attributed file-discovery spans if present"),
        ),
        "file_transformation": (
            seed_call("list_blocks", {"behavior_kind": "file_transformation", "level": "macro", "min_event_count": 1, "limit": 8}, "retrieve attributed file-transformation spans if present"),
            seed_call("list_events", {"index_name": "operation_family_index", "key": "file_rename", "limit": 20, "cursor": None}, "check concrete rename evidence before claiming transformation semantics"),
            seed_call("find_file_extension_renames", {"process_key": None, "scope": "direct_user_shared", "min_rename_count": 3, "min_scope_count": 2, "limit": 8}, "inspect repeated same-process extension-changing renames, including replacement of source basenames, across distinct direct user or shared-data target scopes"),
            seed_call("find_file_extension_renames", {"process_key": None, "scope": "all", "min_rename_count": 20, "min_scope_count": 1, "limit": 8}, "inspect broad same-process non-transient extension-append renames across distinct original files"),
            seed_call("list_events", {"index_name": "operation_family_index", "key": "file_delete", "limit": 20, "cursor": None}, "check concrete delete evidence before claiming transformation semantics"),
            seed_call("find_file_extension_transitions", {"process_key": None, "scope": "direct_user_shared", "min_pair_count": 3, "max_order_gap": 250, "limit": 8}, "inspect repeated same-process added-extension writes followed by original-file deletion in direct user or shared data"),
            seed_call("find_file_extension_transitions", {"process_key": None, "scope": "all", "min_pair_count": 20, "max_order_gap": 1000, "limit": 8}, "inspect repeated non-transient added-extension write/delete transformations across the attributed trace"),
            seed_call("find_raw_filesystem_metadata_writes", {"limit": 8}, "inspect successful writes to raw filesystem metadata objects"),
        ),
        "ransom_note": (
            seed_call("find_ransom_note_artifacts", {"limit": 8}, "inspect note-like basenames with successful create or write evidence"),
            seed_call("search_events", {"patterns": "decrypt", "fields": ["target", "detail", "process"], "limit": 20, "cursor": None}, "search for decrypt-related note or command evidence"),
            seed_call("search_events", {"patterns": "restore", "fields": ["target", "detail", "process"], "limit": 20, "cursor": None}, "search for restore-related note or command evidence"),
        ),
        "registry": (
            seed_call("find_run_key_executable_bindings", {"limit": 8}, "inspect successful Run or RunOnce values that bind executable payload paths"),
            seed_call("list_blocks", {"behavior_kind": "registry_modification", "level": "macro", "min_event_count": 1, "limit": 8}, "retrieve attributed registry-modification spans if present"),
            seed_call("list_events", {"index_name": "operation_family_index", "key": "registry_write", "limit": 20, "cursor": None}, "check concrete registry-write events"),
        ),
        "process": (
            seed_call("summarize_processes", {"limit": 12}, "summarize attributed processes before inspecting execution chains"),
            seed_call("list_events", {"index_name": "operation_index", "key": "process create", "limit": 40, "cursor": None}, "retrieve concrete parent-child process creation events"),
            seed_call("find_concealed_script_host_fingerprinting", {"limit": 8}, "inspect encoded script execution that combines explicit window concealment with host hardware fingerprinting"),
            seed_call("find_deployed_elevated_autostart_tasks", {"limit": 8}, "inspect executable deployment followed by an elevated scheduled task configured for logon or startup"),
            seed_call("find_command_invocations", {"terms": "cmd.exe", "limit": 20, "cursor": None}, "check command-interpreter execution with attribution"),
            seed_call("find_command_invocations", {"terms": "vssadmin", "limit": 20, "cursor": None}, "check recovery-tool execution from the process chain"),
            seed_call("find_command_invocations", {"terms": "icacls", "limit": 20, "cursor": None}, "check ACL or permission-tampering tool execution from the process chain"),
            seed_call("find_command_invocations", {"terms": "takeown", "limit": 20, "cursor": None}, "check ownership-tampering tool execution from the process chain"),
        ),
        "recovery": (
            seed_call("find_destructive_recovery_commands", {"limit": 8}, "find attributed destructive recovery commands with paired successful process creation and start evidence"),
            seed_call("find_command_invocations", {"terms": "vssadmin", "limit": 20, "cursor": None}, "check Volume Shadow Copy command evidence"),
            seed_call("find_command_invocations", {"terms": "wmic", "limit": 20, "cursor": None}, "check WMIC recovery-artifact command evidence"),
            seed_call("find_command_invocations", {"terms": "bcdedit", "limit": 20, "cursor": None}, "check boot-recovery command evidence"),
            seed_call("find_command_invocations", {"terms": "icacls", "limit": 20, "cursor": None}, "check permission or ACL-impact command evidence"),
            seed_call("find_command_invocations", {"terms": "takeown", "limit": 20, "cursor": None}, "check ownership-impact command evidence"),
        ),
        "anti_analysis": (
            seed_call("summarize_operations", {"limit": 12}, "summarize attributed operation surface before assessing probes"),
            seed_call("find_command_invocations", {"terms": None, "limit": 20, "cursor": None}, "retrieve command-line probe or reconnaissance events if present"),
        ),
    }
    return plans.get(agent_id, ())


def seed_call(tool_name: str, arguments: dict[str, Any], purpose: str) -> dict[str, Any]:
    return {"tool_name": tool_name, "arguments": arguments, "purpose": purpose}


def filter_seed_tool_calls(seed_calls: tuple[dict[str, Any], ...], allowed_tools: tuple[str, ...]) -> tuple[dict[str, Any], ...]:
    if not allowed_tools:
        return tuple(seed_calls)
    allowed = set(allowed_tools)
    return tuple(call for call in seed_calls if str(call.get("tool_name") or call.get("name") or "") in allowed)


def default_evidence_context_policy() -> dict[str, Any]:
    return {
        "fact_kinds": (
            "behavior_trace_summary",
            "behavior_index_summary",
            "behavior_block_summary",
            "process_tree_summary",
            "tree_filter_summary",
        ),
        "artifact_kinds": (
            "behavior_trace",
            "behavior_index",
            "behavior_blocks",
            "behavior_trace_meta",
            "behavior_index_meta",
            "behavior_blocks_meta",
        ),
        "max_facts": 12,
        "max_artifacts": 12,
    }


def run_evidence_profile_task(
    context: TaskContext,
    client: JSONChatClient,
    loop_config: LLMEvidenceLoopConfig | None = None,
    agent_prompts: dict[str, AgentPrompt] | None = None,
    analysis_protocol: str = "legacy-v1",
) -> TaskResult:
    agent_id = str(context.spec.parameters.get("agent_id") or context.spec.profile)
    store = evidence_store_for_context(context)
    base_registry = ToolRegistry(
        StreamingCatalogEvidenceTools(store) if isinstance(store, CatalogEvidenceStore) else EvidenceTools(store)
    )
    timing = ToolQueryTiming(context.store.task_dir(context.spec.task_id),
                             sample_id=context.state.sample_id, task_id=context.spec.task_id, agent_id=agent_id)
    registry = TaskScopedToolRegistry(base_registry, allowed_tools=tuple(context.spec.allowed_tools), timing=timing)
    config = config_from_budget(context.spec.budget, loop_config)
    session_context = ContextComposer(context.state).compose(context.spec)
    if analysis_protocol in {"evidence-reasoning-v2", "evidence-binary-v1"}:
        from harness.behavior.reasoning_v2 import CompatibleReasoningRunner
        runner_type = CompatibleReasoningRunner
        if config.max_submission_corrections:
            from harness.behavior.submission_correction import SubmissionCorrectionRunner
            runner_type = SubmissionCorrectionRunner
        if config.require_investigation_closure:
            from harness.behavior.investigation_closure import FollowupEvidenceRunner
            runner_type = FollowupEvidenceRunner
        runner = runner_type(registry, client, config=config, agent_prompts=agent_prompts)
    elif analysis_protocol == "evidence-reasoning-v1":
        from harness.behavior.reasoning import EvidenceReasoningRunner
        runner = EvidenceReasoningRunner(registry, client, config=config, agent_prompts=agent_prompts)
    elif analysis_protocol == "legacy-v1":
        runner = LLMEvidenceAgentRunner(registry, client, config=config, agent_prompts=agent_prompts)
    else:
        raise ValueError(f"unsupported analysis_protocol: {analysis_protocol!r}")
    runner_status = "raised"
    try:
        result = runner.run(
            agent_id=agent_id,
            task_prompt=optional_string(context.spec.parameters.get("task_prompt")),
            seed_tool_calls=seed_tool_calls_from_parameters(context.spec.parameters),
            session_context=session_context,
        )
        runner_status = "returned"
    finally:
        timing.finish(runner_status=runner_status)
    scope_certificates = (
        {"certificate_count": 0, "analysis_protocol": analysis_protocol, "certificates": []}
        if analysis_protocol in {"evidence-reasoning-v1", "evidence-reasoning-v2", "evidence-binary-v1"}
        else apply_file_discovery_scope_certificates(result.claim_ledger, store)
    )
    execution_observation = (
        assess_root_execution_adequacy(
            store.iter_events() if isinstance(store, CatalogEvidenceStore) else enumerate(store.events)
        )
        if agent_id == "process"
        else None
    )
    summary = evidence_summary(context.spec, agent_id, result, scope_certificates)
    coverage = build_role_coverage_certificate(
        task_id=context.spec.task_id,
        agent_id=agent_id,
        loop_status=result.status,
        claim_count=len(result.claim_ledger.claims),
        tool_call_count=len(result.evidence_ledger.tool_history),
        seed_tool_call_count=len(context.spec.parameters.get("seed_tool_calls") or ()),
        completion=result.diagnostics.get("completion") if isinstance(result.diagnostics, dict) else None,
        execution_observation=execution_observation,
        source_artifact_ids=(
            f"{context.spec.task_id}:evidence_loop_result",
            f"{context.spec.task_id}:tool_history",
            f"{context.spec.task_id}:local_memory",
        ),
    )
    artifacts = materialize_evidence_artifacts(context, result, coverage, scope_certificates)
    facts = [
        SessionFact(
            fact_id=f"{context.spec.task_id}:summary",
            kind="evidence_profile_summary",
            data=summary,
            source_task_id=context.spec.task_id,
            artifact_ids=tuple(ref.artifact_id for ref in artifacts.values()),
        )
    ]
    facts.append(
        SessionFact(
            fact_id=f"{context.spec.task_id}:coverage",
            kind="role_coverage",
            data=coverage,
            source_task_id=context.spec.task_id,
            artifact_ids=(artifacts["coverage_certificate"].artifact_id,),
        )
    )
    if result.status in COMPLETED_EVIDENCE_LOOP_STATUSES:
        for claim in result.claim_ledger.claims.values():
            facts.append(
                SessionFact(
                    fact_id=f"{context.spec.task_id}:claim:{claim.claim_id}",
                    kind="candidate_claim",
                    data=claim.to_dict(),
                    source_task_id=context.spec.task_id,
                    artifact_ids=(
                        artifacts["candidate_claims"].artifact_id,
                        artifacts["scope_certificates"].artifact_id,
                    ),
                )
            )
    return TaskResult.completed(
        context.spec.task_id,
        artifacts=artifacts,
        facts=tuple(facts),
        diagnostics=summary,
    )


def evidence_store_for_context(context: TaskContext):
    index_ref = context.input_ref("behavior_index")
    if bool(index_ref.metadata.get("catalog_mode")):
        checkpoints_path = str(index_ref.metadata.get("trace_checkpoints_path") or "").strip()
        if not checkpoints_path:
            raise ValueError("catalog-backed behavior index has no checkpoint artifact")
        return EvidenceStore.from_catalog(
            context.input_path("behavior_trace"),
            context.input_path("behavior_index"),
            context.input_path("behavior_blocks"),
            checkpoints_path,
        )
    return EvidenceStore(
        context.input_path("behavior_trace"),
        context.input_path("behavior_index"),
        context.input_path("behavior_blocks"),
    )


def materialize_evidence_artifacts(
    context: TaskContext,
    result: LLMEvidenceLoopResult,
    coverage: dict[str, Any],
    scope_certificates: dict[str, Any],
):
    task_id = context.spec.task_id
    payloads = {
        "candidate_claims": [claim.to_dict() for claim in result.claim_ledger.claims.values()],
        "scope_certificates": scope_certificates,
        "coverage_certificate": coverage,
        "tool_history": result.evidence_ledger.to_dict(),
        "local_memory": result.memory.to_context(),
        "llm_context_final": result.context.to_dict(),
        "model_responses": list(result.model_responses),
        "evidence_loop_result": result.to_dict(),
    }
    filenames = {
        "candidate_claims": "candidate_claims.json",
        "scope_certificates": "scope_certificates.json",
        "coverage_certificate": "coverage_certificate.json",
        "tool_history": "tool_history.json",
        "local_memory": "local_memory.json",
        "llm_context_final": "llm_context_final.json",
        "model_responses": "model_responses.json",
        "evidence_loop_result": "evidence_loop_result.json",
    }
    artifacts = {}
    for name, payload in payloads.items():
        path = context.store.path_for(task_id, filenames[name])
        write_json(path, payload)
        artifacts[name] = context.store.artifact_ref(
            task_id,
            name,
            name,
            path,
            artifact_metadata(name, payload, result),
        )
    return artifacts


def artifact_metadata(name: str, payload: Any, result: LLMEvidenceLoopResult) -> dict[str, Any]:
    if name == "candidate_claims":
        return {"claim_count": len(payload), "loop_status": result.status, "agent_id": result.agent_id}
    if name == "scope_certificates":
        return {
            "certificate_count": int(payload.get("certificate_count") or 0),
            "agent_id": result.agent_id,
        }
    if name == "coverage_certificate":
        return {
            "coverage_status": str(payload.get("coverage_status") or ""),
            "agent_id": result.agent_id,
        }
    if name == "tool_history":
        return {"tool_call_count": len(payload.get("tool_history", [])), "agent_id": result.agent_id}
    if name == "model_responses":
        return {"response_count": len(payload), "agent_id": result.agent_id}
    return {"agent_id": result.agent_id, "loop_status": result.status}


def evidence_summary(
    spec: TaskSpec,
    agent_id: str,
    result: LLMEvidenceLoopResult,
    scope_certificates: dict[str, Any],
) -> dict[str, Any]:
    completion = result.diagnostics.get("completion")
    return {
        "schema_version": "evidence-profile-task-v1",
        "agent_id": agent_id,
        "task_id": spec.task_id,
        "loop_status": result.status,
        "claim_count": len(result.claim_ledger.claims),
        "tool_call_count": len(result.evidence_ledger.tool_history),
        "seen_ref_count": len(result.evidence_ledger.seen_ref_ids),
        "completion": dict(completion) if isinstance(completion, dict) else None,
        "diagnostics": result.diagnostics,
        "allowed_tools": list(spec.allowed_tools),
        "budget": dict(spec.budget),
        "seed_tool_call_count": len(spec.parameters.get("seed_tool_calls") or ()),
        "scope_certificate_count": int(scope_certificates.get("certificate_count") or 0),
    }


def config_from_budget(
    budget: dict[str, Any],
    default: LLMEvidenceLoopConfig | None,
) -> LLMEvidenceLoopConfig:
    base = default or LLMEvidenceLoopConfig()
    return LLMEvidenceLoopConfig(
        max_rounds=int(budget.get("max_rounds") or base.max_rounds),
        max_tool_calls=int(budget.get("max_tool_calls") or base.max_tool_calls),
        stop_after_claim=bool(budget.get("stop_after_claim", base.stop_after_claim)),
        max_response_format_retries=int(
            budget.get("max_response_format_retries", base.max_response_format_retries)
        ),
        max_submission_corrections=budget.get("max_submission_corrections", base.max_submission_corrections),
        require_investigation_closure=budget.get("require_investigation_closure", base.require_investigation_closure),
        strict_json_schema=budget.get("strict_json_schema", base.strict_json_schema),
    )


def seed_tool_calls_from_parameters(parameters: dict[str, Any]) -> tuple[ToolCallPlan, ...]:
    calls = []
    for item in parameters.get("seed_tool_calls") or ():
        if not isinstance(item, dict):
            continue
        tool_name = item.get("tool_name") or item.get("name")
        if not tool_name:
            continue
        calls.append(
            ToolCallPlan(
                tool_name=str(tool_name),
                kwargs=dict(item.get("arguments") or item.get("kwargs") or {}),
                purpose=optional_string(item.get("purpose")),
            )
        )
    return tuple(calls)


def optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

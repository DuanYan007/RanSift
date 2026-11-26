"""Agent-specific prompt contracts for behavior evidence agents."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentPrompt:
    agent_id: str
    role: str
    responsibility: str
    exclusions: tuple[str, ...]
    default_task: str
    required_checks: tuple[str, ...] = ()
    benign_alternatives: tuple[str, ...] = ()
    tool_strategy: tuple[str, ...] = ()
    claim_types: tuple[str, ...] = ()
    few_shot_examples: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "responsibility": self.responsibility,
            "exclusions": list(self.exclusions),
            "default_task": self.default_task,
            "required_checks": list(self.required_checks),
            "benign_alternatives": list(self.benign_alternatives),
            "tool_strategy": list(self.tool_strategy),
            "claim_types": list(self.claim_types),
            "few_shot_examples": list(self.few_shot_examples),
        }


AGENT_PROMPTS: dict[str, AgentPrompt] = {
    "file_transformation": AgentPrompt(
        agent_id="file_transformation",
        role="file-transformation evidence analyst",
        responsibility=(
            "Assess whether retained sample events show file content writes, "
            "renames, deletes, extension changes, or repeated transformations."
        ),
        exclusions=(
            "Do not infer ransomware intent from counts alone.",
            "Do not treat unrelated host activity as sample behavior.",
            "Do not claim encryption unless the evidence supports transformation semantics.",
            "Do not stop at write-only evidence before checking rename, delete, or extension-change events.",
            "Do not emit an absent claim when the inspected process timeline or block replay is truncated; use uncertain until enough same-process evidence is checked.",
            "Do not treat WER, crash-dump, prefetch, or other diagnostic-only outputs as destructive transformation unless the evidence also shows user or shared-data targeting.",
        ),
        default_task="Find evidence for or against sample-attributed file transformation behavior.",
        required_checks=(
            "same-process attribution",
            "write, rename, delete, or extension-change semantics",
            "explicit SetRenameInformationFile or delete check before final behavior claim",
            "target continuity across operations",
            "bulk or repeated transformation scope",
            "user, public, desktop, document, share, or other non-system target namespace",
            "distinguish diagnostic/system outputs from user-data transformation",
        ),
        benign_alternatives=(
            "installer or updater writing application files",
            "archive extraction or backup synchronization",
            "document conversion or bulk user-file processing",
        ),
        tool_strategy=(
            "list_events:operation_index=setrenameinformationfile",
            "search_events:extension_change_or_ransomware_extension_marker",
            "list_blocks:behavior_kind=file_transformation",
            "get_block_events:selected_transformation_block,representative_only=false",
            "trace_target:target_scope_if_continuity_is_unclear",
        ),
        claim_types=(
            "file_transformation_behavior",
            "file_transformation_absent",
            "file_transformation_uncertain",
        ),
        few_shot_examples=(
            {
                "situation": "Need extension-change evidence before inspecting high-volume write blocks.",
                "next_action": {
                    "tool_request": {
                        "tool_name": "list_events",
                        "arguments": {"index_name": "operation_index", "key": "setrenameinformationfile", "limit": 40, "cursor": None},
                        "purpose": "inspect concrete rename operations and cite source events",
                    }
                },
            },
            {
                "situation": "A file-transformation block exists but representative events do not show semantics.",
                "next_action": {
                    "tool_request": {
                        "tool_name": "get_block_events",
                        "arguments": {"block_id": "macro_000123", "representative_only": False, "limit": 40},
                        "purpose": "replay enough events to verify write/rename/delete semantics before claiming transformation",
                    }
                },
            },
            {
                "situation": "Need extension-change evidence without knowing the final extension.",
                "next_action": {
                    "tool_request": {
                        "tool_name": "list_events",
                        "arguments": {"index_name": "operation_index", "key": "setrenameinformationfile", "limit": 40, "cursor": None},
                        "purpose": "inspect rename operations and cite concrete source events",
                    }
                },
            },
            {
                "situation": "Same-process evidence shows extension-changing renames across user documents.",
                "next_action": {
                    "claim_output": {
                        "claim_type": "file_transformation_behavior",
                        "statement": "Same-process events show repeated SetRenameInformationFile operations with extension-changing renames across user documents and follow-on file write activity.",
                        "confidence": "high",
                        "evidence_ref_ids": ["event:3077", "event:5275", "block:macro_193181"],
                        "supporting_block_ids": ["macro_193181"],
                        "alternative_explanations": ["legitimate bulk file processing"],
                        "uncertainty": ["retained dynamic evidence shows rename and write semantics but not original file contents"],
                        "risk_primitives": ["dynamic_user_data_transformation_destructive"],
                    }
                },
            },
        ),
    ),
    "file_discovery": AgentPrompt(
        agent_id="file_discovery",
        role="file-discovery evidence analyst",
        responsibility="Assess sample-attributed file and directory enumeration behavior.",
        exclusions=("Do not treat single benign file opens as target discovery.",),
        default_task="Find evidence for or against target file discovery.",
        required_checks=(
            "same-process attribution",
            "directory or target enumeration semantics",
            "user, shared, or document-like namespace coverage",
            "neighboring file content or transformation behavior",
        ),
        benign_alternatives=(
            "installer scanning application directories",
            "backup or synchronization software enumerating user files",
            "file manager or indexer behavior",
        ),
        tool_strategy=(
            "summarize_blocks:macro",
            "list_blocks:file_discovery",
            "get_block_events:selected_discovery_block",
            "neighbor_blocks:selected_discovery_block",
            "trace_target:representative_target_if_expansion_is_needed",
        ),
        claim_types=(
            "file_discovery_behavior",
            "file_discovery_absent",
            "file_discovery_uncertain",
        ),
    ),
    "registry": AgentPrompt(
        agent_id="registry",
        role="registry evidence analyst",
        responsibility="Assess registry discovery and modification evidence from retained events.",
        exclusions=("Do not infer persistence without registry write or execution context evidence.",),
        default_task="Find registry behavior that is relevant to risk analysis.",
        required_checks=(
            "same-process attribution",
            "registry key or value target",
            "query versus write distinction",
            "relation to execution, recovery, environment discovery, or persistence",
        ),
        benign_alternatives=(
            "compatibility checks",
            "installer registry setup",
            "ordinary application configuration reads",
        ),
        tool_strategy=(
            "list_blocks:behavior_kind=registry_modification",
            "list_events:operation_index=regsetvalue",
            "search_events:currentversion\\run_or_other_autostart_key",
            "get_window_around_event:representative_registry_write",
            "trace_target:registry_key_prefix",
        ),
        claim_types=("registry_behavior", "registry_absent", "registry_uncertain"),
        few_shot_examples=(
            {
                "situation": "Assess persistence-relevant registry writes.",
                "next_action": {
                    "tool_request": {
                        "tool_name": "list_events",
                        "arguments": {"index_name": "operation_index", "key": "regsetvalue", "limit": 30, "cursor": None},
                        "purpose": "find concrete registry writes before deciding whether persistence evidence exists",
                    }
                },
            },
            {
                "situation": "A registry write event cites CurrentVersion\\Run and a sample path.",
                "next_action": {
                    "claim_output": {
                        "claim_type": "registry_behavior",
                        "statement": "Sample-attributed registry write targets an autostart Run value and stores a sample executable path.",
                        "confidence": "high",
                        "evidence_ref_ids": ["event:312"],
                        "supporting_block_ids": [],
                        "alternative_explanations": ["installer autostart setup"],
                        "uncertainty": ["dynamic trace shows the write but not post-reboot execution"],
                    }
                },
            },
        ),
    ),
    "process": AgentPrompt(
        agent_id="process",
        role="process evidence analyst",
        responsibility=(
            "Assess process-local execution behavior, child execution, interpreter misuse, tool use, "
            "and executable deployment paired with durable auto-start configuration."
        ),
        exclusions=("Do not infer maliciousness from process creation alone.",),
        default_task="Summarize process-local behavior with evidence references.",
        required_checks=(
            "parent-child or same-process attribution",
            "tool or interpreter identity",
            "encoded or concealed interpreter execution and host-identifier collection when present",
            "deployed executable plus target-matched elevated scheduled-task persistence when present",
            "execution timing relative to file or recovery behavior",
            "failed launch versus executed activity",
        ),
        benign_alternatives=(
            "installer helper process",
            "runtime dependency loading",
            "legitimate system utility invocation",
        ),
        tool_strategy=(
            "summarize_processes",
            "list_events:operation_index=process create",
            "search_events:command_line_terms_such_as_cmd_powershell_vssadmin",
            "find_concealed_script_host_fingerprinting:verified concealed encoded script and hardware-ID chain",
            "find_deployed_elevated_autostart_tasks:verified deployment and elevated scheduled-task chain",
            "get_window_around_event:process_create_or_start_event",
            "trace_process:child_process_name_or_pid",
        ),
        claim_types=(
            "process_execution_behavior",
            "process_execution_absent",
            "process_execution_uncertain",
        ),
        few_shot_examples=(
            {
                "situation": "Assess helper-process execution chains.",
                "next_action": {
                    "tool_request": {
                        "tool_name": "list_events",
                        "arguments": {"index_name": "operation_index", "key": "process create", "limit": 30, "cursor": None},
                        "purpose": "find concrete process-create events with parent process attribution",
                    }
                },
            },
            {
                "situation": "Need command-line evidence for a system tool chain.",
                "next_action": {
                    "tool_request": {
                        "tool_name": "search_events",
                        "arguments": {"patterns": ["cmd.exe", "/c"], "fields": ["detail", "target", "process"], "limit": 20, "cursor": None},
                        "purpose": "retrieve command-line evidence rather than relying on process counts",
                    }
                },
            },
        ),
    ),
    "ransom_note": AgentPrompt(
        agent_id="ransom_note",
        role="ransom-note deployment evidence analyst",
        responsibility=(
            "Assess whether retained sample events show creation, writing, or distribution "
            "of ransom-note-like files or operator-facing recovery instructions."
        ),
        exclusions=(
            "Do not infer a ransom note from generic text-file writes alone.",
            "Do not treat unrelated README or documentation files as ransom notes without naming or context evidence.",
            "Do not claim note deployment unless concrete create/write events are cited.",
        ),
        default_task="Find evidence for or against sample-attributed ransom-note deployment.",
        required_checks=(
            "same-process attribution",
            "note-like filename or instruction-string evidence",
            "successful CreateFile or WriteFile semantics",
            "distribution scope across user, public, desktop, document, or shared directories",
            "relation to file transformation or recovery-inhibition behavior",
        ),
        benign_alternatives=(
            "installer or updater writing user-facing documentation",
            "benign application creating recovery or instruction text files",
            "test harness or analyst fixture using ransom-note-like filenames",
        ),
        tool_strategy=(
            "search_events:patterns=[restore_my_files],fields=[target,detail,process]",
            "search_events:patterns=[decrypt],fields=[target,detail,process]",
            "list_index_keys:path_index,pattern=restore_my_files",
            "get_window_around_event:representative_note_write",
            "trace_target:representative_note_path",
        ),
        claim_types=(
            "ransom_note_deployment_behavior",
            "ransom_note_deployment_absent",
            "ransom_note_deployment_uncertain",
        ),
        few_shot_examples=(
            {
                "situation": "Check for a known ransom-note filename before summarizing broad file writes.",
                "next_action": {
                    "tool_request": {
                        "tool_name": "search_events",
                        "arguments": {"patterns": ["restore_my_files"], "fields": ["target", "detail", "process"], "limit": 40, "cursor": None},
                        "purpose": "find concrete note create/write events and cite source events",
                    }
                },
            },
            {
                "situation": "A note-like target has successful CreateFile and WriteFile events in user directories.",
                "next_action": {
                    "claim_output": {
                        "claim_type": "ransom_note_deployment_behavior",
                        "statement": "Sample-attributed events create and write ransom-note-like files across user directories.",
                        "confidence": "high",
                        "evidence_ref_ids": ["event:13604", "event:13633"],
                        "supporting_block_ids": [],
                        "alternative_explanations": ["benign documentation generation"],
                        "uncertainty": ["dynamic trace shows file writes but not full note text"],
                        "risk_primitives": ["dynamic_ransom_note_deployment"],
                    }
                },
            },
        ),
    ),
    "recovery": AgentPrompt(
        agent_id="recovery",
        role="recovery-impact evidence analyst",
        responsibility="Assess backup, recovery, shadow-copy, service, and boot-impact behavior.",
        exclusions=("Do not claim recovery inhibition without concrete command or target evidence.",),
        default_task="Find evidence for or against recovery-impact behavior.",
        required_checks=(
            "command or target evidence",
            "same-process or child-process attribution",
            "impact surface such as shadow copy, backup catalog, service, boot, or safe mode",
            "failed probe versus successful modification",
        ),
        benign_alternatives=(
            "system maintenance",
            "installer service setup",
            "administrative backup tooling",
        ),
        tool_strategy=(
            "list_index_keys:process_name_index,pattern=vssadmin",
            "search_events:patterns=[vssadmin,delete shadows]",
            "list_events:process_name_index=vssadmin.exe",
            "get_window_around_event:cmd_or_vssadmin_event",
            "trace_process:process_name=vssadmin.exe",
        ),
        claim_types=(
            "recovery_impact_behavior",
            "recovery_impact_absent",
            "recovery_impact_uncertain",
        ),
        few_shot_examples=(
            {
                "situation": "Check shadow-copy deletion without guessing a synthetic index name.",
                "next_action": {
                    "tool_request": {
                        "tool_name": "search_events",
                        "arguments": {"patterns": ["vssadmin", "delete shadows"], "fields": ["detail", "target", "process"], "limit": 20, "cursor": None},
                        "purpose": "find concrete command-line evidence for recovery inhibition",
                    }
                },
            },
            {
                "situation": "The first recovery query returns zero matches.",
                "next_action": {
                    "tool_request": {
                        "tool_name": "list_index_keys",
                        "arguments": {"index_name": "process_name_index", "pattern": "vss", "limit": 20, "cursor": None},
                        "purpose": "recover by enumerating valid process-name keys instead of emitting an uncited absence claim",
                    }
                },
            },
        ),
    ),
    "anti_analysis": AgentPrompt(
        agent_id="anti_analysis",
        role="dynamic anti-analysis evidence analyst",
        responsibility="Assess environment, VM, debugger, sandbox, and monitor reconnaissance behavior.",
        exclusions=("Do not classify ordinary compatibility checks as anti-analysis without context.",),
        default_task="Find dynamic anti-analysis evidence or explain its absence.",
        required_checks=(
            "probe target and operation semantics",
            "same-process attribution",
            "whether the probe is followed by early exit or behavior suppression",
            "ordinary runtime compatibility check versus analysis-aware discovery",
        ),
        benign_alternatives=(
            "ordinary runtime compatibility check",
            "application environment setup",
            "dependency or locale discovery",
        ),
        tool_strategy=(
            "summarize_operations",
            "summarize_blocks:macro",
            "list_events:environment_or_runtime_probe",
            "trace_process:probe_process",
            "get_window_around_event:probe_representative_event",
        ),
        claim_types=(
            "anti_analysis_behavior",
            "anti_analysis_absent",
            "anti_analysis_uncertain",
        ),
    ),
    "evidence_auditor": AgentPrompt(
        agent_id="evidence_auditor",
        role="evidence auditor",
        responsibility="Verify that claims are supported by cited evidence references and blocks.",
        exclusions=("Do not search broadly for new claims.", "Do not repair unsupported claims by inventing evidence."),
        default_task="Review existing claims against cited evidence references.",
        required_checks=(
            "cited evidence refs resolve",
            "supporting blocks replay",
            "representative events align with the claim",
            "tool limitations are preserved",
        ),
        tool_strategy=(
            "get_event:cited_event_refs",
            "get_block:cited_or_supporting_blocks",
            "get_block_events:supporting_blocks",
            "neighbor_blocks:supporting_blocks",
            "explain_event_origin:cited_event_refs",
        ),
        claim_types=("accepted", "revised", "rejected"),
    ),
}


def default_prompt(agent_id: str) -> AgentPrompt:
    return AgentPrompt(
        agent_id=agent_id,
        role=f"{agent_id} evidence analyst",
        responsibility="Analyze assigned behavior using only tool-returned evidence.",
        exclusions=("Do not make unsupported claims.",),
        default_task="Analyze the assigned behavior question with evidence references.",
    )

"""Operation-level behavior classification shared by trace, index, and blocks."""
from __future__ import annotations


def classify_operation_family(operation: str) -> str:
    op = operation.casefold().strip()
    if op == "querydirectory":
        return "directory_enum"
    if op in {"createfile", "queryopen"}:
        return "file_open"
    if op == "readfile":
        return "file_read"
    if op in {"writefile", "setendoffileinformationfile"}:
        return "file_write"
    if "setrenameinformation" in op:
        return "file_rename"
    if "setdispositioninformation" in op:
        return "file_delete"
    if op in {"closefile", "irp_mj_close"}:
        return "file_close"
    if op.startswith("query") and ("file" in op or "information" in op):
        return "file_metadata_query"
    if op == "regsetvalue" or op.startswith("regcreate") or op.startswith("regdelete"):
        return "registry_write"
    if op.startswith("regset"):
        return "registry_metadata"
    if op.startswith("regopen") or op.startswith("regclose"):
        return "registry_open"
    if op.startswith("regquery") or op.startswith("regenum"):
        return "registry_query"
    if op in {"process start", "process create"}:
        return "process_start"
    if op == "load image":
        return "image_load"
    if op.startswith("tcp") or op.startswith("udp"):
        return "network_connect"
    if op == "process profiling":
        return "runtime_probe"
    if "thread" in op or "process" in op:
        return "runtime_activity"
    return "other"

BEHAVIOR_CLASSES = {
    "malicious_only",
    "risk_relevant",
    "dual_use",
    "absent",
    "uncertain",
    "static_strong",
    "unclassified",
}
MALICIOUS_POLICY_PRIMITIVES = {
    "dynamic_recovery_inhibition_destructive": (
        "Dynamic execution of a command that deletes, disables, or weakens recovery "
        "artifacts such as Volume Shadow Copies or boot recovery."
    ),
    "dynamic_user_data_transformation_destructive": (
        "High-confidence dynamic execution of repeated user- or shared-data transformation "
        "such as extension-changing renames, destructive writes, or delete-linked transformation "
        "that benign startup behavior does not plausibly explain."
    ),
    "dynamic_raw_filesystem_metadata_tampering": (
        "High-confidence dynamic writes to raw filesystem metadata objects such as $MFT, "
        "$Bitmap, or $LogFile."
    ),
    "dynamic_concealed_encoded_script_host_fingerprinting": (
        "High-confidence dynamic execution of an encoded PowerShell payload that explicitly hides its "
        "window while a sample-attributed process collects a hardware identifier. This establishes "
        "concealed host-fingerprinting execution, not encryption or extortion impact."
    ),
    "dynamic_deployed_elevated_autostart_task_persistence": (
        "High-confidence dynamic deployment of an executable followed by execution of a scheduled-task "
        "creation command that targets the same executable at logon or startup as SYSTEM with the highest "
        "run level."
    ),
    "dynamic_ransom_note_and_run_key_persistence": (
        "Corroborated dynamic evidence of a ransom-note-like artifact and an executable "
        "Run or RunOnce autostart binding in the same submitted sample."
    ),
    "embedded_extortion_template": (
        "Strong static extortion evidence such as a ransomware note template, strict "
        "note filename, or contact channel."
    ),
    "embedded_recovery_inhibition_command": (
        "Strong static evidence of commands that delete or disable recovery artifacts."
    ),
    "embedded_service_disruption_command": (
        "Strong static evidence of commands that terminate database, backup, or enterprise services."
    ),
    "embedded_ransom_note_name": (
        "Strong static evidence of a strict ransomware note filename."
    ),
    "embedded_ransomware_capability_symbols": (
        "Strong static symbols exposing ransomware capabilities across note deployment, "
        "file encryption, recovery removal, and target discovery."
    ),
}
RISK_RELEVANT_POLICY_PRIMITIVES = {
    "dynamic_ransom_note_artifact": (
        "A note-like filename was successfully created or written, but its content and "
        "extortion effect were not independently established."
    ),
    "dynamic_run_key_executable_binding": (
        "A successful Run or RunOnce value write binds an executable payload, but later "
        "autostart execution was not observed."
    ),
}
DUAL_USE_POLICY_PRIMITIVES = {
    "ordinary_file_output": (
        "Writes to an output or log artifact without supported destructive transformation "
        "of existing user data. Preserve uncertainty about contents and purpose."
    ),
    "filesystem_paging_io": (
        "Filesystem metadata writes explicitly recorded as paging I/O. This is an I/O "
        "observation, not proof of deliberate raw-metadata tampering; verified destructive "
        "metadata-write evidence continues to take priority."
    ),
    "ordinary_child_process_execution": (
        "Observed parent-child execution without a supported harmful command or effect. "
        "Creation of a helper or console process alone does not establish ransomware risk."
    ),
    "readonly_file_discovery": (
        "Directory enumeration, file reads, or metadata queries, including user documents, "
        "without a supported harmful operation or demonstrated target-selection purpose."
    ),
    "atomic_file_replacement": (
        "Temporary-file writes followed by replacement of an existing file path. This "
        "operation alone establishes neither encryption nor benign intent; independently "
        "supported destructive effects and ransomware-specific evidence take priority."
    ),
    "process_start_only": (
        "A sample-attributed process start without a child process, destructive command, "
        "or ransomware-stage behavior."
    ),
    "system_dependency_file_discovery": (
        "File discovery limited to Windows DLLs or system dependency paths, which is common "
        "during ordinary application startup."
    ),
    "system_application_file_discovery": (
        "File discovery confined to Windows, application, or controlled sample-local paths "
        "without direct user, shared, or document namespace coverage."
    ),
    "ordinary_registry_interaction": (
        "Registry query, key open/create, or value activity without a verified executable autostart "
        "binding, destructive setting, or confirmed persistence effect."
    ),
    "anti_analysis_absent": (
        "The anti-analysis agent found no debugger, VM, sandbox, monitor, or behavior-suppression signal."
    ),
}
OBSERVATION_BOUNDARY_POLICY = (
    "Confidence measures support for an observation, not maliciousness. Ordinary child "
    "execution, read-only discovery of user documents, and temporary-file replacement "
    "are dual-use operations. Do not promote them to malicious-only behavior from "
    "confidence, target location, counts, or rename wording alone. Retain independently "
    "supported destructive effects, ransomware-specific evidence, and verified contracts. "
    "A no_risk verdict still requires sufficient bounded role coverage and no unresolved "
    "risk-bearing claim; it describes the checked execution, not all possible behavior."
)
STATIC_STRONG_RISK_PRIMITIVES = {
    "static_extortion_template_strong": "embedded_extortion_template",
    "static_recovery_inhibition_command_strong": "embedded_recovery_inhibition_command",
    "static_service_disruption_command_strong": "embedded_service_disruption_command",
    "static_ransom_note_name_strong": "embedded_ransom_note_name",
    "static_ransomware_capability_symbols_strong": "embedded_ransomware_capability_symbols",
}
DESTRUCTIVE_RECOVERY_COMMAND_PATTERNS = (
    ("vssadmin_delete_shadows", ("vssadmin", "delete", "shadow")),
    ("vssadmin_resize_shadows", ("vssadmin", "resize", "shadow")),
    ("wmic_shadowcopy_delete", ("wmic", "shadowcopy", "delete")),
    ("wbadmin_delete", ("wbadmin", "delete")),
    ("bcdedit_disable_recovery", ("bcdedit", "recoveryenabled", "no")),
)
DESTRUCTIVE_RECOVERY_PATTERNS = tuple(
    terms for _, terms in DESTRUCTIVE_RECOVERY_COMMAND_PATTERNS
) + (
    ("shadow copy", "delete"),
    ("shadow copies", "delete"),
    ("recovery inhibition",),
    ("recovery impact", "delete"),
)
USER_DATA_SCOPE_TERMS = (
    "\\users\\", "c:\\users", "\\desktop", "\\documents", "\\downloads",
    "\\pictures", "\\videos", "\\music", "\\public", "\\onedrive",
    "\\share\\", "\\shares\\", "\\network share", "\\mapped drive",
)
DIRECT_USER_DATA_SCOPE_TERMS = (
    "\\desktop", "\\documents", "\\downloads", "\\pictures", "\\videos",
    "\\music", "\\public", "\\onedrive", "\\share\\", "\\shares\\",
    "\\network share", "\\mapped drive",
)
TRANSIENT_APPLICATION_SCOPE_TERMS = (
    "\\appdata\\local\\temp\\", "\\appdata\\local\\temp",
    "\\program files\\", "\\program files (x86)\\",
)
SYSTEM_OR_DIAGNOSTIC_SCOPE_TERMS = (
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "\\wer\\",
    "\\prefetch\\",
    "\\programdata\\microsoft\\windows\\wer\\",
    ".dmp",
    ".wer",
)
FILE_TRANSFORMATION_STRONG_TERMS = (
    "setrenameinformationfile",
    "extension change",
    "extension-changing",
    "renamed",
    "rename",
    "deletefile",
    "overwrote",
    "overwriting",
)
FILE_TRANSFORMATION_SCOPE_TERMS = (
    "multiple files",
    "many files",
    "bulk",
    "repeated file transformation",
    "repeated transformations",
    "across user directories",
    "across user files",
)
DETERMINISTIC_DIRECT_USER_EXTENSION_TRANSITION_RULE = "deterministic_same_process_direct_user_extension_transition"
DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE = "deterministic_same_process_direct_user_extension_rename"
DETERMINISTIC_REPEATED_EXTENSION_TRANSFORMATION_RULE = "deterministic_repeated_added_extension_write_delete_transformation"
DETERMINISTIC_REPEATED_EXTENSION_RENAME_TRANSFORMATION_RULE = "deterministic_repeated_nontransient_extension_append_rename_transformation"
DETERMINISTIC_RAW_FILESYSTEM_METADATA_WRITE_RULE = "deterministic_attributed_raw_filesystem_metadata_write"
DETERMINISTIC_RANSOM_NOTE_ARTIFACT_RULE = "deterministic_attributed_ransom_note_artifact"
DETERMINISTIC_RUN_KEY_EXECUTABLE_BINDING_RULE = "deterministic_attributed_run_key_executable_binding"
DETERMINISTIC_EXECUTED_DESTRUCTIVE_RECOVERY_COMMAND_RULE = "deterministic_attributed_destructive_recovery_command_execution"
DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE = "deterministic_attributed_concealed_encoded_script_host_fingerprinting"
DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE = "deterministic_attributed_deployed_elevated_autostart_task"
DETERMINISTIC_SYSTEM_CONTROLLED_FILE_DISCOVERY_RULE = "deterministic_system_controlled_file_discovery"


def annotate_claim_semantics(claim: dict) -> dict:
    """Return a claim copy with deterministic semantic-boundary fields."""
    out = dict(claim)
    out.update(classify_claim_semantics(out))
    return out


def classify_claim_semantics(claim: dict) -> dict:
    """Classify a candidate claim before verdict synthesis.

    The output separates risk-bearing primitives from benign-compatible
    primitives so verdict synthesis does not have to infer that boundary only
    from natural-language text.
    """
    if is_static_claim_like(claim):
        primitives = static_risk_primitives(claim)
        return {
            "behavior_class": "static_strong" if primitives else "unclassified",
            "risk_primitives": primitives,
            "dual_use_primitives": [],
        }
    malicious_primitives = claim_policy_primitives(claim)
    if malicious_primitives:
        return {
            "behavior_class": "malicious_only",
            "risk_primitives": malicious_primitives,
            "dual_use_primitives": [],
        }
    if is_absent_claim_like(claim):
        dual = claim_dual_use_primitives(claim)
        return {
            "behavior_class": "absent",
            "risk_primitives": [],
            "dual_use_primitives": dual,
        }
    deterministic_risk = deterministic_risk_primitives(claim)
    if deterministic_risk:
        return {
            "behavior_class": "risk_relevant",
            "risk_primitives": deterministic_risk,
            "dual_use_primitives": [],
        }
    certified_dual = certified_file_discovery_dual_use_primitives(claim)
    if certified_dual:
        # Confidence describes certainty in the finding, not its risk class.
        # Preserve the boundary already established from the cited source
        # evidence rather than erasing it when a claim has low confidence.
        return {
            "behavior_class": "dual_use",
            "risk_primitives": [],
            "dual_use_primitives": certified_dual,
        }
    dual = claim_dual_use_primitives(claim)
    explicitly_uncertain = (
        str(claim.get("claim_type") or "").casefold().endswith("uncertain")
        or str(claim.get("status") or "").casefold() in {"uncertain", "rejected"}
    )
    if dual and not explicitly_uncertain:
        return {
            "behavior_class": "dual_use",
            "risk_primitives": [],
            "dual_use_primitives": dual,
        }
    if is_uncertain_claim_like(claim):
        return {
            "behavior_class": "uncertain",
            "risk_primitives": [],
            "dual_use_primitives": [],
        }
    return {
        "behavior_class": "risk_relevant" if is_risk_relevant_claim(claim) else "unclassified",
        "risk_primitives": [
            item for item in declared_risk_primitives(claim) if item not in MALICIOUS_POLICY_PRIMITIVES
        ],
        "dual_use_primitives": [],
    }


def certified_file_discovery_dual_use_primitives(claim: dict) -> list[str]:
    """Retain a source-issued discovery boundary across claim normalization."""
    if (
        str(claim.get("agent_id") or "").casefold() != "file_discovery"
        or str(claim.get("claim_type") or "").casefold() != "file_discovery_behavior"
        or str(claim.get("behavior_class") or "").casefold() != "dual_use"
        or str(claim.get("status") or "").casefold() in {"uncertain", "rejected"}
        or not string_list(claim.get("evidence_ref_ids"))
        or DETERMINISTIC_SYSTEM_CONTROLLED_FILE_DISCOVERY_RULE
        not in string_list(claim.get("supporting_rule_ids"))
        or declared_risk_primitives(claim)
    ):
        return []
    return sorted({
        item
        for item in string_list(claim.get("dual_use_primitives"))
        if item in {"system_dependency_file_discovery", "system_application_file_discovery"}
    })


def claim_policy_primitives(claim: dict) -> list[str]:
    if is_static_claim_like(claim):
        return sorted(set(
            item
            for item in static_risk_primitives(claim)
            if item in MALICIOUS_POLICY_PRIMITIVES
        ))

    # A paired Process Create/Process Start contract establishes command
    # execution even when the command's external effect remains unobserved.
    # The contract is materialized by a deterministic tool, not self-attested
    # by the role agent.
    if has_deterministic_file_transformation(claim):
        return ["dynamic_user_data_transformation_destructive"]
    if has_deterministic_raw_filesystem_metadata_write(claim):
        return ["dynamic_raw_filesystem_metadata_tampering"]
    if has_deterministic_destructive_recovery_command(claim):
        return ["dynamic_recovery_inhibition_destructive"]
    if has_deterministic_concealed_script_host_fingerprinting(claim):
        return ["dynamic_concealed_encoded_script_host_fingerprinting"]
    if has_deterministic_deployed_elevated_autostart_task(claim):
        return ["dynamic_deployed_elevated_autostart_task_persistence"]

    # Dynamic policy primitives are not self-attested by an agent. A role can
    # propose one, but the boundary accepts it only after the claim itself meets
    # the confidence and semantic requirements below.
    if not is_dynamic_executed_claim(claim):
        return []
    agent_id = str(claim.get("agent_id") or "").casefold()
    claim_type = str(claim.get("claim_type") or "").casefold()
    text = claim_assertion_text(claim)
    primitives: list[str] = []
    if (
        agent_id == "recovery"
        and claim_type == "recovery_impact_behavior"
        and destructive_recovery_command_kind(text) is not None
    ):
        primitives.append("dynamic_recovery_inhibition_destructive")
    if (
        agent_id == "file_transformation"
        and claim_type == "file_transformation_behavior"
        and contains_high_precision_user_data_transformation(text)
    ):
        primitives.append("dynamic_user_data_transformation_destructive")
    return sorted(set(primitives))


def claim_dual_use_primitives(claim: dict) -> list[str]:
    declared = [item for item in string_list(claim.get("dual_use_primitives") or claim.get("dual_use_primitive"))]
    primitives = canonical_observational_primitives(claim, declared)
    claim_type = str(claim.get("claim_type") or "").casefold()
    agent_id = str(claim.get("agent_id") or "").casefold()
    text = claim_search_text(claim)
    status = str(claim.get("status") or "").casefold()
    if claim_type.endswith("absent") or status == "absent":
        if "anti_analysis" in agent_id or "anti_analysis" in claim_type:
            primitives.append("anti_analysis_absent")
        return sorted(set(primitives))
    if is_static_claim_like(claim) or claim_policy_primitives(claim):
        return sorted(set(primitives))
    if "process" in agent_id or "process_execution" in claim_type:
        if is_process_start_only_text(text):
            primitives.append("process_start_only")
    if "file_discovery" in agent_id or "file_discovery" in claim_type:
        if is_system_dependency_discovery_text(text):
            primitives.append("system_dependency_file_discovery")
        elif is_system_or_application_file_discovery_text(text):
            primitives.append("system_application_file_discovery")
    if "registry" in agent_id or "registry" in claim_type:
        if is_autostart_key_open_without_value_write_text(text):
            primitives.append("ordinary_registry_interaction")
        elif is_ordinary_registry_text(text):
            primitives.append("ordinary_registry_interaction")
    return sorted(set(primitives))


def canonical_observational_primitives(claim: dict, declared: list[str]) -> list[str]:
    """Preserve supported observational labels without treating them as intent."""
    aliases = {
        "child-process execution": "ordinary_child_process_execution",
        "child process execution": "ordinary_child_process_execution",
        "directory enumeration": "readonly_file_discovery",
        "file metadata queries": "readonly_file_discovery",
        "same-directory file replacement via setrenameinformationfile": "atomic_file_replacement",
    }
    role = str(claim.get("agent_id") or "").casefold()
    text = claim_assertion_text(claim).casefold()
    primitives = []
    for value in declared:
        name = aliases.get(value.casefold().strip(), value.casefold().strip())
        if name not in DUAL_USE_POLICY_PRIMITIVES:
            continue
        if name in {"ordinary_child_process_execution", "readonly_file_discovery", "atomic_file_replacement", "ordinary_file_output", "filesystem_paging_io"}:
            if declared_risk_primitives(claim):
                continue
            if name == "ordinary_child_process_execution":
                if role != "process" or has_non_negated_harmful_process_term(text):
                    continue
                if any(marker in text for marker in (" -enc", " -encodedcommand", "-windowstyle hidden", " -w hidden")):
                    continue
            elif name == "readonly_file_discovery":
                if role != "file_discovery":
                    continue
                if any(contains_unnegated_term(text, term) for term in ("writefile", "setrenameinformation", "deletefile", "encrypted")):
                    continue
            elif name == "atomic_file_replacement":
                if role != "file_transformation" or "temporar" not in text:
                    continue
                if not any(term in text for term in ("replace", "replacement")):
                    continue
                if contains_high_precision_user_data_transformation(text):
                    continue
            elif name == "ordinary_file_output":
                if role != "file_transformation" or not any(term in text for term in ("output", "log file", "log artifact")):
                    continue
                if contains_high_precision_user_data_transformation(text):
                    continue
            else:
                metadata_context = "metadata" in text or any(
                    marker in text for marker in ("$logfile", "$mft", "$bitmap", "$extend")
                )
                if role != "file_transformation" or "paging" not in text or not metadata_context:
                    continue
        primitives.append(name)
    return sorted(set(primitives))


def has_only_dual_use_or_absent_claims(claims: list[dict]) -> bool:
    if not claims:
        return True
    return all(is_no_risk_compatible_claim(claim) for claim in claims)


def no_risk_blocking_claim_ids(claims: list[dict]) -> list[str]:
    """Return positive observations that prevent a final no-risk classification."""
    return sorted(
        {
            claim_id
            for claim in claims
            if (claim_id := str(claim.get("claim_id") or ""))
            and not is_no_risk_compatible_claim(claim)
        }
    )


def is_no_risk_compatible_claim(claim: dict) -> bool:
    """Require every positive claim to have an explicit benign-compatible boundary."""
    behavior_class = str(claim.get("behavior_class") or "").casefold()
    if behavior_class in {"dual_use", "absent"} or is_absent_claim_like(claim):
        return True
    return bool(claim_dual_use_primitives(claim))


def declared_risk_primitives(claim: dict) -> list[str]:
    return sorted(set(
        string_list(claim.get("risk_primitives") or claim.get("risk_primitive"))
        + string_list(claim.get("malicious_primitives") or claim.get("malicious_primitive"))
        + string_list(claim.get("behavior_primitives") or claim.get("behavior_primitive"))
    ))


def static_risk_primitives(claim: dict) -> list[str]:
    claim_type = str(claim.get("claim_type") or "")
    primitives = [STATIC_STRONG_RISK_PRIMITIVES[claim_type]] if claim_type in STATIC_STRONG_RISK_PRIMITIVES else []
    primitives.extend(item for item in declared_risk_primitives(claim) if item.startswith("embedded_"))
    return sorted(set(primitives))


def is_dynamic_executed_claim(claim: dict) -> bool:
    claim_type = str(claim.get("claim_type") or "").casefold()
    status = str(claim.get("status") or "").casefold()
    confidence = str(claim.get("confidence") or "medium").casefold()
    refs = string_list(claim.get("evidence_ref_ids"))
    agent_id = str(claim.get("agent_id") or "").casefold()
    source = str(claim.get("source") or "").casefold()
    if claim_type.endswith(("absent", "uncertain")) or status in {"absent", "uncertain", "rejected"}:
        return False
    if confidence != "high":
        return False
    if agent_id in {"static", "static_strong"} or source.startswith("extract_static"):
        return False
    if refs and all(ref.startswith("static:") for ref in refs):
        return False
    return True


def has_deterministic_destructive_recovery_command(claim: dict) -> bool:
    """Accept a paired dynamic command-execution contract at medium or high confidence.

    The lower confidence may describe the unobserved *effect* of the command;
    it does not weaken the independently verified process-execution evidence.
    """
    if is_rejected_or_absent_claim(claim):
        return False
    if str(claim.get("agent_id") or "").casefold() != "recovery":
        return False
    if str(claim.get("claim_type") or "").casefold() != "recovery_impact_behavior":
        return False
    if str(claim.get("confidence") or "").casefold() not in {"medium", "high"}:
        return False
    if DETERMINISTIC_EXECUTED_DESTRUCTIVE_RECOVERY_COMMAND_RULE not in string_list(
        claim.get("supporting_rule_ids") or claim.get("supporting_rule_id")
    ):
        return False
    refs = set(string_list(claim.get("evidence_ref_ids")))
    return len(refs) >= 2 and all(ref.startswith("event:") for ref in refs)


def has_deterministic_file_transformation(claim: dict) -> bool:
    if is_rejected_or_absent_claim(claim):
        return False
    if str(claim.get("agent_id") or "").casefold() != "file_transformation":
        return False
    if str(claim.get("claim_type") or "").casefold() != "file_transformation_behavior":
        return False
    if str(claim.get("confidence") or "").casefold() != "high":
        return False
    rule_ids = set(string_list(claim.get("supporting_rule_ids") or claim.get("supporting_rule_id")))
    if not rule_ids & {
        DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE,
        DETERMINISTIC_DIRECT_USER_EXTENSION_TRANSITION_RULE,
        DETERMINISTIC_REPEATED_EXTENSION_TRANSFORMATION_RULE,
        DETERMINISTIC_REPEATED_EXTENSION_RENAME_TRANSFORMATION_RULE,
    }:
        return False
    refs = set(string_list(claim.get("evidence_ref_ids")))
    return len(refs) >= 2 and all(ref.startswith("event:") for ref in refs)


def has_deterministic_raw_filesystem_metadata_write(claim: dict) -> bool:
    if is_rejected_or_absent_claim(claim):
        return False
    if str(claim.get("agent_id") or "").casefold() != "file_transformation":
        return False
    if str(claim.get("claim_type") or "").casefold() != "file_transformation_behavior":
        return False
    if str(claim.get("confidence") or "").casefold() != "high":
        return False
    if DETERMINISTIC_RAW_FILESYSTEM_METADATA_WRITE_RULE not in string_list(
        claim.get("supporting_rule_ids") or claim.get("supporting_rule_id")
    ):
        return False
    refs = set(string_list(claim.get("evidence_ref_ids")))
    return len(refs) >= 2 and all(ref.startswith("event:") for ref in refs)


def has_deterministic_ransom_note_artifact(claim: dict) -> bool:
    if is_rejected_or_absent_claim(claim):
        return False
    if str(claim.get("agent_id") or "").casefold() != "ransom_note":
        return False
    if str(claim.get("claim_type") or "").casefold() not in {
        "ransom_note_deployment_behavior",
        "ransom_note_deployment_uncertain",
    }:
        return False
    if str(claim.get("confidence") or "").casefold() not in {"medium", "high"}:
        return False
    if DETERMINISTIC_RANSOM_NOTE_ARTIFACT_RULE not in string_list(
        claim.get("supporting_rule_ids") or claim.get("supporting_rule_id")
    ):
        return False
    refs = set(string_list(claim.get("evidence_ref_ids")))
    return bool(refs) and all(ref.startswith("event:") for ref in refs)


def has_deterministic_run_key_executable_binding(claim: dict) -> bool:
    if is_rejected_or_absent_claim(claim):
        return False
    if str(claim.get("agent_id") or "").casefold() != "registry":
        return False
    if str(claim.get("claim_type") or "").casefold() not in {
        "registry_behavior",
        "registry_uncertain",
    }:
        return False
    if str(claim.get("confidence") or "").casefold() not in {"medium", "high"}:
        return False
    if DETERMINISTIC_RUN_KEY_EXECUTABLE_BINDING_RULE not in string_list(
        claim.get("supporting_rule_ids") or claim.get("supporting_rule_id")
    ):
        return False
    refs = set(string_list(claim.get("evidence_ref_ids")))
    return bool(refs) and all(ref.startswith("event:") for ref in refs)


def deterministic_risk_primitives(claim: dict) -> list[str]:
    primitives: list[str] = []
    if has_deterministic_ransom_note_artifact(claim):
        primitives.append("dynamic_ransom_note_artifact")
    if has_deterministic_run_key_executable_binding(claim):
        primitives.append("dynamic_run_key_executable_binding")
    return sorted(set(primitives))


def cross_claim_policy_primitives(claims: list[dict]) -> list[dict[str, object]]:
    """Return policy primitives that require corroboration across role claims."""
    note_claims = [
        str(claim.get("claim_id") or "")
        for claim in claims
        if has_deterministic_ransom_note_artifact(claim)
        and str(claim.get("claim_id") or "")
    ]
    run_key_claims = [
        str(claim.get("claim_id") or "")
        for claim in claims
        if has_deterministic_run_key_executable_binding(claim)
        and str(claim.get("claim_id") or "")
    ]
    pairs = []
    for note_claim_id in sorted(set(note_claims)):
        for run_key_claim_id in sorted(set(run_key_claims)):
            pairs.append({
                "primitive": "dynamic_ransom_note_and_run_key_persistence",
                "claim_ids": [note_claim_id, run_key_claim_id],
            })
    return pairs


def has_deterministic_concealed_script_host_fingerprinting(claim: dict) -> bool:
    """Accept a high-confidence execution chain verified by the deterministic tool."""
    if is_rejected_or_absent_claim(claim):
        return False
    if str(claim.get("agent_id") or "").casefold() != "process":
        return False
    if str(claim.get("claim_type") or "").casefold() != "process_execution_behavior":
        return False
    if str(claim.get("confidence") or "").casefold() != "high":
        return False
    if DETERMINISTIC_CONCEALED_ENCODED_SCRIPT_HOST_FINGERPRINT_RULE not in string_list(
        claim.get("supporting_rule_ids") or claim.get("supporting_rule_id")
    ):
        return False
    refs = set(string_list(claim.get("evidence_ref_ids")))
    return len(refs) >= 2 and all(ref.startswith("event:") for ref in refs)



def has_deterministic_deployed_elevated_autostart_task(claim: dict) -> bool:
    """Accept the three-event deployed elevated scheduled-task contract."""
    if is_rejected_or_absent_claim(claim):
        return False
    if str(claim.get("agent_id") or "").casefold() != "process":
        return False
    if str(claim.get("claim_type") or "").casefold() != "process_execution_behavior":
        return False
    if str(claim.get("confidence") or "").casefold() != "high":
        return False
    if DETERMINISTIC_DEPLOYED_ELEVATED_AUTOSTART_TASK_RULE not in string_list(
        claim.get("supporting_rule_ids") or claim.get("supporting_rule_id")
    ):
        return False
    refs = set(string_list(claim.get("evidence_ref_ids")))
    return len(refs) >= 3 and all(ref.startswith("event:") for ref in refs)

def is_static_claim_like(claim: dict) -> bool:
    agent_id = str(claim.get("agent_id") or "").casefold()
    source = str(claim.get("source") or "").casefold()
    refs = string_list(claim.get("evidence_ref_ids"))
    return agent_id in {"static", "static_strong"} or source.startswith("extract_static") or any(ref.startswith("static:") for ref in refs)


def is_uncertain_or_absent_claim_like(claim: dict) -> bool:
    return is_absent_claim_like(claim) or is_uncertain_claim_like(claim)


def is_absent_claim_like(claim: dict) -> bool:
    claim_type = str(claim.get("claim_type") or "").casefold()
    status = str(claim.get("status") or "").casefold()
    return claim_type.endswith("absent") or status == "absent"


def is_uncertain_claim_like(claim: dict) -> bool:
    claim_type = str(claim.get("claim_type") or "").casefold()
    status = str(claim.get("status") or "").casefold()
    confidence = str(claim.get("confidence") or "").casefold()
    return claim_type.endswith("uncertain") or status in {"uncertain", "rejected"} or confidence == "low"


def is_rejected_or_absent_claim(claim: dict) -> bool:
    return str(claim.get("status") or "").casefold() in {"absent", "rejected"}


def claim_search_text(claim: dict) -> str:
    return " ".join([
        str(claim.get("agent_id") or ""),
        str(claim.get("claim_type") or ""),
        str(claim.get("statement") or ""),
        " ".join(string_list(claim.get("behavior_primitives") or claim.get("behavior_primitive"))),
        " ".join(string_list(claim.get("supporting_rule_ids"))),
        " ".join(string_list(claim.get("alternative_explanations"))),
        " ".join(string_list(claim.get("uncertainty"))),
    ]).casefold()


def claim_assertion_text(claim: dict) -> str:
    """Return affirmative claim text, excluding alternatives and uncertainty."""
    return " ".join([
        str(claim.get("statement") or ""),
        " ".join(string_list(claim.get("behavior_primitives") or claim.get("behavior_primitive"))),
        " ".join(string_list(claim.get("supporting_rule_ids"))),
    ]).casefold()


def contains_destructive_recovery_inhibition(text: str) -> bool:
    normalized = text.replace("-", " ")
    return any(all(term in normalized for term in pattern) for pattern in DESTRUCTIVE_RECOVERY_PATTERNS)


def destructive_recovery_command_kind(text: str) -> str | None:
    """Return a strict command family when a destructive recovery command is present."""
    normalized = str(text or "").casefold().replace("-", " ")
    for command_kind, pattern in DESTRUCTIVE_RECOVERY_COMMAND_PATTERNS:
        if all(term in normalized for term in pattern):
            return command_kind
    return None


def is_process_start_only_text(text: str) -> bool:
    if has_non_negated_harmful_process_term(text):
        return False
    start_terms = ("started successfully", "process start", "launched at pid", "executed once")
    no_child_terms = (
        "no additional child",
        "without a child",
        "only one process-start",
        "one process start",
        "no process-create events",
        "no process create events",
        "no child execution evidence",
    )
    return any(term in text for term in start_terms) and (any(term in text for term in no_child_terms) or "command line" in text)


def has_non_negated_harmful_process_term(text: str) -> bool:
    destructive_terms = ("delete shadows", "shadowcopy", "restore_my_files", "taskkill", "net stop")
    if any(term in text for term in destructive_terms):
        return True
    if any(term in text for term in ("wmic", "wbadmin", "bcdedit")):
        return True
    if contains_acl_or_ownership_tampering(text):
        return True
    if "vssadmin" in text:
        if not contains_unnegated_term(text, "vssadmin"):
            return False
        negated_vssadmin = (
            "no vssadmin", "no `vssadmin", "no evidence", "not found",
            "not matched", "not match", "not evidenced", "not observed",
        )
        return not any(term in text for term in negated_vssadmin)
    ambiguous_terms = ("ransom", "encrypt", "file transformation", "persistence", "run key")
    return any(contains_unnegated_term(text, term) for term in ambiguous_terms)


def is_system_dependency_discovery_text(text: str) -> bool:
    user_path_terms = (
        "\\users\\", "c:\\users", "\\desktop", "\\documents", "\\downloads",
        "\\pictures", "\\public", "\\onedrive", "\\share", "\\shares",
    )
    if any(term in text for term in user_path_terms):
        return False
    system_terms = ("system dll", "windows dll", "c:\\windows\\system32", "c:\\windows\\syswow64", "system namespace")
    dependency_terms = ("dll", "dependency", "module loading", "application startup", "runtime")
    return any(term in text for term in system_terms) and any(term in text for term in dependency_terms)


def is_system_or_application_file_discovery_text(text: str) -> bool:
    user_path_terms = (
        "\\users\\", "c:\\users", "\\desktop", "\\documents", "\\downloads",
        "\\pictures", "\\public", "\\onedrive", "\\share", "\\shares",
    )
    if any(term in text for term in user_path_terms):
        return False
    scope_terms = (
        "windows path", "windows paths", "c:\\windows", "system32", "syswow64",
        "application directory", "application path", "program files", "sample-local path",
        "sample local path", "controlled sample path",
    )
    discovery_terms = (
        "file metadata query", "file metadata queries", "metadata query", "metadata queries",
        "directory enumeration", "path enumeration", "querydirectory",
    )
    return any(term in text for term in scope_terms) and any(term in text for term in discovery_terms)


def is_ordinary_registry_text(text: str) -> bool:
    if has_non_negated_registry_risk_term(text):
        return False
    if any(term in text for term in ("access denied", "denied", "name not found", "not successful", "unsuccessful", "failed", "compatibility", "ordinary application", "configuration")):
        return True
    ordinary_paths = ("hklm\\software\\wow6432node", "muicache", "wintrust", "software publishing")
    return any(term in text for term in ordinary_paths)


def is_autostart_key_open_without_value_write_text(text: str) -> bool:
    """Classify key-only Run/RunOnce access separately from a value binding."""
    normalized = str(text or "").casefold()
    key_open_terms = (
        "regcreatekey", "regopenkey", "opened the autostart key", "opened the run key",
        "open of the run key", "key open",
    )
    autostart_terms = (
        "currentversion\\run", "currentversion\\runonce", "autostart key", "run key",
    )
    value_write_terms = (
        "regsetvalue", "value write", "wrote a value", "set a value", "bound an executable",
        "executable payload", "executable run or runonce binding",
    )
    return (
        any(term in normalized for term in key_open_terms)
        and any(term in normalized for term in autostart_terms)
        and not any(contains_unnegated_term(normalized, term) for term in value_write_terms)
    )


def has_non_negated_registry_risk_term(text: str) -> bool:
    destructive_terms = ("disable", "recoveryenabled", "safe boot", "service disruption")
    if any(contains_unnegated_term(text, term) for term in destructive_terms):
        return True
    persistence_path_terms = ("currentversion\\run", "\\run\\", "run key", "startup folder", "update microsoft defender")
    if any(contains_unnegated_term(text, term) for term in persistence_path_terms):
        return True
    return contains_unnegated_term(text, "autostart") or contains_unnegated_term(text, "persistence")


def contains_unnegated_term(text: str, term: str, window: int = 96) -> bool:
    start = 0
    while True:
        index = text.find(term, start)
        if index < 0:
            return False
        prefix = text[max(0, index - window):index]
        if not has_local_negation(prefix):
            return True
        start = index + len(term)


def has_local_negation(prefix: str) -> bool:
    if prefix.rstrip().endswith(("non-", "non")):
        return True
    negation_markers = (
        " no ", " not ", " without ", " nor ", " neither ", " never ",
        "does not", "do not", "did not", "is not", "are not", "was not", "were not",
        "not establish", "not established", "not confirmed", "not observed", "not evidenced",
        "rather than", "instead of", "not a", "not an",
        "no successful", "no evidence", "does not by", "do not by",
    )
    padded = f" {prefix} "
    return any(marker in padded for marker in negation_markers)


def is_risk_relevant_claim(claim: dict) -> bool:
    text = " ".join([
        str(claim.get("agent_id") or ""),
        str(claim.get("claim_type") or ""),
        str(claim.get("statement") or ""),
        " ".join(string_list(claim.get("supporting_rule_ids"))),
    ]).casefold()
    risk_terms = (
        "file_transformation",
        "ransom_note",
        "recovery",
        "vssadmin",
        "shadow",
        "static_recovery_inhibition",
        "static_extortion",
        "static_ransom_note",
        "static_service_disruption",
        "service_disruption",
        "anti_analysis",
        "sandbox",
        "debug",
        "icacls",
        "takeown",
        "permission",
        "acl",
    )
    return any(term in text for term in risk_terms)


def contains_high_precision_user_data_transformation(text: str) -> bool:
    normalized = text.replace("-", " ")
    user_scope = has_non_transient_user_data_scope(normalized)
    diagnostic_only = any(term in normalized for term in SYSTEM_OR_DIAGNOSTIC_SCOPE_TERMS)
    if (
        DETERMINISTIC_DIRECT_USER_EXTENSION_TRANSITION_RULE in normalized
        or DETERMINISTIC_DIRECT_USER_EXTENSION_RENAME_RULE in normalized
    ):
        return True
    strong_semantics = any(term in normalized for term in FILE_TRANSFORMATION_STRONG_TERMS)
    broad_scope = any(term in normalized for term in FILE_TRANSFORMATION_SCOPE_TERMS)
    ransomware_marker = any(term in normalized for term in (".locked", ".encrypted", "ransomware extension", "names ending in ."))
    explicit_change = any(contains_unnegated_term(normalized, term) for term in (
        "extension changing", "changed file extensions", "changing file extensions",
        "appended extension", "added extension", "files were encrypted", "encrypted file contents",
        "rendered unreadable", "confirmed content destruction",
    ))
    if diagnostic_only and not user_scope:
        return False
    if strong_semantics and (explicit_change or ransomware_marker) and (user_scope or broad_scope):
        return True
    if user_scope and broad_scope and explicit_change:
        return True
    return False


def has_non_transient_user_data_scope(text: str) -> bool:
    """Require user/shared data rather than installer or temporary staging paths."""
    if any(term in text for term in DIRECT_USER_DATA_SCOPE_TERMS):
        return True
    if not any(term in text for term in USER_DATA_SCOPE_TERMS):
        return False
    return not any(term in text for term in TRANSIENT_APPLICATION_SCOPE_TERMS)


def contains_acl_or_ownership_tampering(text: str) -> bool:
    acl_tool = any(term in text for term in ("icacls", "takeown"))
    acl_semantics = any(term in text for term in (" /grant", " grant ", " /deny", " deny ", "permission", "acl", "ownership", "inheritance", "recursive", "/t"))
    return acl_tool and acl_semantics


def string_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return [str(value)]

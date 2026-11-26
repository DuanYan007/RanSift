"""Source-enforced scope certificates for file-discovery claims."""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from .classification import (
    DETERMINISTIC_SYSTEM_CONTROLLED_FILE_DISCOVERY_RULE,
    classify_operation_family,
)
from .context import ClaimLedger
from .path_scope import is_controlled_sample_path


SCHEMA_VERSION = "harness-file-discovery-scope-certificates-v1"
SYSTEM_CONTROLLED_FILE_DISCOVERY_RULE = DETERMINISTIC_SYSTEM_CONTROLLED_FILE_DISCOVERY_RULE
SAFE_DISCOVERY_OPERATIONS = frozenset({
    "directory_enum",
    "file_open",
    "file_read",
    "file_metadata_query",
})


def apply_file_discovery_scope_certificates(
    claim_ledger: ClaimLedger,
    store: Any,
) -> dict[str, Any]:
    """Canonicalize claims whose cited evidence is system/control-only discovery.

    The LLM may describe a cited block more broadly than its retained targets
    support. This projection is deliberately narrow: it only applies when
    every cited event or block is non-mutating file discovery over Windows
    system paths or the controlled submitted-sample path.
    """
    certificates: list[dict[str, Any]] = []
    for claim_id, claim in list(claim_ledger.claims.items()):
        certificate = system_controlled_file_discovery_certificate(claim.to_dict(), store)
        if certificate is None:
            continue

        scopes = tuple(certificate["scope_kinds"])
        primitive = (
            "system_application_file_discovery"
            if "controlled_sample" in scopes
            else "system_dependency_file_discovery"
        )
        claim_ledger.claims[claim_id] = replace(
            claim,
            statement=certificate["statement"],
            supporting_block_ids=tuple(certificate["supporting_block_ids"]),
            alternative_explanations=(
                "ordinary dependency loading or application startup checks",
                "controlled submitted-sample inspection",
            ),
            supporting_rule_ids=unique_values(
                (*claim.supporting_rule_ids, SYSTEM_CONTROLLED_FILE_DISCOVERY_RULE)
            ),
            uncertainty=unique_values(
                (*claim.uncertainty, "The scope certificate is limited to the cited retained evidence.")
            ),
            behavior_class="dual_use",
            risk_primitives=(),
            dual_use_primitives=(primitive,),
            review_notes=unique_values(
                (*claim.review_notes, "source_scope_certificate:system_controlled_file_discovery")
            ),
        )
        certificates.append({
            "claim_id": claim_id,
            "rule_id": SYSTEM_CONTROLLED_FILE_DISCOVERY_RULE,
            "evidence_ref_ids": list(certificate["evidence_ref_ids"]),
            "supporting_block_ids": list(certificate["supporting_block_ids"]),
            "scope_kinds": list(scopes),
            "operation_families": list(certificate["operation_families"]),
            "behavior_class": "dual_use",
            "dual_use_primitive": primitive,
            "statement": certificate["statement"],
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "certificate_count": len(certificates),
        "certificates": certificates,
    }


def system_controlled_file_discovery_certificate(
    claim: dict[str, Any],
    store: Any,
) -> dict[str, Any] | None:
    if (
        str(claim.get("agent_id") or "").casefold() != "file_discovery"
        or str(claim.get("claim_type") or "").casefold() != "file_discovery_behavior"
    ):
        return None

    evidence_refs = unique_values(str(ref) for ref in claim.get("evidence_ref_ids") or () if str(ref))
    if not evidence_refs:
        return None

    scopes: set[str] = set()
    operations: set[str] = set()
    supporting_block_ids: set[str] = set()
    for ref_id in evidence_refs:
        if ref_id.startswith("block:"):
            block = resolve_block(store, ref_id)
            if block is None:
                return None
            if str(block.get("behavior_kind") or "").casefold() != "file_discovery":
                return None
            block_operations = {
                str(item).casefold()
                for item in block.get("operation_families") or ()
                if str(item)
            }
            if not block_operations or not block_operations <= SAFE_DISCOVERY_OPERATIONS:
                return None
            block_scopes = scopes_from_block(block)
            if not block_scopes:
                return None
            scopes.update(block_scopes)
            operations.update(block_operations)
            supporting_block_ids.add(str(block.get("block_id") or ref_id.removeprefix("block:")))
            continue

        if ref_id.startswith("event:"):
            event = resolve_event(store, ref_id)
            if event is None:
                return None
            operation = classify_operation_family(
                str((event.get("action") or {}).get("operation") or "")
            )
            if operation not in SAFE_DISCOVERY_OPERATIONS:
                return None
            scope = scope_from_event(event)
            if scope is None:
                return None
            scopes.add(scope)
            operations.add(operation)
            continue

        return None

    if not scopes or not operations:
        return None
    return {
        "evidence_ref_ids": evidence_refs,
        "supporting_block_ids": tuple(sorted(supporting_block_ids)),
        "scope_kinds": tuple(sorted(scopes)),
        "operation_families": tuple(sorted(operations)),
        "statement": canonical_statement(scopes, operations),
    }


def resolve_block(store: Any, ref_id: str) -> dict[str, Any] | None:
    block_id = ref_id.removeprefix("block:")
    try:
        block = store.get_block(block_id)
    except (IndexError, KeyError, TypeError, ValueError):
        return None
    return block if isinstance(block, dict) else None


def resolve_event(store: Any, ref_id: str) -> dict[str, Any] | None:
    try:
        offset = int(ref_id.removeprefix("event:"))
        event = store.get_event(offset)
    except (IndexError, KeyError, TypeError, ValueError):
        return None
    return event if isinstance(event, dict) else None


def scopes_from_block(block: dict[str, Any]) -> set[str] | None:
    declared_scope = scope_from_block_target_scope(str(block.get("target_scope") or ""))
    paths = [str(path) for path in block.get("target_examples") or () if str(path)]
    if not paths:
        return {declared_scope} if declared_scope else None
    scopes: set[str] = set()
    for path in paths:
        scope = scope_from_target(path, "")
        if scope is None:
            if declared_scope != "controlled_sample" or is_direct_user_or_shared_path(path):
                return None
            scope = declared_scope
        elif declared_scope and scope != declared_scope:
            return None
        scopes.add(scope)
    return scopes


def scope_from_block_target_scope(target_scope: str) -> str | None:
    normalized_scope = target_scope.casefold().strip()
    if normalized_scope.endswith(":controlled_sample"):
        return "controlled_sample"
    if normalized_scope.endswith(":windows"):
        return "windows"
    return None


def is_direct_user_or_shared_path(path: str) -> bool:
    normalized_path = path.casefold().replace("/", "\\")
    return (
        normalized_path.startswith("c:\\users\\")
        or "\\share\\" in normalized_path
        or "\\shares\\" in normalized_path
        or "\\network share" in normalized_path
        or "\\mapped drive" in normalized_path

    )

def scope_from_event(event: dict[str, Any]) -> str | None:
    target = event.get("target") or {}
    return scope_from_target(
        str(target.get("normalized_path") or target.get("path") or ""),
        str(target.get("namespace") or ""),
    )


def scope_from_target(path: str, namespace: str) -> str | None:
    normalized_path = path.casefold().replace("/", "\\")
    normalized_namespace = namespace.casefold().strip()
    if normalized_namespace == "controlled_sample":
        return "controlled_sample"
    if normalized_namespace in {"windows", "system"}:
        return "windows"
    if normalized_namespace in {"", "other"} and is_controlled_sample_path(normalized_path):
        return "controlled_sample"
    if normalized_path == "c:\\windows" or normalized_path.startswith("c:\\windows\\"):
        return "windows"
    return None


def canonical_statement(scopes: set[str], operations: set[str]) -> str:
    scope_text = []
    if "windows" in scopes:
        scope_text.append("Windows system")
    if "controlled_sample" in scopes:
        scope_text.append("the controlled submitted-sample")
    operation_text = ", ".join(sorted(operations)).replace("_", " ")
    return (
        "Cited sample-attributed file-discovery evidence is limited to "
        + " and ".join(scope_text)
        + f" paths through {operation_text}. No cited observation targets direct user or shared data."
    )


def unique_values(values: tuple[str, ...] | list[str] | Any) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value) for value in values if str(value)))

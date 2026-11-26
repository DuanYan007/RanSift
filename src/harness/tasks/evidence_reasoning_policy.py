"""Claim relationships, investigation closure and comparison of behavioral explanations."""
from __future__ import annotations

from copy import deepcopy
from itertools import combinations
from pathlib import Path
import json

from harness.behavior.investigation_closure import SCHEMA as CLOSURE_SCHEMA
from harness.behavior.reasoning import text, texts

CONNECTION_SCHEMA = [{
    "claim_ids": ["at least two distinct supplied claim ids"],
    "relation": "process_delegation|shared_object|temporal_sequence|overlapping_observation|same_process",
    "evidence_ref_ids": ["event:* or block:* owned by these claims"],
    "explanation": "what the observed connection establishes",
    "limitations": ["missing intermediate operations, attribution limits, or unconfirmed causality"],
}]
HYPOTHESIS_SCHEMA = {
    label: {"supporting_claim_ids": ["supplied claim id"],
            "contradicting_claim_ids": ["supplied claim id"],
            "explanation": "what this explanation accounts for and what it does not",
            "unconfirmed_assumptions": ["premises not established by the observations"]}
    for label in ("malicious", "benign")
}
SYMMETRIC_INSTRUCTION = (
    " Apply the same evidentiary standard to malicious and benign explanations. "
    "For each, identify supporting observations, contradictory observations and unconfirmed assumptions. "
    "Lack of authorization, installer provenance, or a known legitimate purpose does not itself establish malicious intent. "
    "Conversely, ordinary runtime loading, unpacking or configuration saving explains only those operations, not the executable's entire purpose. "
    "For registry writes, distinguish the written value, the documented meaning of that value, a change from its prior state, "
    "and the inferred purpose. An unknown prior value limits claims of a state change; it does not erase observed write semantics "
    "or independently supported attack intent. Application startup or a nearby settings save does not by itself explain an anomalous write. "
    "Do not require a prior value or successful damage when the requested action and corroborating context already support malicious conduct. "
    "Failed operations can still support an attack attempt "
    "when their requested action and context establish attack semantics; successful final damage is not required. "
    "Do not identify a test program, trusted tool or malware family from regularity or a filename alone. "
    "Review actual premises rather than substituting a stronger argument the initial analyst did not make. "
    "Unknown activity and incomplete coverage support neither class by themselves. "
    "Do not require proof of harmlessness or presume an undocumented operation malicious."
)
LINK_INSTRUCTION = (
    " Connect relevant findings across roles using observed process instances, parent-child execution, target continuity and event order. "
    "Return claim_connections, or an empty list if no connection is supported. "
    "Connection candidates are retrieval hints, not causal edges, independent corroboration or risk votes. "
    "Shared events are overlapping observations; the same process or target does not establish causality. "
    "Explain any missing transition between unpacking, delegated execution and later behavior; never fill it by inference alone."
)


def collect_closures(context):
    result = []
    for source, task in sorted(context.state.task_results.items()):
        if not source.startswith("evidence_"):
            continue
        ref = task.artifacts.get("evidence_loop_result")
        data = json.loads(Path(ref.path).read_text()) if ref else {}
        closure = data.get("diagnostics", {}).get("investigation_closure")
        if not isinstance(closure, dict) or closure.get("schema_version") != CLOSURE_SCHEMA:
            raise ValueError("v029 requires fresh closure-aware investigation: " + source)
        result.append({"source_task_id": source, "coverage_id": source + ":coverage", **closure})
    if not result:
        raise ValueError("v029 investigation closure records are missing")
    return result


def connection_candidates(claims, observations, *, limit=64):
    events = {}
    for fact in observations:
        for event in fact.get("event_examples", []):
            if type(event.get("offset")) is int:
                events.setdefault("event:" + str(event["offset"]), event)
    nodes = []
    for claim in claims:
        refs = set(claim.get("evidence_ref_ids", []))
        visible = [events[ref] for ref in sorted(refs) if ref in events]
        nodes.append({"claim_id": claim["claim_id"], "agent_id": claim.get("agent_id", ""),
                      "refs": refs, "processes": {e.get("process", {}).get("node_id") for e in visible} - {None, ""},
                      "targets": {e.get("target", "").casefold() for e in visible if isinstance(e.get("target"), str) and e["target"]},
                      "offsets": [e["offset"] for e in visible]})
    candidates = []
    for a, b in combinations(nodes, 2):
        if a["agent_id"] == b["agent_id"]:
            continue
        shared = sorted(a["refs"] & b["refs"])
        processes = sorted(a["processes"] & b["processes"])
        targets = sorted(a["targets"] & b["targets"])
        if not (shared or processes or targets):
            continue
        candidates.append({"claim_ids": [a["claim_id"], b["claim_id"]],
            "shared_evidence_refs": shared, "shared_process_instances": processes,
            "shared_target_paths": targets[:8], "shared_target_count": len(targets),
            "cited_event_order_bounds": {n["claim_id"]: [min(n["offsets"]), max(n["offsets"])]
                                        for n in [a, b] if n["offsets"]},
            "causality_established": False})
    return {"items": candidates[:limit], "matched_count": len(candidates),
            "returned_count": min(limit, len(candidates)), "omitted_count": max(0, len(candidates) - limit),
            "limitations": ["Only cited event examples are compared; nonoverlap does not establish independence. Parent-child or rename causality requires inspecting the supplied evidence."]}


def augment(payload, claims, observations, *, closures=None, claim_linking=False, symmetric_review=False):
    payload = deepcopy(payload)
    payload["reference_contract"] = {
        "claim_ids": [claim["claim_id"] for claim in claims],
        "evidence_refs_by_claim": {claim["claim_id"]: list(claim.get("evidence_ref_ids", [])) for claim in claims},
        "coverage_ids": list(payload.get("analysis_coverage", {}).get("coverage_ids", [])),
        "source_fact_ids": [fact["source_task_id"] + ":" + fact["fact_id"] for fact in observations],
        "rules": [
            "All *_claim_ids fields accept only claim_ids; never coverage or source fact IDs.",
            "Use coverage_ids and source_fact_ids only in analysis_gaps; a zero-match query is a scoped gap, not a claim.",
            "Connection evidence_ref_ids must be owned by its listed claim_ids, with at least one reference from each claim.",
            "Do not borrow an adjacent event from source_observations unless a listed claim owns that exact reference.",
        ],
    }
    payload["instruction"] += " Follow reference_contract: claim IDs, coverage IDs, query-result IDs and event/block IDs are separate namespaces."
    if closures is not None:
        payload["investigation_closures"] = closures
        payload["instruction"] += " Preserve material unresolved investigation leads as analysis gaps; task completion is not evidence that all behavior was examined."
    if claim_linking:
        payload["claim_connection_candidates"] = connection_candidates(claims, observations)
        payload["output_schema"]["claim_connections"] = CONNECTION_SCHEMA
        payload["instruction"] += LINK_INSTRUCTION
    if symmetric_review:
        payload["output_schema"]["hypothesis_assessment"] = HYPOTHESIS_SCHEMA
        payload["instruction"] += SYMMETRIC_INSTRUCTION
    return payload


def preserve_closure_gaps(verdict, closures):
    """A final binary choice cannot erase a recorded uncompleted investigation."""
    if closures is None:
        return verdict
    verdict["investigation_closures"] = deepcopy(closures)
    gaps = verdict.setdefault("analysis_gaps", [])
    for closure in closures:
        for lead in closure["leads"]:
            if lead["status"] != "unresolved":
                continue
            description = ("Unresolved investigation lead " + closure["source_task_id"] + ":" + lead["lead_id"]
                           + ". " + lead["explanation"] + " Next step: " + lead["next_step"])
            if any(gap["description"] == description for gap in gaps):
                continue
            gaps.append({"description": description, "impact": "material",
                         "coverage_ids": [closure["coverage_id"]], "source_fact_ids": []})
            verdict["analysis_status"] = "incomplete"
    return verdict


def normalize_extensions(response, claims, *, claim_linking=False, symmetric_review=False):
    known = {c["claim_id"]: c for c in claims}

    def ids(value, field, required=False):
        refs = texts(value, field, required=required)
        if set(refs) - set(known):
            raise ValueError(field + " cites unknown claims: " + str(sorted(set(refs) - set(known)))
                             + "; use reference_contract.claim_ids only")
        return refs

    output, errors = {}, []
    if claim_linking:
        raw = response.get("claim_connections")
        if not isinstance(raw, list):
            errors.append("claim_connections must be an explicit list")
            raw = []
        connections = []
        for index, item in enumerate(raw):
            try:
                if not isinstance(item, dict) or set(item) != set(CONNECTION_SCHEMA[0]):
                    raise ValueError("invalid claim connection")
                claims_in_link = ids(item.get("claim_ids"), "connection claim_ids", True)
                if len(claims_in_link) < 2:
                    raise ValueError("a connection requires at least two distinct claims")
                if not isinstance(item.get("relation"), str) or item["relation"] not in {"process_delegation", "shared_object", "temporal_sequence", "overlapping_observation", "same_process"}:
                    raise ValueError("invalid connection relation")
                refs = texts(item.get("evidence_ref_ids"), "connection evidence_ref_ids", required=True)
                owned = {r for cid in claims_in_link for r in known[cid].get("evidence_ref_ids", [])}
                if set(refs) - owned or any(not ref.startswith(("event:", "block:")) for ref in refs):
                    raise ValueError("connection cites evidence not owned by its claims: "
                                     + str(sorted(set(refs) - owned)) + "; allowed evidence_refs_by_claim: "
                                     + str({cid: known[cid].get("evidence_ref_ids", []) for cid in claims_in_link}))
                if any(not set(refs).intersection(known[cid].get("evidence_ref_ids", [])) for cid in claims_in_link):
                    raise ValueError("a connection needs evidence from each cited claim")
                connections.append({"claim_ids": claims_in_link, "relation": item["relation"], "evidence_ref_ids": refs,
                    "explanation": text(item.get("explanation"), "connection explanation"),
                    "limitations": texts(item.get("limitations", []), "connection limitations")})
            except ValueError as exc:
                errors.append(f"claim_connections[{index}]: {exc}")
        output["claim_connections"] = connections
    if symmetric_review:
        raw = response.get("hypothesis_assessment")
        if not isinstance(raw, dict) or set(raw) != {"malicious", "benign"}:
            errors.append("hypothesis_assessment must examine malicious and benign explanations")
            raw = {}
        hypotheses = {}
        for label, item in raw.items():
            try:
                if not isinstance(item, dict) or set(item) != set(HYPOTHESIS_SCHEMA[label]):
                    raise ValueError("invalid hypothesis assessment fields")
                # Both lists are checked so an invalid support list does not
                # conceal a second invalid contradiction list.
                validated, id_errors = {}, []
                for field, description in [("supporting_claim_ids", "hypothesis support"),
                                           ("contradicting_claim_ids", "hypothesis contradiction")]:
                    try:
                        validated[field] = ids(item[field], description)
                    except ValueError as exc:
                        id_errors.append(str(exc))
                if id_errors:
                    raise ValueError("; ".join(id_errors))
                hypotheses[label] = {**validated,
                    "explanation": text(item["explanation"], "hypothesis explanation"),
                    "unconfirmed_assumptions": texts(item["unconfirmed_assumptions"], "unconfirmed_assumptions")}
            except ValueError as exc:
                errors.append(f"hypothesis_assessment.{label}: {exc}")
        output["hypothesis_assessment"] = hypotheses
    if errors:
        raise ValueError("; ".join(errors))
    return output

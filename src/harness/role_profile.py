"""Investigator prompts and analysis configuration."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.behavior.agent_prompts import AGENT_PROMPTS, AgentPrompt, default_prompt


ROLE_PROFILE_SCHEMA = "harness-role-profile-v1"
DEFAULT_PROFILE_ID = "builtin-default"
TEXT_FIELDS = ("role", "responsibility", "default_task")
SEQUENCE_FIELDS = (
    "exclusions",
    "required_checks",
    "benign_alternatives",
    "tool_strategy",
    "claim_types",
)
PATCH_FIELDS = set(TEXT_FIELDS) | set(SEQUENCE_FIELDS) | {
    f"{field}_append" for field in SEQUENCE_FIELDS
}


@dataclass(frozen=True)
class RoleProfile:
    profile_id: str
    parent_profile_id: str
    change_hypothesis: str
    agent_overrides: dict[str, dict[str, Any]]
    source_path: str = ""
    override_layers: tuple[dict[str, dict[str, Any]], ...] = ()
    inheritance_chain: tuple[dict[str, str], ...] = ()
    analysis_protocol: str = "legacy-v1"
    max_submission_corrections: int = 0
    investigation_closure: bool = False
    claim_linking: bool = False
    symmetric_review: bool = False
    strict_json_schema: bool = False
    unified_references: bool = False

    def evidence_budget(self):
        if self.max_submission_corrections or self.investigation_closure or self.strict_json_schema:
            budget = {"max_rounds": 6, "max_tool_calls": 10,
                      "max_submission_corrections": self.max_submission_corrections}
            if self.investigation_closure:
                budget["require_investigation_closure"] = True
            if self.strict_json_schema:
                budget["strict_json_schema"] = True
            return budget
        return None

    def resolve_agent_prompts(self) -> dict[str, AgentPrompt]:
        if self.analysis_protocol in {"evidence-reasoning-v2", "evidence-binary-v1"}:
            from harness.behavior.reasoning_v2 import reasoning_agent_prompts
            prompts = reasoning_agent_prompts()
        elif self.analysis_protocol == "evidence-reasoning-v1":
            from harness.behavior.reasoning import reasoning_agent_prompts
            prompts = reasoning_agent_prompts()
        else:
            prompts = dict(AGENT_PROMPTS)
        layers = self.override_layers or (self.agent_overrides,)
        for layer in layers:
            for agent_id, patch in layer.items():
                prompts[agent_id] = apply_prompt_patch(
                    prompts.get(agent_id, default_prompt(agent_id)),
                    patch,
                )
        return prompts

    def snapshot(self) -> dict[str, Any]:
        payload = {
            "schema_version": ROLE_PROFILE_SCHEMA,
            "profile_id": self.profile_id,
            "parent_profile_id": self.parent_profile_id,
            "change_hypothesis": self.change_hypothesis,
            "source_path": self.source_path,
            "agent_overrides": self.agent_overrides,
            "inheritance_chain": list(self.inheritance_chain),
            "resolved_agent_prompts": {
                agent_id: prompt.to_dict()
                for agent_id, prompt in sorted(self.resolve_agent_prompts().items())
            },
        }
        if self.analysis_protocol != "legacy-v1":
            payload["analysis_protocol"] = self.analysis_protocol
        if self.max_submission_corrections:
            payload["max_submission_corrections"] = self.max_submission_corrections
        for name in ("investigation_closure", "claim_linking", "symmetric_review", "strict_json_schema", "unified_references"):
            if getattr(self, name):
                payload[name] = True
        payload["profile_sha256"] = canonical_sha256(payload)
        return payload


def load_role_profile(path: str | Path | None = None) -> RoleProfile:
    if path is None:
        return RoleProfile(
            profile_id=DEFAULT_PROFILE_ID,
            parent_profile_id="",
            change_hypothesis="Built-in role prompts without an external override.",
            agent_overrides={},
            override_layers=({},),
            inheritance_chain=(
                {
                    "profile_id": DEFAULT_PROFILE_ID,
                    "parent_profile_id": "",
                    "source_path": "",
                    "source_sha256": "",
                },
            ),
        )
    return load_role_profile_from_source(Path(path).resolve(), ())


def load_role_profile_from_source(source: Path, ancestors: tuple[Path, ...]) -> RoleProfile:
    if source in ancestors:
        chain = " -> ".join(item.name for item in ancestors + (source,))
        raise ValueError(f"role profile inheritance cycle: {chain}")
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("role profile must be a JSON object")
    if str(data.get("schema_version") or "") != ROLE_PROFILE_SCHEMA:
        raise ValueError(f"unsupported role profile schema: {data.get('schema_version')!r}")

    profile_id = required_profile_id(data.get("profile_id"))
    parent_profile_id = optional_profile_id(data.get("parent_profile_id"))
    change_hypothesis = required_text(data.get("change_hypothesis"), "change_hypothesis")
    overrides = normalize_overrides(data.get("agent_overrides"))
    layer = {
        "profile_id": profile_id,
        "parent_profile_id": parent_profile_id,
        "source_path": str(source),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    if parent_profile_id:
        parent_source = source.parent / f"{parent_profile_id}.json"
        if not parent_source.is_file():
            raise FileNotFoundError(
                f"parent role profile {parent_profile_id!r} for {profile_id!r} was not found; "
                f"expected sibling profile {parent_source}"
            )
        parent = load_role_profile_from_source(parent_source.resolve(), ancestors + (source,))
        if parent.profile_id != parent_profile_id:
            raise ValueError(
                f"parent profile id mismatch for {profile_id!r}: expected {parent_profile_id!r}, "
                f"found {parent.profile_id!r} in {parent_source}"
            )
        override_layers = parent.override_layers + (overrides,)
        inheritance_chain = parent.inheritance_chain + (layer,)
    else:
        override_layers = (overrides,)
        inheritance_chain = (layer,)
    analysis_protocol = data.get("analysis_protocol", parent.analysis_protocol if parent_profile_id else "legacy-v1")
    if analysis_protocol not in {"legacy-v1", "evidence-reasoning-v1", "evidence-reasoning-v2", "evidence-binary-v1"}:
        raise ValueError(f"unsupported analysis_protocol: {analysis_protocol!r}")
    corrections = data.get("max_submission_corrections", parent.max_submission_corrections if parent_profile_id else 0)
    if type(corrections) is not int or corrections not in (0, 1):
        raise ValueError("max_submission_corrections must be 0 or 1")
    if corrections and analysis_protocol not in {"evidence-reasoning-v2", "evidence-binary-v1"}:
        raise ValueError("submission correction requires the compatible investigation protocol")
    options = {}
    for name in ("investigation_closure", "claim_linking", "symmetric_review", "strict_json_schema", "unified_references"):
        value = data.get(name, getattr(parent, name) if parent_profile_id else False)
        if type(value) is not bool:
            raise ValueError(f"{name} must be a boolean")
        if value and analysis_protocol != "evidence-binary-v1":
            raise ValueError(f"{name} requires evidence-binary-v1")
        options[name] = value
    if options['strict_json_schema'] and not options['investigation_closure']:
        raise ValueError('strict_json_schema requires investigation_closure')
    if options['unified_references'] and not options['strict_json_schema']:
        raise ValueError('unified_references requires strict_json_schema')
    return RoleProfile(
        profile_id=profile_id,
        parent_profile_id=parent_profile_id,
        change_hypothesis=change_hypothesis,
        agent_overrides=overrides,
        source_path=str(source),
        override_layers=override_layers,
        inheritance_chain=inheritance_chain,
        analysis_protocol=analysis_protocol,
        max_submission_corrections=corrections,
        **options,
    )


def apply_prompt_patch(base: AgentPrompt, patch: dict[str, Any]) -> AgentPrompt:
    data: dict[str, Any] = {
        "agent_id": base.agent_id,
        "role": base.role,
        "responsibility": base.responsibility,
        "exclusions": base.exclusions,
        "default_task": base.default_task,
        "required_checks": base.required_checks,
        "benign_alternatives": base.benign_alternatives,
        "tool_strategy": base.tool_strategy,
        "claim_types": base.claim_types,
        "few_shot_examples": base.few_shot_examples,
    }
    for field in TEXT_FIELDS:
        if field in patch:
            data[field] = required_text(patch[field], f"{base.agent_id}.{field}")

    for field in SEQUENCE_FIELDS:
        values = tuple(data[field])
        if field in patch:
            values = tuple(normalize_string_list(patch[field], f"{base.agent_id}.{field}"))
        append_field = f"{field}_append"
        if append_field in patch:
            values = deduplicated(values + tuple(normalize_string_list(patch[append_field], f"{base.agent_id}.{append_field}")))
        data[field] = values
    return AgentPrompt(**data)


def normalize_overrides(value: Any) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("agent_overrides must be a JSON object")
    normalized: dict[str, dict[str, Any]] = {}
    for raw_agent_id, raw_patch in value.items():
        agent_id = required_profile_id(raw_agent_id)
        if not isinstance(raw_patch, dict):
            raise ValueError(f"agent_overrides.{agent_id} must be a JSON object")
        unknown = sorted(set(raw_patch) - PATCH_FIELDS)
        if unknown:
            raise ValueError(f"agent_overrides.{agent_id} has unsupported fields: {unknown}")
        for field in SEQUENCE_FIELDS:
            if field in raw_patch and f"{field}_append" in raw_patch:
                raise ValueError(f"agent_overrides.{agent_id} cannot set both {field} and {field}_append")
        normalized[agent_id] = dict(raw_patch)
    return normalized


def normalize_string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    items = [required_text(item, field_name) for item in value]
    return list(deduplicated(tuple(items)))


def required_profile_id(value: Any) -> str:
    text = required_text(value, "profile_id")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", text):
        raise ValueError(f"invalid profile id: {text!r}")
    return text


def optional_profile_id(value: Any) -> str:
    if value is None or str(value).strip() == "":
        return ""
    return required_profile_id(value)


def required_text(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} must be a non-empty string")
    return text


def deduplicated(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def canonical_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

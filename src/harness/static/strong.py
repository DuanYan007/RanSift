"""Static indicators for ransom content, recovery commands and related artifacts."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.behavior.classification import annotate_claim_semantics

ASCII_RE = re.compile(rb"[ -~]{4,}")
UTF16_RE = re.compile(rb"(?:[ -~]\x00){4,}")

RULE_PATTERNS: dict[str, tuple[str, ...]] = {
    "strong_extortion_phrase": (
        r"your\s+files\s+(?:have\s+been\s+|are\s+|were\s+)?encrypted",
        r"all\s+(?:your\s+)?(?:data|files)\s+(?:was\s+|has\s+been\s+|were\s+)?encrypted",
        r"files\s+have\s+been\s+encrypted",
        r"how\s+to\s+(?:restore|recover|decrypt)\s+(?:your\s+)?files",
        r"to\s+(?:restore|recover|decrypt)\s+(?:your\s+)?files",
        r"pay\s+(?:the\s+)?ransom",
        r"decryption\s+(?:software|tool|key)",
        r"private\s+key\s+.*decrypt",
        r"do\s+not\s+(?:rename|modify).*encrypted",
    ),
    "strong_ransom_note_name": (
        r"ryukreadme\.html",
        r"how\s+to\s+(?:restore|recover|decrypt)\s+(?:your\s+)?files\.(?:txt|html|hta)",
        r"restore[_ -]?my[_ -]?files\.(?:txt|html|hta)",
        r"readme[_ -]?(?:decrypt|restore|recover).*\.(?:txt|html|hta)",
    ),
    "strong_ransom_contact": (
        r"\.onion\b",
        r"tor\s+browser",
        r"@[a-z0-9._%+-]*(?:protonmail|proton|tutanota|mailfence)\.[a-z]+",
    ),
    "strong_recovery_destroy_cmd": (
        r"vssadmin(?:\.exe)?\s+(?:delete|resize)\s+shadows",
        r"wmic(?:\.exe)?\s+shadowcopy\s+(?:delete|delet)",
        r"bcdedit(?:\.exe)?.{0,80}recoveryenabled\s+(?:no|false)",
        r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)",
        r"delete\s+shadows\s*/all\s*/quiet",
    ),
    "strong_inhibit_service_list": (
        r"net\s+stop\s+(?:sql|mssql|veeam|backup|exchange)",
        r"taskkill(?:\.exe)?.{0,80}(?:sql|veeam|backup|exchange)",
    ),
    "strong_note_capability_symbol": (
        r"ANEvent(?:DropNote|GetNoteName|GetNoteText|PutToNote|IsOpenNote)",
    ),
    "strong_file_encryption_capability_symbol": (
        r"ANEvent(?:CryptFile|GetEncKey|GetEncryptExtensions(?:Full|Ignore)|GetPublicKey)",
    ),
    "strong_recovery_removal_capability_symbol": (
        r"ANEventRemoveBackups",
    ),
    "strong_target_discovery_capability_symbol": (
        r"ANEvent(?:DriveScan|GetPrimaryPaths|GetProcesses|GetServices)",
    ),
    "strong_anti_debug_capability_symbol": (
        r"ANEventIsInDebugger",
    ),
}

COMPILED_RULES = {
    rule_id: tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)
    for rule_id, patterns in RULE_PATTERNS.items()
}

CLAIM_TYPES = {
    "static_extortion_template_strong",
    "static_recovery_inhibition_command_strong",
    "static_service_disruption_command_strong",
    "static_ransom_note_name_strong",
}


@dataclass(frozen=True)
class StaticEvidenceItem:
    ref_id: str
    rule_id: str
    pattern: str
    value: str
    encoding: str
    source: str = "static_string"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ref_id": self.ref_id,
            "source": self.source,
            "rule_id": self.rule_id,
            "pattern": self.pattern,
            "encoding": self.encoding,
            "value": self.value,
        }


@dataclass(frozen=True)
class StaticClaim:
    claim_id: str
    agent_id: str
    claim_type: str
    statement: str
    confidence: str
    evidence_ref_ids: tuple[str, ...]
    supporting_rule_ids: tuple[str, ...]
    alternative_explanations: tuple[str, ...] = ()
    uncertainty: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "claim_id": self.claim_id,
            "agent_id": self.agent_id,
            "claim_type": self.claim_type,
            "statement": self.statement,
            "confidence": self.confidence,
            "evidence_ref_ids": list(self.evidence_ref_ids),
            "supporting_block_ids": [],
            "supporting_rule_ids": list(self.supporting_rule_ids),
            "alternative_explanations": list(self.alternative_explanations),
            "uncertainty": list(self.uncertainty),
            "status": "candidate",
        }
        return annotate_claim_semantics(payload)


@dataclass(frozen=True)
class StaticScanResult:
    sample_path: str
    sha256: str
    size_bytes: int
    string_count: int
    matched_items: tuple[StaticEvidenceItem, ...]
    claims: tuple[StaticClaim, ...]
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "harness-static-strong-scan-v1",
            "sample_path": self.sample_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "string_count": self.string_count,
            "matched_items": [item.to_dict() for item in self.matched_items],
            "claims": [claim.to_dict() for claim in self.claims],
            "diagnostics": self.diagnostics,
        }


def scan_static_strong_evidence(path: str | Path, max_strings: int = 80000) -> StaticScanResult:
    sample_path = Path(path)
    data = sample_path.read_bytes()
    strings = extract_strings(data, max_strings=max_strings)
    matched_items = match_static_rules(strings)
    claims = build_static_claims(matched_items)
    diagnostics = {
        "scanner": "deterministic-strong-static-v1",
        "retained_signal_policy": "strong-only",
        "excluded_signal_classes": [
            "generic crypto imports",
            "generic file/process imports",
            "packer or entropy-only indicators",
            "single weak keywords such as decrypt/readme",
        ],
        "rule_match_counts": rule_match_counts(matched_items),
    }
    return StaticScanResult(
        sample_path=str(sample_path),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        string_count=len(strings),
        matched_items=tuple(matched_items),
        claims=tuple(claims),
        diagnostics=diagnostics,
    )


def extract_strings(data: bytes, max_strings: int) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for match in ASCII_RE.finditer(data):
        values.append((match.group(0).decode("latin1", "ignore").strip(), "ascii"))
        if len(values) >= max_strings:
            break
    if len(values) < max_strings:
        for match in UTF16_RE.finditer(data):
            values.append((match.group(0).decode("utf-16le", "ignore").strip(), "utf-16le"))
            if len(values) >= max_strings:
                break
    deduped: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for value, encoding in values:
        if len(value) < 4:
            continue
        key = (value.casefold(), encoding)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((value, encoding))
    return deduped


def match_static_rules(strings: list[tuple[str, str]]) -> list[StaticEvidenceItem]:
    items: list[StaticEvidenceItem] = []
    sequence = 1
    for rule_id, patterns in COMPILED_RULES.items():
        for pattern in patterns:
            for value, encoding in strings:
                if not pattern.search(value):
                    continue
                items.append(StaticEvidenceItem(
                    ref_id=f"static:{sequence:06d}",
                    rule_id=rule_id,
                    pattern=pattern.pattern,
                    value=bounded_value(value),
                    encoding=encoding,
                ))
                sequence += 1
                break
    return items


def build_static_claims(items: list[StaticEvidenceItem]) -> list[StaticClaim]:
    by_rule: dict[str, list[StaticEvidenceItem]] = defaultdict(list)
    for item in items:
        by_rule[item.rule_id].append(item)
    claims: list[StaticClaim] = []
    add_extortion_claim(claims, by_rule)
    add_recovery_claim(claims, by_rule)
    add_service_claim(claims, by_rule)
    add_note_name_claim(claims, by_rule)
    add_capability_symbol_claim(claims, by_rule)
    return claims


def add_extortion_claim(claims: list[StaticClaim], by_rule: dict[str, list[StaticEvidenceItem]]) -> None:
    phrase = by_rule.get("strong_extortion_phrase", [])
    contacts = by_rule.get("strong_ransom_contact", [])
    note_names = by_rule.get("strong_ransom_note_name", [])
    if not phrase or not (contacts or note_names):
        return
    refs = refs_for(phrase + contacts + note_names)
    rules = rules_for(phrase + contacts + note_names)
    claims.append(StaticClaim(
        claim_id=f"static_claim_{len(claims) + 1:06d}",
        agent_id="static_strong",
        claim_type="static_extortion_template_strong",
        statement="static strings contain a ransomware extortion template with a contact or note-name indicator",
        confidence="high",
        evidence_ref_ids=tuple(refs),
        supporting_rule_ids=tuple(rules),
        alternative_explanations=("embedded documentation or test strings, if not linked to runtime behavior",),
        uncertainty=("static evidence does not prove that the template was written during this execution",),
    ))


def add_recovery_claim(claims: list[StaticClaim], by_rule: dict[str, list[StaticEvidenceItem]]) -> None:
    items = by_rule.get("strong_recovery_destroy_cmd", [])
    if not items:
        return
    claims.append(StaticClaim(
        claim_id=f"static_claim_{len(claims) + 1:06d}",
        agent_id="static_strong",
        claim_type="static_recovery_inhibition_command_strong",
        statement="static strings contain commands that delete or disable Windows recovery artifacts",
        confidence="high",
        evidence_ref_ids=tuple(refs_for(items)),
        supporting_rule_ids=tuple(rules_for(items)),
        alternative_explanations=("administrative recovery-maintenance tooling, if independently established",),
        uncertainty=("static evidence does not prove that the command executed in this trace",),
    ))


def add_service_claim(claims: list[StaticClaim], by_rule: dict[str, list[StaticEvidenceItem]]) -> None:
    items = by_rule.get("strong_inhibit_service_list", [])
    if not items:
        return
    claims.append(StaticClaim(
        claim_id=f"static_claim_{len(claims) + 1:06d}",
        agent_id="static_strong",
        claim_type="static_service_disruption_command_strong",
        statement="static strings contain commands that terminate database, backup, or enterprise services",
        confidence="high",
        evidence_ref_ids=tuple(refs_for(items)),
        supporting_rule_ids=tuple(rules_for(items)),
        alternative_explanations=("administrative maintenance scripts, if independently established",),
        uncertainty=("static evidence does not prove that the command executed in this trace",),
    ))


def add_note_name_claim(claims: list[StaticClaim], by_rule: dict[str, list[StaticEvidenceItem]]) -> None:
    items = by_rule.get("strong_ransom_note_name", [])
    if not items:
        return
    existing_refs = {ref for claim in claims for ref in claim.evidence_ref_ids}
    refs = [item for item in items if item.ref_id not in existing_refs]
    if not refs:
        return
    claims.append(StaticClaim(
        claim_id=f"static_claim_{len(claims) + 1:06d}",
        agent_id="static_strong",
        claim_type="static_ransom_note_name_strong",
        statement="static strings contain a strict ransom-note filename pattern",
        confidence="high",
        evidence_ref_ids=tuple(refs_for(refs)),
        supporting_rule_ids=tuple(rules_for(refs)),
        alternative_explanations=("embedded test fixture or documentation, if independently established",),
        uncertainty=("static evidence does not prove that the note file was created during this execution",),
    ))


def add_capability_symbol_claim(claims: list[StaticClaim], by_rule: dict[str, list[StaticEvidenceItem]]) -> None:
    groups = {
        "note": by_rule.get("strong_note_capability_symbol", []),
        "file_encryption": by_rule.get("strong_file_encryption_capability_symbol", []),
        "recovery_removal": by_rule.get("strong_recovery_removal_capability_symbol", []),
        "target_discovery": by_rule.get("strong_target_discovery_capability_symbol", []),
        "anti_debug": by_rule.get("strong_anti_debug_capability_symbol", []),
    }
    present_core = [name for name in ("note", "file_encryption", "recovery_removal", "target_discovery") if groups[name]]
    if not groups["note"] or not groups["file_encryption"] or len(present_core) < 3:
        return
    items = [item for name in ("note", "file_encryption", "recovery_removal", "target_discovery", "anti_debug") for item in groups[name]]
    claims.append(StaticClaim(
        claim_id=f"static_claim_{len(claims) + 1:06d}",
        agent_id="static_strong",
        claim_type="static_ransomware_capability_symbols_strong",
        statement="static symbols expose ransomware capabilities spanning note deployment, file encryption, recovery removal, and target discovery",
        confidence="high",
        evidence_ref_ids=tuple(refs_for(items)),
        supporting_rule_ids=tuple(rules_for(items)),
        alternative_explanations=("debug symbols or RTTI retained from a ransomware-capable binary",),
        uncertainty=("static symbols expose compiled capabilities; dynamic execution of each capability is not proven by static evidence alone",),
    ))


def refs_for(items: list[StaticEvidenceItem]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item.ref_id not in seen:
            seen.add(item.ref_id)
            out.append(item.ref_id)
    return out


def rules_for(items: list[StaticEvidenceItem]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item.rule_id not in seen:
            seen.add(item.rule_id)
            out.append(item.rule_id)
    return out


def rule_match_counts(items: list[StaticEvidenceItem]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in items:
        counts[item.rule_id] += 1
    return dict(sorted(counts.items()))


def bounded_value(value: str, limit: int = 260) -> str:
    text = " ".join(value.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def write_static_scan(path: Path, result: StaticScanResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

from __future__ import annotations

import unittest

from harness.behavior.classification import annotate_claim_semantics


class BehaviorClassificationTests(unittest.TestCase):
    def test_failed_muicache_non_persistence_registry_activity_is_dual_use(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000001",
            "agent_id": "registry",
            "claim_type": "registry_behavior",
            "statement": "sample attempted registry key creation under HKU\\.DEFAULT\\Software\\Classes\\Local Settings\\Muicache, but the observed result was ACCESS DENIED rather than a successful write.",
            "confidence": "medium",
            "evidence_ref_ids": ["event:738"],
            "alternative_explanations": ["non-persistence registry access that did not succeed"],
            "uncertainty": ["The observed targets are Muicache-related, not an autostart or persistence key."],
        })

        self.assertEqual(claim["behavior_class"], "dual_use")
        self.assertEqual(claim["dual_use_primitives"], ["ordinary_registry_interaction"])
        self.assertEqual(claim["risk_primitives"], [])

    def test_process_start_with_negated_vssadmin_match_is_dual_use(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000001",
            "agent_id": "process",
            "claim_type": "process_execution_behavior",
            "statement": "age-keygen.exe started successfully and no additional child process evidence was observed.",
            "confidence": "high",
            "evidence_ref_ids": ["event:0"],
            "uncertainty": ["`vssadmin` was not matched in the provided query path."],
        })

        self.assertEqual(claim["behavior_class"], "dual_use")
        self.assertEqual(claim["dual_use_primitives"], ["process_start_only"])

    def test_process_start_with_no_concrete_vssadmin_invocation_is_dual_use(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000005",
            "agent_id": "process",
            "claim_type": "process_execution_behavior",
            "statement": "The attributed process instance is `age.exe` with a successful process start at offset 0. The event records parent PID 4960, child PID 5028, command line `C:\\analyst\\age.exe`, and current directory `C:\\Windows\\system32`.",
            "confidence": "medium",
            "evidence_ref_ids": ["event:0"],
            "uncertainty": ["No concrete `cmd.exe` or `vssadmin` invocation was evidenced in the available queries."],
        })

        self.assertEqual(claim["behavior_class"], "dual_use")
        self.assertEqual(claim["dual_use_primitives"], ["process_start_only"])

    def test_local_startup_without_process_create_evidence_is_dual_use(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000006",
            "agent_id": "process",
            "claim_type": "process_execution_behavior",
            "statement": "The attributed process `age.exe` started successfully as PID 5028, then immediately created a thread, loaded its own image and `ntdll.dll`, and performed registry queries early in execution.",
            "confidence": "medium",
            "evidence_ref_ids": ["event:0", "event:1"],
            "uncertainty": ["No process-create events were returned by the operation_index=process create query."],
        })

        self.assertEqual(claim["behavior_class"], "dual_use")
        self.assertEqual(claim["dual_use_primitives"], ["process_start_only"])

    def test_denied_muicache_claim_with_rather_than_persistence_is_dual_use(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000003",
            "agent_id": "registry",
            "claim_type": "registry_behavior",
            "statement": "The attributed process attempted registry access under HKU\\.Default\\Software\\Classes\\Local Settings\\MUICache and both attempts were denied.",
            "confidence": "medium",
            "evidence_ref_ids": ["event:738"],
            "alternative_explanations": ["ordinary application configuration access"],
            "uncertainty": ["this target is consistent with UI cache or application metadata rather than persistence"],
        })

        self.assertEqual(claim["behavior_class"], "dual_use")
        self.assertEqual(claim["dual_use_primitives"], ["ordinary_registry_interaction"])

    def test_denied_autostart_registry_target_is_not_ordinary_registry(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000004",
            "agent_id": "registry",
            "claim_type": "registry_behavior",
            "statement": "The attributed process attempted a registry write under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and the access was denied.",
            "confidence": "medium",
            "evidence_ref_ids": ["event:740"],
        })

        self.assertNotEqual(claim["behavior_class"], "dual_use")
        self.assertNotIn("ordinary_registry_interaction", claim["dual_use_primitives"])

    def test_open_only_autostart_key_is_dual_use(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000007",
            "agent_id": "registry",
            "claim_type": "registry_behavior",
            "statement": "Sample-attributed registry activity opened the autostart key HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run using RegCreateKey.",
            "confidence": "high",
            "evidence_ref_ids": ["event:1188"],
            "alternative_explanations": ["installer autostart setup"],
            "uncertainty": [
                "The event is a RegCreateKey open, not a confirmed RegSetValue write or executable binding."
            ],
        })

        self.assertEqual(claim["behavior_class"], "dual_use")
        self.assertEqual(claim["dual_use_primitives"], ["ordinary_registry_interaction"])
        self.assertEqual(claim["risk_primitives"], [])

    def test_user_scope_extension_changing_transformation_is_malicious_only(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000010",
            "agent_id": "file_transformation",
            "claim_type": "file_transformation_behavior",
            "statement": "Same-process events show repeated SetRenameInformationFile operations with extension-changing renames across C:\\Users\\analyst\\Documents and follow-on file write activity.",
            "confidence": "high",
            "evidence_ref_ids": ["event:3077", "event:5275"],
        })

        self.assertEqual(claim["behavior_class"], "malicious_only")
        self.assertIn("dynamic_user_data_transformation_destructive", claim["risk_primitives"])
        self.assertEqual(claim["dual_use_primitives"], [])

    def test_ransom_note_text_without_a_verified_certificate_is_risk_relevant(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000011",
            "agent_id": "ransom_note",
            "claim_type": "ransom_note_deployment_behavior",
            "statement": "Sample-attributed events create and write ransom-note-like files named restore_my_files.txt across user directories and the public desktop.",
            "confidence": "high",
            "evidence_ref_ids": ["event:13604", "event:13633"],
        })

        self.assertEqual(claim["behavior_class"], "risk_relevant")
        self.assertEqual(claim["risk_primitives"], [])
        self.assertEqual(claim["dual_use_primitives"], [])


    def test_ransom_note_uncertainty_cannot_self_attest_recovery_inhibition(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000011b",
            "agent_id": "ransom_note",
            "claim_type": "ransom_note_deployment_behavior",
            "statement": "The attributed process created and wrote how_to_decrypt.hta.",
            "confidence": "high",
            "evidence_ref_ids": ["event:3530", "event:3531"],
            "supporting_rule_ids": ["deterministic_attributed_ransom_note_artifact"],
            "uncertainty": [
                "The trace does not establish file encryption or broader recovery inhibition."
            ],
        })

        self.assertEqual(claim["behavior_class"], "risk_relevant")
        self.assertEqual(claim["risk_primitives"], ["dynamic_ransom_note_artifact"])

    def test_recovery_uncertainty_without_a_command_is_not_malicious_only(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000011c",
            "agent_id": "recovery",
            "claim_type": "recovery_impact_behavior",
            "statement": "The attributed process performed a recovery-related registry query.",
            "confidence": "high",
            "evidence_ref_ids": ["event:42"],
            "uncertainty": ["This does not establish recovery inhibition."],
        })

        self.assertNotEqual(claim["behavior_class"], "malicious_only")
        self.assertEqual(claim["risk_primitives"], [])


    def test_declared_medium_confidence_transformation_does_not_bypass_policy(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000012",
            "agent_id": "file_transformation",
            "claim_type": "file_transformation_behavior",
            "statement": "Same-process activity wrote and deleted temporary DLL files under C:\\Users\\analyst\\AppData\\Local\\Temp during installer staging.",
            "confidence": "medium",
            "evidence_ref_ids": ["event:2132", "event:2404"],
            "risk_primitives": ["dynamic_user_data_transformation_destructive"],
            "alternative_explanations": ["installer staging"],
        })

        self.assertEqual(claim["behavior_class"], "risk_relevant")
        self.assertEqual(claim["risk_primitives"], [])

    def test_transient_user_temp_scope_is_not_destructive_user_data_scope(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000013",
            "agent_id": "file_transformation",
            "claim_type": "file_transformation_behavior",
            "statement": "Same-process events show repeated delete and write operations under C:\\Users\\analyst\\AppData\\Local\\Temp for installer DLL staging.",
            "confidence": "high",
            "evidence_ref_ids": ["event:2132", "event:2404"],
            "risk_primitives": ["dynamic_user_data_transformation_destructive"],
            "alternative_explanations": ["installer staging"],
        })

        self.assertNotEqual(claim["behavior_class"], "malicious_only")
        self.assertEqual(claim["risk_primitives"], [])

    def test_system_or_application_file_discovery_is_dual_use(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000014",
            "agent_id": "file_discovery",
            "claim_type": "file_discovery_behavior",
            "statement": "The attributed process issued repeated file metadata queries over Windows paths and the controlled sample-local path, without direct user or shared-data targets.",
            "confidence": "medium",
            "evidence_ref_ids": ["block:phase_000011", "block:phase_000015"],
            "alternative_explanations": ["installer or loader compatibility probing"],
        })

        self.assertEqual(claim["behavior_class"], "dual_use")
        self.assertEqual(claim["dual_use_primitives"], ["system_application_file_discovery"])
        self.assertEqual(claim["risk_primitives"], [])

    def test_system_or_application_file_discovery_rejects_user_scope(self):
        claim = annotate_claim_semantics({
            "claim_id": "claim_000015",
            "agent_id": "file_discovery",
            "claim_type": "file_discovery_behavior",
            "statement": "The attributed process issued repeated file metadata queries over Windows paths and C:\\Users\\analyst\\Documents.",
            "confidence": "medium",
            "evidence_ref_ids": ["block:phase_000016"],
        })

        self.assertNotEqual(claim["behavior_class"], "dual_use")
        self.assertNotIn("system_application_file_discovery", claim["dual_use_primitives"])

if __name__ == "__main__":
    unittest.main()

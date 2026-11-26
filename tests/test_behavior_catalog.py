from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.behavior.catalog import build_behavior_catalog


class BehaviorCatalogTests(unittest.TestCase):
    def test_builds_bounded_indexes_checkpoints_and_process_local_phases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace.jsonl"
            self.write_trace(trace, [
                self.event(0, 1.0, "WriteFile", "file", "file_write", r"C:\\Users\\alice\\Documents\\a.txt", "txt", 10),
                self.event(1, 1.1, "WriteFile", "file", "file_write", r"C:\\Users\\alice\\Documents\\b.txt", "txt", 10),
                self.event(2, 1.2, "Process Create", "process", "process_start", "", "", 10, "Command line: cmd.exe /c whoami"),
                self.event(3, 1.3, "RegSetValue", "registry", "registry_write", r"HKCU\\Software\\Demo", "", 20),
            ])

            catalog = build_behavior_catalog(
                trace_path=trace,
                phase_blocks_path=root / "phase_blocks.jsonl",
                checkpoints_path=root / "trace_checkpoints.json",
                checkpoint_stride=2,
                representative_limit=4,
                phase_event_cap=8,
            )

            self.assertEqual(catalog["event_count"], 4)
            self.assertEqual(catalog["phase_blocks"]["event_count"], 4)
            self.assertEqual(catalog["integrity"]["status"], "pass")
            self.assertEqual(catalog["checkpoints"]["count"], 2)
            family_entries = catalog["indexes"]["operation_family_index"]["entries"]
            by_key = {row["key"]: row for row in family_entries}
            self.assertEqual(by_key["file_write"]["event_count"], 2)
            self.assertIn("process_start", by_key)
            blocks = self.read_jsonl(root / "phase_blocks.jsonl")
            self.assertEqual(sum(int(block["event_count"]) for block in blocks), 4)
            file_block = next(block for block in blocks if block["behavior_kind"] == "file_transformation")
            self.assertEqual(file_block["target_scope"], "file:users")
            self.assertEqual(file_block["process_instance"]["pid"], 10)
            self.assertEqual(file_block["event_count"], 2)
            checkpoints = json.loads((root / "trace_checkpoints.json").read_text(encoding="utf-8"))
            self.assertEqual(checkpoints["event_count"], 4)
            self.assertEqual(checkpoints["checkpoints"][0][0], 0)
            self.assertEqual(checkpoints["checkpoints"][1][0], 2)

    def test_rejects_non_contiguous_trace_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace.jsonl"
            self.write_trace(trace, [
                self.event(0, 1.0, "WriteFile", "file", "file_write", r"C:\\Users\\alice\\Documents\\a.txt", "txt", 10),
                self.event(2, 1.1, "WriteFile", "file", "file_write", r"C:\\Users\\alice\\Documents\\b.txt", "txt", 10),
            ])
            with self.assertRaisesRegex(ValueError, "not contiguous"):
                build_behavior_catalog(
                    trace_path=trace,
                    phase_blocks_path=root / "phase_blocks.jsonl",
                    checkpoints_path=root / "trace_checkpoints.json",
                )

    @staticmethod
    def event(
        offset: int,
        timestamp: float,
        operation: str,
        category: str,
        family: str,
        path: str,
        extension: str,
        pid: int,
        detail: str = "",
    ) -> dict[str, object]:
        return {
            "order": {"filtered": offset, "source": f"ev_{offset:06d}", "source_numeric": offset},
            "time": {"timestamp": timestamp, "raw_time": str(timestamp)},
            "action": {"operation": operation, "category": category, "result": "SUCCESS", "operation_family": family},
            "target": {"path": path, "normalized_path": path.casefold(), "namespace": "users" if "Users" in path else ("registry" if category == "registry" else "empty"), "extension": extension},
            "detail": {"raw_detail": detail, "parsed": {"command_line": "cmd.exe /c whoami"} if detail else {}},
            "process_context": {"pid": pid, "process_name": "sample.exe", "node_id": f"node_{pid}", "depth": 0, "process_key": f"node_{pid}|{pid}|sample.exe"},
        }

    @staticmethod
    def write_trace(path: Path, rows: list[dict[str, object]]) -> None:
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

    @staticmethod
    def read_jsonl(path: Path) -> list[dict[str, object]]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


if __name__ == "__main__":
    unittest.main()

"""Local query telemetry kept outside evidence and model-visible context."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Any, Callable
from uuid import uuid4


class ToolQueryTiming:
    def __init__(self, directory: Path, *, sample_id: str, task_id: str, agent_id: str) -> None:
        self.directory = Path(directory)
        self.events_path = self.directory / "tool_timing.jsonl"
        self.summary_path = self.directory / "tool_timing_summary.json"
        self.identity = {
            "schema_version": "harness-tool-timing-v1",
            "sample_id": sample_id,
            "task_id": task_id,
            "agent_id": agent_id,
            "run_id": uuid4().hex,
        }
        self.records: list[dict[str, Any]] = []
        self.recording_errors = 0
        self._sequence = 0

    def invoke(self, tool_name: str, query: dict[str, Any], call: Callable[[], Any]) -> Any:
        self._sequence += 1
        record = {
            "sequence": self._sequence,
            "tool_name": tool_name,
            "query": {key: value for key, value in query.items() if key != "ledger"},
            "started_at": self._utc_now(),
        }
        self._append({**record, "status": "started"})
        result = None
        status, error_type = "success", None
        # Exclude telemetry serialization and disk I/O from query execution time.
        started = time.perf_counter_ns()
        try:
            result = call()
            return result
        except BaseException as exc:
            status, error_type = "error", type(exc).__name__
            raise
        finally:
            duration = max(0, time.perf_counter_ns() - started) / 1_000_000_000
            completed = {
                **record,
                "finished_at": self._utc_now(),
                "duration_seconds": duration,
                "status": status,
                "error_type": error_type,
                "matched_count": getattr(result, "matched_count", None),
                "returned_count": getattr(result, "returned_count", None),
            }
            self.records.append(completed)
            self._append(completed)

    def finish(self, *, runner_status: str) -> None:
        by_tool: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in self.records:
            by_tool[record["tool_name"]].append(record)
        summary = {
            **self.identity,
            "recorded_at": self._utc_now(),
            "runner_status": runner_status,
            "measurement_scope": "task tool dispatch, including validation; excluding telemetry I/O",
            "clock": "perf_counter_ns",
            "recording_errors": self.recording_errors,
            "events_complete": self.recording_errors == 0,
            **self._aggregate(self.records),
            "by_tool": {name: self._aggregate(records) for name, records in sorted(by_tool.items())},
        }
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            temporary = self.summary_path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            temporary.replace(self.summary_path)
        except Exception as exc:
            self._record_failure(exc)

    @staticmethod
    def _aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
        durations = [record["duration_seconds"] for record in records]
        total = sum(durations)
        return {
            "call_count": len(records),
            "success_count": sum(record["status"] == "success" for record in records),
            "error_count": sum(record["status"] == "error" for record in records),
            "duration_seconds_sum": total,
            "duration_seconds_mean": total / len(durations) if durations else None,
            "duration_seconds_max": max(durations) if durations else None,
        }

    def _append(self, record: dict[str, Any]) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            with self.events_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({**self.identity, **record}, ensure_ascii=False) + "\n")
        except Exception as exc:
            self._record_failure(exc)

    def _record_failure(self, exc: Exception) -> None:
        self.recording_errors += 1
        if self.recording_errors == 1:
            # An observability failure must not replace a tool result/exception.
            try:
                logging.getLogger(__name__).warning("Tool timing could not be saved (%s)", type(exc).__name__)
            except Exception:
                pass

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

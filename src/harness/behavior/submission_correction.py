"""Bounded correction of an investigation submission using its existing observations."""
from __future__ import annotations

import json
from dataclasses import replace

from .llm_loop import no_evidence_completion
from .llm_protocol import compact_response
from .reasoning_v2 import CompatibleReasoningRunner


class SubmissionCorrectionRunner(CompatibleReasoningRunner):
    def run(self, *args, **kwargs):
        result = super().run(*args, **kwargs)
        if result.status == "invalid_response" and self.config.max_submission_corrections:
            return self.correct_submission(result)
        return result

    def correct_submission(self, result):
        """Reuse only the saved observations, preserving the original rejected output."""
        if (result.status != "invalid_response" or not self.config.max_submission_corrections
                or result.diagnostics.get("submission_correction")):
            return result
        diagnostics = dict(result.diagnostics)
        original = result.model_responses[-1] if result.model_responses else {}
        action = self.parse_response(original)
        allowed = [action.kind] if action.kind in {"claim_output", "no_evidence"} else ["claim_output", "no_evidence"]
        if isinstance(original, dict) and action.kind == "invalid":
            # A malformed claims list still expresses a finding submission.
            # Format repair must not turn that finding into a negative result.
            if any(key in original for key in ("claim_output", "claims", "claim_type")) or any(
                    original.get(key) == "claim_output" for key in ("type", "kind")):
                allowed = ["claim_output"]
            elif "no_evidence" in original or "checked_fact_ids" in original:
                allowed = ["no_evidence"]
        correction = {"limit": 1, "attempts": 1, "additional_tool_calls": 0,
                      "original_response_index": len(result.model_responses) - 1,
                      "original_error": diagnostics.get("error", "Invalid investigation submission"),
                      "investigation_responses": len(result.model_responses)}
        diagnostics["submission_correction"] = correction
        context = replace(result.context, available_tools=(),
                          output_schema={key: value for key, value in result.context.output_schema.items()
                                         if key != "tool_request"})
        context = replace(context, output_schema={**context.output_schema, "one_of": allowed})
        messages = list(self.messages_for_context(context))
        payload = json.loads(messages[-1]["content"])
        payload["available_tools"] = []
        payload["output_schema"] = context.output_schema
        payload["terminal_response_required"] = True
        payload["submission_correction"] = {**correction, "rejected_response": original}
        payload["instruction"] = (
            "Correct the rejected submission using only the observations already visible here. "
            "This is one submission-correction attempt, outside the investigation budget. "
            "Do not request tools or invent operations, observations, or references. "
            "Preserve relevant observed findings; narrow unsupported statements and clarify limitations. "
            "evidence_ref_ids accepts only returned event:* and block:* references. "
            "supporting_block_ids accepts only returned block identifiers, exactly as supplied. "
            "fact_* identifies a query result, not an event or block: use visible fact IDs in "
            "no_evidence.checked_fact_ids, or in investigation_closure.leads[].supporting_fact_ids. "
            "For a claim, describe negative-query scope and limitations in uncertainty, without placing "
            "query-fact IDs into evidence_ref_ids. An empty-result query is not an extra positive claim: "
            "retain that negative-query scope in uncertainty rather than submitting a claim with empty references. "
            "Never discard a relevant finding merely to return no_evidence. "
            "Return exactly one permitted terminal response: " + ", ".join(allowed) + "."
        )
        if self.config.require_investigation_closure:
            payload["instruction"] += (
                " Include investigation_closure beside the action envelope. Tools are unavailable: "
                "retain unresolved leads and their concrete next steps rather than claiming new investigation. "
                "Include EVERY supplied lead_id exactly once, not a representative subset. Use only the "
                "fact_* IDs listed in investigation_fact_ids for supporting_fact_ids; never event or block IDs."
            )
        if self.config.strict_json_schema:
            from harness.structured_output import agent_schema
            payload = agent_schema(payload,self.registry)
            self._last_strict_output_schema = payload['output_schema']
        messages[-1] = {"role": "user", "content": json.dumps(payload, sort_keys=True)}
        correction["request"] = payload
        responses = list(result.model_responses)
        try:
            complete = getattr(self.client, "complete_json_once", self.client.complete_json)
            response = complete(tuple(messages))
            responses.append(compact_response(response))
        except Exception as exc:
            raw = getattr(exc, "raw_response_content", None)
            correction.update(status="response_parse_failed" if raw is not None else "request_failed",
                              error_type=type(exc).__name__, error=str(exc))
            if raw is not None:
                correction["raw_response_content"] = raw
            diagnostics["error"] = "Submission correction request failed"
            return replace(result, status="submission_correction_error", context=context,
                           model_responses=tuple(responses), diagnostics=diagnostics)
        action = self.parse_response(response)
        try:
            if action.kind not in allowed:
                raise ValueError("Submission correction must return an allowed terminal response; tools are disabled")
            closing_error = self.terminal_submission_error(action, result.memory, context.loop_state, correction=True)
            if closing_error:
                raise ValueError(closing_error)
            if action.kind == "claim_output":
                self.record_claim_outputs(result.agent_id, result.claim_ledger, action.claims, result.memory)
                status = "completed"
            else:
                diagnostics["completion"] = no_evidence_completion(action, result.memory)
                status = "completed_no_evidence"
        except ValueError as exc:
            correction.update(status="rejected", error=str(exc))
            diagnostics["error"] = str(exc)
            return replace(result, context=context, model_responses=tuple(responses), diagnostics=diagnostics)
        correction["status"] = "accepted"
        diagnostics.pop("error", None)
        return replace(result, status=status, context=context,
                       model_responses=tuple(responses), diagnostics=diagnostics)

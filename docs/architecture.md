# Analysis workflow

1. **Validate inputs.** Read the sample's CSV header and process tree; check normalized event offsets and process/node correspondence.
2. **Prepare evidence.** Build a bounded event catalog, process-local phase fragments and byte checkpoints from normalized events. Preserve source event identifiers for traceability.
3. **Investigate behavior.** Seven agents investigate file discovery, file transformation, ransom-note deployment, registry activity, process execution, recovery inhibition and anti-analysis behavior. Read-only tools retrieve events, fragments, target activity and process timelines.
4. **Combine findings.** Joint reasoning compares the agents' cited findings, shared observations, investigation gaps and alternative explanations.
5. **Verify and decide.** Reference checks validate citation ownership and structure. Independent semantic review examines the interpretation. Final adjudication resolves the review issues and returns a malicious or benign label, or an explicit execution failure.

Each investigator has a budget of six model rounds and ten tool calls, including initial queries. Its context retains twelve recent query records. Event and fragment references use E identifiers, findings use C identifiers, and query records use Q identifiers in model requests.

The catalog-backed runtime stores one phase-fragment level. Its `micro` and `macro` tool selectors are compatibility aliases for those same fragments; they do not construct separate fragment sets. Full fragment expansion reconstructs membership from process, behavior kind, target scope and event-order bounds.

Optional static analysis reads only the file selected with `--static-sample`. Extracted ransom-related content is supplied after semantic review, at final adjudication. It is interpreted alongside dynamic evidence.

The public interface is implemented in `src/ransift/`. Event processing, evidence tools, prompts, task execution and verification are implemented in `src/harness/`. Packaged configuration resources provide the default prompts, budgets and output layout.

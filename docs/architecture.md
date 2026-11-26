# Analysis workflow

1. **Validate inputs.** Read the sample's CSV header and process tree; check normalized event offsets and process/node correspondence.
2. **Prepare evidence.** Build a bounded event catalog, two levels of process-local fragments and byte checkpoints from normalized events. Preserve source event identifiers for traceability.
3. **Investigate behavior.** Seven agents investigate file discovery, file transformation, ransom-note deployment, registry activity, process execution, recovery inhibition and anti-analysis behavior. Read-only tools retrieve events, fragments, target activity and process timelines.
4. **Combine findings.** Joint reasoning compares the agents' cited findings, shared observations, investigation gaps and alternative explanations.
5. **Verify and decide.** Reference checks validate citation ownership and structure. Independent semantic review examines the interpretation. Final adjudication resolves the review issues and returns a malicious or benign label, or an explicit execution failure.

Each investigator has a budget of six model rounds and ten tool calls, including initial queries. Its context retains twelve recent query records. Event and fragment references use E identifiers, findings use C identifiers, and query records use Q identifiers in model requests.

Micro fragments connect compatible operations by the same process on the same target, with adjacent time gaps of at most 2 seconds and event-order gaps of at most 25. Macro fragments combine consecutive micro fragments by the same process when behavior kind, category and target scope agree, with time gaps of at most 10 seconds and order gaps of at most 250. File scopes use parent directory and extension. Both levels are split at a maximum of 2,048 events per fragment; this does not discard events.

The levels are stored separately in `micro_fragments.jsonl` and `macro_fragments.jsonl`. Each micro records its macro parent, and each macro records its micro children. Both preserve exact source event offsets or offset ranges. Existing tools accept `level="micro"` and `level="macro"` and return the corresponding level; expansion follows exact membership rather than every event between a fragment's endpoints. A shared query interface does not make the two fragment sets identical.

The reader still accepts older phase-only catalogs, where both selectors refer to the same phase fragments. New analyses build the hierarchy. The retained `phase_blocks.jsonl` is a compatibility artifact and does not define either new level.

Optional static analysis reads only the file selected with `--static-sample`. Extracted ransom-related content is supplied after semantic review, at final adjudication. It is interpreted alongside dynamic evidence.

The public interface is implemented in `src/ransift/`. Event processing, evidence tools, prompts, task execution and verification are implemented in `src/harness/`. Packaged configuration resources provide the default prompts, budgets and output layout.

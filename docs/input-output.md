# Input and output formats

## Input directory

| File | Format |
| --- | --- |
| `raw_events.csv` | Procmon CSV with columns `Time of Day`, `Process Name`, `PID`, `Operation`, `Path`, `Result`, `Detail` |
| `normalized_events.jsonl` | One event per line with `order`, `time`, `action`, `target`, `detail`, `process_context` objects |
| `process_tree.json` | JSON object containing `root_nodes` and `node_index`; nodes contain process identities |

Normalized `order.filtered` offsets are integers starting at zero and are contiguous. Timestamps must be finite numbers and operations must have nonempty names. Each event requires a nonnegative integer PID and a node ID matching the supplied tree. Tree roots may be node IDs or nested node objects with a `node_id`; each root must occur in `node_index`. Inputs must be consistently de-identified and must remain unchanged during analysis. Directory and file symlinks are rejected.

`validate` checks the CSV header, tree structure and first event. `validate --full` checks every normalized event. Validation does not compare every normalized event against the raw CSV body.

The program uses the supplied normalized stream and process tree without recomputing attribution. It reads only these three files and, when explicitly requested, one local static input. Labels and dataset-wide metadata are not required.

## Output directory

Use a new directory outside the sample directory. An ancestor of the sample directory is also rejected. Input logs are referenced rather than copied; keep them available when inspecting detailed task artifacts.

| Path | Contents |
| --- | --- |
| `input.json` | Sample identifier, input hashes, validation scope and static-input status |
| `prepared/` | Catalog, phase fragments, byte checkpoints, trace summary and configuration |
| `api-calls.jsonl` | Request phase, agent ID, elapsed time, success/error status and returned token usage |
| `outputs/<sample-id>/` | Task state, investigator outputs, reference mappings, model exchanges, reasoning and final decision |
| `result.json` | Overall status, label, timing and usage totals |

The sample identifier is derived from the normalized log's SHA-256. Output records do not contain API keys or authentication headers. Local task artifacts contain evidence and file paths and should be reviewed before sharing.

## Status and exit codes

| Result | Meaning | CLI exit code |
| --- | --- | ---: |
| `prepared` | Local evidence construction completed without model calls | 0 |
| `completed` | Final adjudication produced a validated malicious/benign label | 0 |
| `failed` | Analysis ended without a valid final label | 1 |
| Input/configuration/preparation error | The requested operation could not proceed | 2 |

Failures retain a null label. Partial output is retained for inspection; use a new output directory for another attempt.

## Timing and token accounting

Preparation time covers hashing and evidence construction after full validation. Analysis time covers investigation and downstream tasks. Token totals sum returned prompt/completion usage; missing usage is reported separately. Failed requests without usage have unknown token cost.

## Optional static input

`--static-sample` selects one regular local file for content extraction. The program does not download, search for or execute it. Static input is not accepted in preparation-only mode.

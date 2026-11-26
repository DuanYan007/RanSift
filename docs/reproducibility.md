# Reproducing an analysis

## Offline check

After installation, validate and prepare the synthetic example:

```sh
ransift validate --sample-dir examples/synthetic-sample --full
ransift analyze --sample-dir examples/synthetic-sample --output prepared-example --prepare-only
```

These commands require no API credential or model request. The example illustrates the input format; it is not an evaluation sample.

## Model-backed analysis

Supply the three input files described in [Input and output formats](input-output.md), an explicit API configuration and a credential environment variable. The endpoint must support the selected model and strict JSON Schema responses. Credentials and model access are supplied by the user.

Record the source commit, Python and package versions, model ID, API configuration without its credential, input hashes and output artifacts for each analysis. A model ID may refer to a service updated by its provider; identical requests need not produce identical decisions.

`result.json` records the returned label, timing and token totals. `api-calls.jsonl` records per-request status, duration and reported usage. Detailed investigator and decision artifacts remain in the output directory. Failed analyses have no label.

The source package contains the analysis runtime, default prompts, tools, verification and synthetic tests. Evaluation datasets, experiment orchestration and baseline implementations are distributed separately from this package. No executable samples are included.

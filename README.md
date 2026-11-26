# RanSift

RanSift investigates ransomware-related behavior from Windows execution logs using seven specialized agents, joint reasoning and evidence verification.

## Installation

Requires Python 3.11 or later.

```sh
python -m pip install .
```

Optional PE-resource extraction:

```sh
python -m pip install '.[static]'
```

Decoding encrypted CFGS resources also requires OpenSSL.

## Input

Provide one sample directory containing:

```text
<sample>/
├── raw_events.csv
├── normalized_events.jsonl
└── process_tree.json
```

[Input and output formats](docs/input-output.md).

## Configuration

Copy `configs/llm.example.json` to `llm.local.json`. Set the model ID, API base URL and credential environment-variable name. Set the API key in that environment variable. The client uses strict JSON Schema responses.

## Usage

Validate the input structure:

```sh
ransift validate --sample-dir ./sample
ransift validate --sample-dir ./sample --full
```

Build the evidence catalog without model calls:

```sh
ransift analyze --sample-dir ./sample --output ./prepared-run --prepare-only
```

Run the complete analysis:

```sh
ransift analyze --sample-dir ./sample --output ./analysis-run --config ./llm.local.json
```

Analysis sends retrieved evidence and investigation context to the configured API. Inputs remain read-only; output must be a new, separate directory.

To include static content from an explicitly supplied local file:

```sh
ransift analyze --sample-dir ./sample --output ./analysis-run --config ./llm.local.json --static-sample ./local-binary
```

Static content enters final adjudication. Without that argument, analysis uses log evidence only. Submitted files are never executed.

## Results

- `result.json`: final label or failure, elapsed time, request counts and token usage.
- `api-calls.jsonl`: request phase, investigator, elapsed time, status and returned usage.
- `prepared/`: evidence catalog, phase fragments, checkpoints and configuration.
- `outputs/<sample-id>/`: investigator findings, evidence references, reasoning, review and final decision.

Detailed outputs contain submitted evidence and local file references. Keep them private unless reviewed for sharing.

## Tests

```sh
python -m unittest discover -s tests
```

Tests use synthetic events and a local model stub. A three-file example is provided in `examples/synthetic-sample/`.

[Analysis workflow](docs/architecture.md).

[Reproducing an analysis](docs/reproducibility.md).

## License

This source code is licensed under the [Apache License 2.0](LICENSE). Separately distributed datasets are governed by their own licenses.

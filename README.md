# Ghost Data Still Exists auditor

A Python audit agent for HackerRank's Orchestrate October 2026 challenge. It reconstructs audit-time identity, inventories relevant records and copies, applies supplied deletion and retention rules, detects active recreation paths, and emits the required ordered CSV only when every request is supported by evidence.

## Current run status

The latest strict run processed all 518 requests: 200 resolved and 318 unresolved. The agent withheld `output.csv` because required policy facts or timely state evidence were missing. The 32-request sample diagnostic resolved 11 requests and left 21 unresolved, so sample accuracy is reported as not measured. No labels are guessed to force a submission file.

## Requirements and setup

- Python 3.10 or later
- Local [Ollama](https://ollama.com/) with `qwen2.5:0.5b`
- `pypdf`; install dependencies with `python -m pip install -r code/requirements.txt`
- Tesseract OCR is optional for image evidence

Download the participant-facing `dataset/` files from the [official challenge repository](https://github.com/interviewstreet/hackerrank-orchestrate-october26) and put `dataset/` beside `code/`. The private corpus and expected outputs are intentionally excluded from this public repository. Run the model locally with `ollama pull qwen2.5:0.5b`; no cloud API key is needed.

From the repository root:

```bash
python code/main.py
```

The default command reads the full request CSV and writes `output.csv` only if every audit resolves and validates. Otherwise it writes a diagnostic summary under `artifacts/` and exits nonzero. `python code/main.py --max-cases 8` runs a diagnostic subset and never writes a partial prediction file.

## Design

- Manifest and embedded timestamps gate evidence against each request's `audit_at`.
- Historical identifiers are resolved from supplied identity history with ambiguous ownership kept unresolved.
- CSV, JSON, logs, SQL snapshots, PDFs, text and optional OCR are read as evidence; primary and replica scopes remain independent.
- Deterministic code owns policy, obligations, status and step order. The local model interprets request intent and may suggest a source-grounded narrative state; quotes must match the source and pass state-specific positive assertion checks.
- A successful command, cache miss, catalog mention or empty unscoped search is not proof of deletion.

See [code/README.md](code/README.md) for detailed architecture, diagnostics, and evaluation commands.

## Verification and packaging

```bash
python -m pytest code/tests -q
python scripts/package.py
```

The suite currently passes 81 tests and 34 subtests. The package script builds `code.zip` from `code/`, requires the evaluation and usage reports, and excludes environment files, credentials, caches, build output and nested archives. The generated reports are included in `code/evaluation/`.

This repository contains implementation and diagnostics only; it does not include a contest submission or claim a successful score.

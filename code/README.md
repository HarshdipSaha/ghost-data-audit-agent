# Ghost Data Still Exists auditor

Python implementation for the HackerRank Orchestrate October 2026 challenge. It reads the supplied `dataset/`, uses a local Ollama model for request meaning and bounded narrative evidence interpretation, applies the provided rules in deterministic code, and writes the exact required `output.csv` schema.

The competition corpus is intentionally not included in this repository. Download the participant-facing files from the [official starter repository](https://github.com/interviewstreet/hackerrank-orchestrate-october26) and place its `dataset/` directory beside `code/`. Keep the corpus and its sample reference out of commits and prediction code paths.

## Requirements

- Python 3.10 or later
- Ollama running locally with `qwen2.5:0.5b` available
- Tesseract OCR for screenshot evidence (optional when OCR is unavailable; affected evidence is recorded as an ingestion gap)
- Install Python dependency: `python -m pip install -r code/requirements.txt`
- Fetch the local model once: `ollama pull qwen2.5:0.5b`

The model runs on loopback at `http://127.0.0.1:11434`; no API key or paid cloud model is required. A local alternative can be selected with `GHOST_AUDIT_MODEL`, but cloud tags are rejected. `OLLAMA_HOST` must remain a loopback address. Exact request batches and semantic evidence reads are cached under ignored `code/.cache/semantic/`.

## Run

From the repository root:

```bash
python code/main.py
```

The command reads all rows from `dataset/deletion_requests.csv`, uses all CSV and manifested evidence files, and writes root `output.csv` only after every case has a resolvable, validated decision. It writes a diagnostic `artifacts/run_summary.json`; this file can contain case-specific internal details and is ignored by Git. The latest full run resolved **518/518** and wrote the required CSV (356 INCOMPLETE, 152 COMPLETE, 10 NOT_APPLICABLE). Full-set hidden-label accuracy is unknown.

For an early limited diagnostic run, `python code/main.py --max-cases 8` processes only the first eight cases, never writes a partial output, and returns summary counts. The CLI exits nonzero and leaves `output.csv` untouched when any required audit fact remains unresolved; it will not invent a status.

To run the public reference requests independently, use `python code/main.py --requests dataset/sample_deletion_requests.csv --output artifacts/sample_predictions.csv --summary artifacts/sample_run_summary.json`. Alternate request files do not overwrite the full-set `output.csv` by default.

For diagnostic evaluation when some sample requests are unresolved, add `--diagnostic-predictions artifacts/sample_resolved_diagnostic.csv`. This writes only resolved rows to a separate path; it never becomes a complete submission CSV. Diagnostic predictions cannot overwrite root `output.csv` or the requested complete output path.

After extracting `code.zip`, run the extracted entry point with explicit paths, for example `python main.py --dataset ../dataset --output ../output.csv --summary ../artifacts/run_summary.json` from the extracted code folder. Install dependencies there with `python -m pip install -r requirements.txt`.

## Architecture

1. `ghost_audit.ingest.Store` reads CSV tables, captures manifest availability, extracts JSON/log/SQL/text/PDF and local OCR observations, tracks physical SQL replica scopes, and records parse issues. SQL runs in an in-memory database with attached database and loadable-extension operations denied.
2. `ghost_audit.identity.IdentityResolver` reconstructs cutoff-time identifiers from the identity change ledger and fails closed on ambiguous ownership.
3. `ghost_audit.ai.LocalSemanticAgent` classifies multilingual request meaning and may interpret up to three grounded document reads per case. Returned evidence claims need a source quote and candidate resource. It cannot choose policy, status, or output steps.
4. `ghost_audit.engine.Auditor` constructs policy obligations, detects remaining data and active recreation paths, keeps primary and replica states separate, and returns an explicit unresolved diagnostic when required proof is missing.
5. `ghost_audit.contract` checks the official operation order and exact CSV schema before writing.

Evidence must be available by `audit_at` and describe a state no later than that cutoff. A successful delete command is not proof of absence. A cache miss, absent search snippet, filename match, or unscoped empty list is not absence evidence. Primary absence does not erase a dirty replica.

An authorized deletion request supplies baseline deletion for ordinary records. Policy treatments preserve present security records unless supplied expiry evidence establishes otherwise, redact conversations unless they are explicitly private/nonshared, and block observed restore access while retaining the archive. Unknown retention/context metadata does not authorize destroying retained data. Tombstone preservation can be established by another required retained record referencing the same stable subject. Shared attachments are redacted unless exclusive ownership is established. Contradictory facts and ambiguous identity remain unresolved. Explicitly non-attributable analytics records with no concrete subject identifiers create no deletion obligation. These conventions are documented in the evaluation report and AI-DLC effort.

## Evaluation

Run unit and adversarial fixtures:

```bash
python -m pytest code/tests -q
```

Generate sample-request predictions first, then score them against the public sample answers in a separate evaluation process:

```bash
python code/main.py --requests dataset/sample_deletion_requests.csv --output artifacts/sample_predictions.csv --summary artifacts/sample_run_summary.json
python code/evaluation/main.py artifacts/sample_predictions.csv dataset/sample_output.csv --report code/evaluation/evaluation_report.md
python code/evaluation/usage.py artifacts/run_summary.json --report code/evaluation/usage_report.md
```

The prediction modules do not read `sample_output.csv`. The evaluator reports status, sequence, step-field and resource recall measures. Team-authored fixtures cover temporal evidence, physical replicas, recycled identifiers, trace readbacks and evaluator completeness. If a run has unresolved cases, render an honest blocked report from its summary rather than scoring a partial output:

```bash
python code/evaluation/main.py --diagnostic-summary artifacts/full_run_summary.json --sample-summary artifacts/sample_run_summary.json --report code/evaluation/evaluation_report.md
```

Reports must be regenerated from the final run. The package script requires both reports and excludes nested archives and build output.

The current sample diagnostic resolves 28/32 cases. Measure all 32 with explicit abstentions using:

```bash
python code/main.py --requests dataset/sample_deletion_requests.csv --summary artifacts/sample_run_summary.json --diagnostic-predictions artifacts/sample_resolved_diagnostic.csv
python code/evaluation/main.py artifacts/sample_resolved_diagnostic.csv dataset/sample_output.csv --allow-missing --run-summary artifacts/full_run_summary.json --report code/evaluation/evaluation_report.md
```

Current results: **87.50%** status accuracy across all 32 (unresolved cases count incorrect), **100%** status accuracy among the 28 resolved cases, **18.75%** exact sequence accuracy, **56.99%** step accuracy, **68.82%** field accuracy, and **66.67%** resource recall. Four samples remain unresolved because independent resource links or state proof are missing; remaining sequence mismatches are documented. These are development sample results, not hidden-test scores. The suite passes 99 tests and 40 subtests; install `pytest` and `pytest-subtests` to run it.

## Artifacts

- `output.csv`: required 518-row submission file when all obligations resolve.
- `code.zip`: created from the runnable `code/` tree with `python scripts/package.py`; excludes datasets, model weights, local caches and environments.
- `code/evaluation/evaluation_report.md`: measured sample metrics, or explicit `Not measured` values when a complete prediction is unavailable, plus custom cases and known blockers.
- `code/evaluation/usage_report.md`: model, provider, calls, token totals, average and cost from the final full run.
- `log.txt`: development conversation log, submitted separately as required by HackerRank.

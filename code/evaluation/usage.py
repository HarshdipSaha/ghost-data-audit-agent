"""Render model token and estimated cost accounting from a run summary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def render_usage_report(summary: dict[str, Any]) -> str:
    usage = summary.get("semantic_usage", {})
    requests = int(summary.get("requests", 0))
    input_tokens = int(usage.get("input_tokens", 0))
    output_tokens = int(usage.get("output_tokens", 0))
    total_tokens = input_tokens + output_tokens
    cost = float(usage.get("estimated_cost_usd", 0.0))
    status = "yes" if summary.get("output_written") else "no"
    return f"""# Token usage and cost report

## Run

- Prediction artifact produced: **{status}**
- Requests processed: **{requests}**
- Resolved: **{int(summary.get('resolved', 0))}**
- Unresolved: **{int(summary.get('unresolved', 0))}**

## Model usage

| Provider | Model | Calls | Cache hits | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---:|---:|---:|---:|---:|---:|
| {usage.get('provider', 'not recorded')} | {usage.get('model', 'not recorded')} | {int(usage.get('model_calls', 0))} | {int(usage.get('cache_hits', 0))} | {input_tokens} | {output_tokens} | {total_tokens} | ${cost:.6f} |

## Overall totals

- Input tokens: **{input_tokens}**
- Output tokens: **{output_tokens}**
- Total tokens: **{total_tokens}**
- Average tokens per request: **{total_tokens / requests if requests else 0:.2f}**
- Estimated total cost: **${cost:.6f}**
- Estimated cost per request: **${cost / requests if requests else 0:.8f}**
- Model elapsed time: **{float(usage.get('elapsed_seconds', 0.0)):.3f} seconds**
- Grounded lexical fallbacks after malformed model responses: **{int(usage.get('lexical_fallbacks', 0))}**
- Evidence interpretations left unresolved after malformed responses: **{int(usage.get('evidence_unresolved', 0))}**

The configured model runs locally through Ollama, so the estimated hosted inference cost is $0.00. This estimate excludes local electricity and hardware costs. If `Prediction artifact produced` is **no**, this is a diagnostic run and must not be described as the run that produced a final `output.csv`.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path)
    parser.add_argument("--report", type=Path, default=Path("code/evaluation/usage_report.md"))
    args = parser.parse_args()
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    report = render_usage_report(summary)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()

"""Run the local AI deletion auditor against dataset/ and write output.csv."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

from ghost_audit.ai import LocalSemanticAgent
from ghost_audit.contract import validate_row, write_output
from ghost_audit.engine import Auditor
from ghost_audit.models import UnresolvedAudit


def read_requests(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    required = {"case_id", "email", "requested_at", "audit_at", "request_text"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Request input must contain {sorted(required)}")
    if len({r["case_id"] for r in rows}) != len(rows):
        raise ValueError("Request file has duplicate case_id values")
    return rows


def run(
    dataset: Path,
    output: Path | None = None,
    max_cases: int | None = None,
    request_file: Path | None = None,
    expected_request_count: int | None = None,
) -> tuple[list, dict, dict]:
    request_file = request_file or dataset / "deletion_requests.csv"
    requests = read_requests(request_file)
    if expected_request_count is not None and len(requests) != expected_request_count:
        raise ValueError(f"Full request set must contain exactly {expected_request_count} rows; found {len(requests)}")
    if max_cases is not None:
        requests = requests[:max_cases]

    auditor = Auditor(dataset)
    agent = LocalSemanticAgent()

    texts = list(dict.fromkeys(row["request_text"] for row in requests))
    unique_authorizations = agent.authorize_many(texts)
    authorization_by_text = dict(zip(texts, unique_authorizations, strict=True))

    decisions, unresolved = [], []
    for request in requests:
        authorization = authorization_by_text[request["request_text"]]
        try:
            decision = auditor.audit(request, authorization, semantic=agent)
            decisions.append(decision)
        except UnresolvedAudit as exc:
            detail = exc.details if isinstance(exc.details, dict) else {"issue": str(exc.details)}
            unresolved.append({"case_id": request["case_id"], "details": detail})

    summary = {
        "request_file": str(request_file),
        "requests": len(requests),
        "unique_request_texts": len(texts),
        "resolved": len(decisions),
        "unresolved": len(unresolved),
        "output_written": False,
        "statuses": dict(Counter(d.status for d in decisions)),
        "unresolved_cases": unresolved,
        "ingestion_issues": auditor.store.issues,
        "semantic_usage": agent.usage,
    }

    if output is not None and not unresolved:
        if len(decisions) != len(read_requests(request_file)):
            raise ValueError("Refusing to write a partial request set to output.csv")
        output.parent.mkdir(parents=True, exist_ok=True)
        write_output(output, decisions)
        expected = {r["case_id"] for r in requests}
        with open(output, newline="", encoding="utf-8-sig") as stream:
            written = list(csv.DictReader(stream))
        if {r["case_id"] for r in written} != expected:
            raise ValueError("Output case coverage differs from the request set")
        for row in written:
            request = next(r for r in requests if r["case_id"] == row["case_id"])
            validate_row(row, auditor.store.evidence_times, request["audit_at"])
        summary["output_written"] = True
    return decisions, summary, {"unresolved": unresolved}


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=repo / "dataset")
    parser.add_argument("--requests", type=Path, help="Request CSV (defaults to dataset/deletion_requests.csv)")
    parser.add_argument("--output", type=Path, help="Prediction CSV (defaults to output.csv for the full set)")
    parser.add_argument("--max-cases", type=int, help="Diagnostic run only; never writes a partial output.csv")
    parser.add_argument("--summary", type=Path, default=repo / "artifacts" / "run_summary.json")
    args = parser.parse_args()

    is_full_request_set = args.requests is None
    output = None if args.max_cases is not None else (args.output or (repo / "output.csv" if is_full_request_set else repo / "artifacts" / "sample_predictions.csv"))
    try:
        expected_count = 518 if args.requests is None and args.max_cases is None else None
        _, summary, _ = run(args.dataset, output, args.max_cases, args.requests, expected_count)
    except Exception as exc:
        print(f"Audit run failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k not in {"unresolved_cases", "ingestion_issues"}}, indent=2, ensure_ascii=False))
    if summary["unresolved"]:
        print("No output.csv was written because at least one audit obligation remains unresolved.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

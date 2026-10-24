"""Independent sample-output evaluator; kept out of prediction code paths."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
OUTPUT_FIELDS = ("case_id", "deletion_status", "steps_json")


def read_rows(path: str | Path) -> dict[str, dict[str, Any]]:
    rows = {}
    with open(path, newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            case_id = row["case_id"]
            if case_id in rows:
                raise ValueError(f"Duplicate case: {case_id}")
            parsed = dict(row)
            parsed["steps"] = json.loads(row["steps_json"])
            rows[case_id] = parsed
    return rows


def evaluate(prediction_path: str | Path, reference_path: str | Path) -> dict[str, Any]:
    predicted, expected = read_rows(prediction_path), read_rows(reference_path)
    missing = expected.keys() - predicted.keys()
    if missing:
        raise ValueError(f"Predictions omit {len(missing)} reference case(s)")
    cases = len(expected)
    status_correct = sum(predicted[k]["deletion_status"] == expected[k]["deletion_status"] for k in expected)
    exact_sequences = 0
    total_fields = matching_fields = expected_steps = predicted_steps = exact_steps = 0
    resource_expected: set[tuple[str, str, str]] = set()
    resource_found: set[tuple[str, str, str]] = set()
    for case_id, expected_row in expected.items():
        p_steps, e_steps = predicted[case_id]["steps"], expected_row["steps"]
        if p_steps == e_steps:
            exact_sequences += 1
        expected_steps += len(e_steps)
        predicted_steps += len(p_steps)
        for step in e_steps:
            resource_expected.add((case_id, step["system_id"], step["resource_id"]))
        for step in p_steps:
            resource_found.add((case_id, step.get("system_id", ""), step.get("resource_id", "")))
        for index in range(max(len(e_steps), len(p_steps))):
            e_step = e_steps[index] if index < len(e_steps) else {}
            p_step = p_steps[index] if index < len(p_steps) else {}
            if e_step == p_step:
                exact_steps += 1
            for field in FIELDS:
                total_fields += 1
                matching_fields += e_step.get(field) == p_step.get(field)
    return {
        "cases": cases,
        "status_accuracy": status_correct / cases if cases else 0.0,
        "status_correct": status_correct,
        "sequence_accuracy": exact_sequences / cases if cases else 0.0,
        "exact_sequences": exact_sequences,
        "step_accuracy": exact_steps / max(expected_steps, predicted_steps, 1),
        "expected_steps": expected_steps,
        "predicted_steps": predicted_steps,
        "field_accuracy": matching_fields / total_fields if total_fields else 1.0,
        "field_matches": matching_fields,
        "field_positions": total_fields,
        "resource_recall": len(resource_found & resource_expected) / len(resource_expected) if resource_expected else 1.0,
        "expected_resources": len(resource_expected),
        "resources_found": len(resource_found & resource_expected),
    }


def render_report(metrics: dict[str, Any], command: str) -> str:
    return """# Evaluation report

## Method

The predictor receives only the request, identity/activity tables, rules and evidence. The evaluator reads `sample_output.csv` after prediction and compares it independently. Team-authored adversarial fixtures live in `code/tests/test_core.py`; their results are reported separately from held-out sample scores.

Command: `{command}`

## Sample results

| Metric | Result |
|---|---:|
| Cases | {cases} |
| Status accuracy | {status_accuracy:.3%} ({status_correct}/{cases}) |
| Exact sequence accuracy | {sequence_accuracy:.3%} ({exact_sequences}/{cases}) |
| Step accuracy | {step_accuracy:.3%} |
| Field accuracy | {field_accuracy:.3%} ({field_matches}/{field_positions}) |
| Resource recall | {resource_recall:.3%} ({resources_found}/{expected_resources}) |

## Team-authored evaluation cases

1. Evidence bundle captured after audit cutoff contains an older embedded fact: future artifact availability is excluded.
2. Primary database is empty while a physical read replica retains a subject row: replica remains a violation.
3. An identity's email changes after the audit cutoff: later email ownership does not leak backward.
4. A same-trace cache miss is followed by an explicit 404 profile read: only the 404 read supports absence.
5. An escaped log envelope preserves trace and service boundaries while a neighboring trace is ignored.

## Failures and improvements

1. Multi-request local-model batches sometimes attached a valid quote to a neighboring request. Authorization now uses one request per model prompt, exact-source quote checks and a three-way unresolved state for unsupported intent.
2. Resource or catalog mentions could be mistaken for live record reads. Document evidence now requires a visible row or state, keeps embedded fact time separate from capture availability, and rejects mentions that postdate the audit cutoff.
3. Email or phone aliases could be recycled to another stable user. Identity discovery now checks cutoff ownership and rejects conflicting stable-user references.
4. A clean primary table could hide a populated physical replica, and one citation could accidentally stand in for multiple copies. Replica scopes remain separate, and complete decisions retain evidence for each physical obligation.
5. Conditional retention and tombstone policies were previously inferred from category alone. The auditor now requires the relevant supplied condition and refuses to certify missing proof.

This report reflects the current run. Regenerate it after every prediction change. Any mismatch should be traced to a general parser, time, identity, coverage, policy, citation or ordering defect; no per-case prediction lookup is permitted.
""".format(command=command, **metrics)


def render_blocked_report(summary: dict[str, Any], sample_summary: dict[str, Any] | None = None) -> str:
    """Report a diagnostic run without fabricating prediction metrics."""
    unresolved = int(summary.get("unresolved", 0))
    sample_line = ""
    if sample_summary is not None:
        sample_line = (
            f"- Sample request diagnostic: **{int(sample_summary.get('resolved', 0))}/"
            f"{int(sample_summary.get('requests', 0))} resolved, "
            f"{int(sample_summary.get('unresolved', 0))} unresolved**; score not measured.\n"
        )
    reasons: Counter[str] = Counter()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            issue = value.get("issue")
            if issue:
                category = value.get("category")
                reasons[f"{category}: {issue}" if category else str(issue)] += 1
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(summary.get("unresolved_cases", []))
    reason_rows = "\n".join(
        "| {} | {} |".format(label.replace("|", "&#124;"), count)
        for label, count in reasons.most_common(12)
    ) or "| No per-case unresolved reason was recorded | 0 |"
    return f"""# Evaluation report

## Method and run status

The predictor receives only participant-facing request, identity/activity, policy, and evidence files. The sample reference is read only by the independent evaluator after a complete prediction CSV exists.

- Requests: **{int(summary.get('requests', 0))}**
- Audits resolved: **{int(summary.get('resolved', 0))}**
- Audits unresolved: **{unresolved}**
- Complete prediction CSV produced: **no**
{sample_line}

No complete prediction CSV was produced, so comparison with `sample_output.csv` was not run. The following metrics are **not measured**; they are not zero scores.

## Sample metrics

| Metric | Result |
|---|---:|
| Case-level deletion-status accuracy | Not measured |
| Exact sequence accuracy | Not measured |
| Step accuracy | Not measured |
| Field accuracy | Not measured |
| Resource recall | Not measured |

## Additional team-authored evaluation cases

1. `test_rejects_nonlocal_or_noncanonical_model_endpoints`: attacker-controlled hostnames, userinfo, non-HTTP schemes, paths, and queries are rejected.
2. `test_non_boolean_direct_identifier_values_do_not_establish_attribution`: false/null-like values cannot create a false anonymization obligation.
3. `test_false_policy_predicates_are_distinct_from_missing_proof`: explicitly disproven shared-context predicates differ from missing policy evidence.
4. `test_document_mention_is_not_state_and_future_embedded_time_is_excluded`: later or merely mentioned resources do not become audit-time state reads.
5. `test_complete_cites_each_physical_copy`: a replica requires its own evidence citation.

## Unresolved diagnostic reasons

Counts below are issue occurrences; one request can have multiple unresolved resources.

| Reason | Count |
|---|---:|
{reason_rows}

## Failures and improvements

The full run left {unresolved} requests unresolved because supplied policy predicates or timely state observations were not established. The largest issue groups are shown above; missing retention intervals, ownership/context facts, or authoritative reads are kept unresolved instead of being converted into guessed statuses or remediation. Hardening added exact loopback endpoint parsing, disabled environment proxies and redirects, separated disproven policy conditions from missing evidence, enforced the 518-row contract, and required both evaluation reports before packaging. The parser, identity resolver, temporal gates, conditional-policy engine, local-only model transport, and output contract are covered by automated tests; passing those tests does not replace a sample score.

Regenerate this report from the latest full-run summary after every implementation change. If unresolved audits remain, report metrics as not measured and do not package a misleading `output.csv`.
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("prediction", type=Path, nargs="?")
    parser.add_argument("reference", type=Path, nargs="?")
    parser.add_argument("--diagnostic-summary", type=Path, help="Render an honest blocked report from a run summary")
    parser.add_argument("--sample-summary", type=Path, help="Optional sample-run summary for a blocked report")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.diagnostic_summary:
        summary = json.loads(args.diagnostic_summary.read_text(encoding="utf-8"))
        sample_summary = json.loads(args.sample_summary.read_text(encoding="utf-8")) if args.sample_summary else None
        report = render_blocked_report(summary, sample_summary)
        report_path = args.report or Path("code/evaluation/evaluation_report.md")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")
        print(report)
        return
    if not args.prediction or not args.reference:
        parser.error("prediction and reference are required unless --diagnostic-summary is supplied")
    metrics = evaluate(args.prediction, args.reference)
    print(json.dumps(metrics, indent=2))
    if args.report:
        args.report.write_text(render_report(metrics, f"python code/evaluation/main.py {args.prediction} {args.reference}"), encoding="utf-8")


if __name__ == "__main__":
    main()

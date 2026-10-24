import csv
import importlib.util
import json
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "evaluation" / "main.py"
SPEC = importlib.util.spec_from_file_location("audit_evaluator", MODULE_PATH)
evaluator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluator)
USAGE_PATH = Path(__file__).resolve().parents[1] / "evaluation" / "usage.py"
USAGE_SPEC = importlib.util.spec_from_file_location("usage_report", USAGE_PATH)
usage_report = importlib.util.module_from_spec(USAGE_SPEC)
USAGE_SPEC.loader.exec_module(usage_report)


def write(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=evaluator.OUTPUT_FIELDS)
        writer.writeheader()
        for case, status, steps in rows:
            writer.writerow({"case_id": case, "deletion_status": status, "steps_json": json.dumps(steps)})


def test_evaluator_scores_status_sequence_fields_and_resources(tmp_path):
    step = {"step_no": 1, "phase": "VERIFICATION", "system_id": "account", "resource_id": "r", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "e1"}
    prediction, reference = tmp_path / "out.csv", tmp_path / "reference.csv"
    write(prediction, [("c1", "COMPLETE", [step])])
    write(reference, [("c1", "COMPLETE", [step])])
    scores = evaluator.evaluate(prediction, reference)
    assert scores["status_accuracy"] == 1
    assert scores["sequence_accuracy"] == 1
    assert scores["field_accuracy"] == 1
    assert scores["resource_recall"] == 1


def test_evaluator_rejects_missing_case_coverage(tmp_path):
    prediction, reference = tmp_path / "out.csv", tmp_path / "reference.csv"
    write(prediction, [])
    write(reference, [("c1", "NOT_APPLICABLE", [])])
    try:
        evaluator.evaluate(prediction, reference)
    except ValueError as exc:
        assert "Predictions omit" in str(exc)
    else:
        raise AssertionError("incomplete case coverage must fail")


def test_full_prediction_can_be_scored_on_reference_subset(tmp_path):
    step = {"step_no": 1, "phase": "VERIFICATION", "system_id": "account", "resource_id": "r", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "e1"}
    prediction, reference = tmp_path / "out.csv", tmp_path / "reference.csv"
    write(prediction, [("c1", "COMPLETE", [step]), ("c2", "NOT_APPLICABLE", [])])
    write(reference, [("c1", "COMPLETE", [step])])
    assert evaluator.evaluate(prediction, reference)["cases"] == 1


def test_usage_report_marks_diagnostic_run_and_accounts_for_tokens():
    report = usage_report.render_usage_report({
        "requests": 518,
        "resolved": 211,
        "unresolved": 307,
        "output_written": False,
        "semantic_usage": {
            "provider": "local Ollama",
            "model": "qwen2.5:0.5b",
            "model_calls": 400,
            "cache_hits": 118,
            "input_tokens": 12000,
            "output_tokens": 4000,
            "estimated_cost_usd": 0,
            "elapsed_seconds": 120,
        },
    })
    assert "Prediction artifact produced: **no**" in report
    assert "Total tokens: **16000**" in report
    assert "Average tokens per request: **30.89**" in report
    assert "must not be described as the run that produced a final" in report


def test_blocked_evaluation_report_labels_metrics_unmeasured():
    report = evaluator.render_blocked_report({
        "requests": 518,
        "resolved": 211,
        "unresolved": 307,
        "output_written": False,
        "unresolved_cases": [
            {"case_id": "x", "details": {"unresolved": [{"issue": "Policy obligation unresolved", "category": "SECURITY_AUDIT_LOG"}]}},
        ],
    }, {"requests": 32, "resolved": 11, "unresolved": 21, "output_written": False})
    assert "Case-level deletion-status accuracy | Not measured" in report
    assert "Exact sequence accuracy | Not measured" in report
    assert "Step accuracy | Not measured" in report
    assert "Field accuracy | Not measured" in report
    assert "Resource recall | Not measured" in report
    assert "No complete prediction CSV was produced" in report
    assert "test_rejects_nonlocal_or_noncanonical_model_endpoints" in report
    assert "test_complete_cites_each_physical_copy" in report
    assert "Sample request diagnostic: **11/32 resolved, 21 unresolved**" in report

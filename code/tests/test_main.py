import csv
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main
from ghost_audit.models import AuditDecision, UnresolvedAudit


def make_dataset(path):
    path.mkdir()
    with (path / "deletion_requests.csv").open("w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"])
        writer.writeheader()
        writer.writerow(dict(case_id="case_x", email="x@example.com", requested_at="2026-01-01T00:00:00Z", reported_status="COMPLETE", reported_at="2026-01-01T00:00:00Z", audit_at="2026-01-02T00:00:00Z", request_text="Please export data, do not delete."))


class FakeAuditor:
    def __init__(self, dataset):
        self.store = type("Store", (), {"evidence_times": {}, "issues": []})()

    def audit(self, request, authorization, semantic=None):
        if authorization is False:
            return AuditDecision(request["case_id"], "NOT_APPLICABLE", [])
        raise UnresolvedAudit(request["case_id"], {"issue": "missing proof"})


class FakeAgent:
    usage = {"provider": "test", "model_calls": 1, "input_tokens": 2, "output_tokens": 1}

    def __init__(self):
        pass

    def authorize_many(self, texts):
        return [False for _ in texts]


class FakePositiveAgent(FakeAgent):
    def authorize_many(self, texts):
        return [True for _ in texts]


def test_cli_writes_non_deletion_only_after_full_resolution(tmp_path):
    dataset = tmp_path / "dataset"
    make_dataset(dataset)
    output = tmp_path / "output.csv"
    with patch.object(main, "Auditor", FakeAuditor), patch.object(main, "LocalSemanticAgent", FakeAgent):
        decisions, summary, _ = main.run(dataset, output)
    assert decisions[0].status == "NOT_APPLICABLE"
    assert summary["unresolved"] == 0
    with output.open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    assert row["deletion_status"] == "NOT_APPLICABLE"
    assert row["steps_json"] == "[]"


def test_cli_refuses_partial_output_when_one_obligation_is_unresolved(tmp_path):
    dataset = tmp_path / "dataset"
    make_dataset(dataset)
    output = tmp_path / "output.csv"
    with patch.object(main, "Auditor", FakeAuditor), patch.object(main, "LocalSemanticAgent", FakePositiveAgent):
        decisions, summary, _ = main.run(dataset, output)
    assert decisions == []
    assert summary["unresolved"] == 1
    assert not output.exists()


def test_cli_can_run_reference_requests_with_separate_case_ids(tmp_path):
    dataset = tmp_path / "dataset"
    make_dataset(dataset)
    sample = tmp_path / "sample_deletion_requests.csv"
    with sample.open("w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"])
        writer.writeheader()
        writer.writerow(dict(case_id="sample_01", email="x@example.com", requested_at="2026-01-01T00:00:00Z", reported_status="COMPLETE", reported_at="2026-01-01T00:00:00Z", audit_at="2026-01-02T00:00:00Z", request_text="Please export data, do not delete."))
    output = tmp_path / "sample_predictions.csv"
    with patch.object(main, "Auditor", FakeAuditor), patch.object(main, "LocalSemanticAgent", FakeAgent):
        _, summary, _ = main.run(dataset, output, request_file=sample)
    assert summary["requests"] == 1
    assert summary["request_file"] == str(sample)
    with output.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["case_id"] for row in rows] == ["sample_01"]


def test_cli_rejects_wrong_row_count_for_default_full_dataset(tmp_path):
    dataset = tmp_path / "dataset"
    make_dataset(dataset)
    with patch.object(main, "Auditor", FakeAuditor), patch.object(main, "LocalSemanticAgent", FakeAgent):
        try:
            main.run(dataset, tmp_path / "output.csv", expected_request_count=518)
        except ValueError as exc:
            assert "exactly 518" in str(exc)
        else:
            raise AssertionError("full request run must enforce the 518-row contract")

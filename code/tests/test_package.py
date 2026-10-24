import importlib.util
from pathlib import Path
from zipfile import ZipFile

import pytest

MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "package.py"
SPEC = importlib.util.spec_from_file_location("package_script", MODULE_PATH)
package_script = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package_script)


def test_package_requires_both_evaluation_reports(tmp_path):
    code = tmp_path / "code"
    (code / "evaluation").mkdir(parents=True)
    (code / "main.py").write_text("pass\n", encoding="utf-8")
    archive = tmp_path / "code.zip"

    with pytest.raises(SystemExit, match="Missing required evaluation reports"):
        package_script.package_code(code, archive)

    assert not archive.exists()


def test_package_contains_required_reports_and_code_only(tmp_path):
    code = tmp_path / "code"
    evaluation = code / "evaluation"
    evaluation.mkdir(parents=True)
    (code / "main.py").write_text("pass\n", encoding="utf-8")
    (evaluation / "evaluation_report.md").write_text("Evaluation status\n", encoding="utf-8")
    (evaluation / "usage_report.md").write_text("Usage status\n", encoding="utf-8")
    (tmp_path / "dataset").mkdir()
    (code / "nested.zip").write_bytes(b"archive")
    (code / ".env").write_text("TOKEN=secret", encoding="utf-8")
    (code / "credentials.json").write_text("{}", encoding="utf-8")
    (code / "build").mkdir()
    (code / "build" / "scratch.txt").write_text("build artifact", encoding="utf-8")
    archive = tmp_path / "code.zip"

    package_script.package_code(code, archive)

    with ZipFile(archive) as zipped:
        names = set(zipped.namelist())
    assert "evaluation/evaluation_report.md" in names
    assert "evaluation/usage_report.md" in names
    assert "main.py" in names
    assert "nested.zip" not in names
    assert ".env" not in names
    assert "credentials.json" not in names
    assert "build/scratch.txt" not in names

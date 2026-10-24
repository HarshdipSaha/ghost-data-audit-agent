"""Build HackerRank's code.zip from code/ without data, caches, or environments."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
CODE = ROOT / "code"
OUTPUT = ROOT / "code.zip"
EXCLUDED_PARTS = {".cache", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules", "build", "dist", "target"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"}
EXCLUDED_NAMES = {"credentials.json", "token.json", "auth.json", ".npmrc", ".pypirc", "netrc"}
REQUIRED_REPORTS = ("evaluation/evaluation_report.md", "evaluation/usage_report.md")


def _is_secret_or_environment_file(path: Path) -> bool:
    name = path.name.casefold()
    return (
        name.startswith(".env")
        or name in EXCLUDED_NAMES
        or name.startswith(("credentials.", "secret.", "secrets.", "service-account"))
        or name.endswith((".pem", ".key", ".p12", ".pfx"))
    )


def package_code(code: Path, output: Path) -> None:
    missing = [relative for relative in REQUIRED_REPORTS if not (code / relative).is_file()]
    if missing:
        raise SystemExit(f"Missing required evaluation reports: {', '.join(missing)}")
    files = [
        path for path in code.rglob("*")
        if path.is_file()
        and not any(part in EXCLUDED_PARTS for part in path.parts)
        and path.suffix.casefold() not in EXCLUDED_SUFFIXES
        and not _is_secret_or_environment_file(path)
    ]
    if not files:
        raise SystemExit("No code files found")
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, path.relative_to(code))
    print(f"Wrote {output} ({len(files)} files)")


def main() -> None:
    package_code(CODE, OUTPUT)


if __name__ == "__main__":
    main()

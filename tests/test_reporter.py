"""Tests de AuditReporter."""

import json

from vibeaudit.models import (
    AuditReport,
    Metrics,
    ProjectMetadata,
    Secret,
    Severity,
    Vulnerability,
)
from vibeaudit.reporter import AuditReporter


def make_repo(tmp_path):
    """Crea un repo con código, tests y un archivo no contable."""
    (tmp_path / "app.py").write_text("a = 1\nb = 2\nc = 3\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("x = 1\ny = 2\n")
    (tmp_path / "data.txt").write_text("uno\ndos\ntres\ncuatro\ncinco\n")
    return tmp_path


def make_reporter(repo_path, extra_issues=None):
    return AuditReporter(
        project=ProjectMetadata(name="demo", iac_files=["main.tf"]),
        vulnerabilities=[
            Vulnerability(rule="r1", file="app.py", line=1, severity=Severity.HIGH),
            Vulnerability(rule="r2", file="app.py", line=2, severity=Severity.CRITICAL),
        ],
        secrets=[
            Secret(type="aws", file="c.py", line=2, severity=Severity.CRITICAL)
        ],
        iac_issues=extra_issues
        or [
            Vulnerability(rule="ckv", file="main.tf", line=3, severity=Severity.MEDIUM)
        ],
        repo_path=repo_path,
    )


class TestAuditReporter:
    def test_metricas_loc_y_tests(self, tmp_path):
        repo = make_repo(tmp_path)
        report = make_reporter(repo).build()

        assert report.metrics.lines_of_code == 5
        assert report.metrics.test_files == 1

    def test_conteo_por_severidad(self, tmp_path):
        repo = make_repo(tmp_path)
        report = make_reporter(repo).build()

        assert report.metrics.vulnerabilities_by_severity == {
            "HIGH": 1,
            "CRITICAL": 1,
            "MEDIUM": 1,
        }

    def test_build_cachea_el_reporte(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = make_reporter(repo)

        first = reporter.build()
        second = reporter.build()

        assert first is second

    def test_to_json_usa_aliases_camelcase(self, tmp_path):
        repo = make_repo(tmp_path)
        data = json.loads(make_reporter(repo).to_json())

        assert data["project"]["name"] == "demo"
        assert data["project"]["iacFiles"] == ["main.tf"]
        assert "linesOfCode" in data["metrics"]
        assert "vulnerabilitiesBySeverity" in data["metrics"]
        assert "iacIssues" in data

    def test_save_to_file(self, tmp_path):
        repo = make_repo(tmp_path)
        out = tmp_path / "out" / "report.json"
        make_reporter(repo).save_to_file(out)

        data = json.loads(out.read_text())
        assert data["project"]["name"] == "demo"

    def test_sin_repo_path_loc_cero(self, tmp_path):
        report = make_reporter(None).build()
        assert report.metrics.lines_of_code == 0
        assert report.metrics.test_files == 0

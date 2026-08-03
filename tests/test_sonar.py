"""Tests de la integración SonarQube (Generic Issue Import y sonar-scanner)."""

import json
import subprocess
from pathlib import Path

import pytest

from vibeaudit.models import (
    AuditReport,
    Metrics,
    ProjectMetadata,
    Secret,
    Severity,
    Vulnerability,
)
from vibeaudit.sonar import (
    SonarRunner,
    _severity_of,
    save_sonar_json,
    to_sonar_issues,
)


def sample_report() -> AuditReport:
    return AuditReport(
        project=ProjectMetadata(name="demo", languages=["python"]),
        vulnerabilities=[
            Vulnerability(
                rule="python.eval.usage",
                file="src/app.py",
                line=12,
                severity=Severity.CRITICAL,
                snippet="eval(user_input)",
            )
        ],
        secrets=[
            Secret(type="aws-access-token", file=".env", line=3, severity=Severity.HIGH)
        ],
        metrics=Metrics(),
    )


class TestGenericImport:
    def test_formato_generic_issue_import(self):
        payload = to_sonar_issues(sample_report())
        assert "issues" in payload and len(payload["issues"]) == 2

    def test_mapa_severidad_y_campos(self):
        payload = to_sonar_issues(sample_report())
        sast = next(
            i for i in payload["issues"] if i["ruleId"] == "sast-python.eval.usage"
        )
        assert sast["engineId"] == "vibeaudit"
        assert sast["type"] == "VULNERABILITY"
        assert sast["severity"] == "BLOCKER"
        assert sast["primaryLocation"]["filePath"] == "src/app.py"
        assert sast["primaryLocation"]["textRange"]["startLine"] == 12

        secret = next(i for i in payload["issues"] if i["ruleId"].startswith("secret-"))
        assert secret["severity"] == "CRITICAL"
        assert secret["primaryLocation"]["filePath"] == ".env"

    def test_sin_hallazgos_con_archivo_vacio(self):
        report = AuditReport(
            project=ProjectMetadata(name="x"),
            metrics=Metrics(),
        )
        payload = to_sonar_issues(report)
        assert payload["issues"] == []

    def test_save_sonar_json_escribe_fichero(self, tmp_path):
        out = tmp_path / "sonar" / "sonar-issues.json"
        save_sonar_json(sample_report(), out)
        data = json.loads(out.read_text())
        assert len(data["issues"]) == 2

    def test_los_sin_archivo_no_se_importan(self):
        from vibeaudit.models import LLMFinding

        report = AuditReport(
            project=ProjectMetadata(name="x"),
            llm_findings=[
                LLMFinding(title="hallazgo LLM", severity=Severity.HIGH)
            ],
            metrics=Metrics(),
        )
        payload = to_sonar_issues(report)
        assert payload["issues"] == []

    def test_severity_mapping_helper(self):
        assert _severity_of(Severity.CRITICAL) == "BLOCKER"
        assert _severity_of(Severity.HIGH) == "CRITICAL"
        assert _severity_of(Severity.MEDIUM) == "MAJOR"
        assert _severity_of(Severity.LOW) == "MINOR"
        assert _severity_of(Severity.INFO) == "INFO"
        assert _severity_of("raro") == "MAJOR"


class TestSonarRunner:
    def test_is_installed_true(self, monkeypatch):
        fake = subprocess.CompletedProcess([], 0)
        monkeypatch.setattr(
            "vibeaudit.sonar.subprocess.run", lambda *a, **k: fake
        )
        assert SonarRunner.is_installed() is True

    def test_is_installed_false_sin_binario(self, monkeypatch):
        def _raise(*a, **k):
            raise FileNotFoundError("no existe")

        monkeypatch.setattr("vibeaudit.sonar.subprocess.run", _raise)
        assert SonarRunner.is_installed() is False

    def test_scan_sin_binario_lanza_error_limpio(self, monkeypatch):
        monkeypatch.setattr(
            "vibeaudit.sonar.SonarRunner.is_installed",
            staticmethod(lambda: False),
        )
        with pytest.raises(RuntimeError, match="sonar-scanner"):
            SonarRunner(Path("/tmp/repo")).scan()

    def test_scan_ejecuta_bla_con_project_basedir(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(
            "vibeaudit.sonar.SonarRunner.is_installed",
            staticmethod(lambda: True),
        )

        def _run(args, capture_output, text, check, timeout):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0)

        monkeypatch.setattr("vibeaudit.sonar.subprocess.run", _run)
        rc = SonarRunner(tmp_path).scan()
        assert rc == 0
        assert calls[0][0] == "sonar-scanner"
        assert f"-Dsonar.projectBaseDir={tmp_path}" in calls[0]
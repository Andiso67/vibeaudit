"""Tests de los modelos Pydantic."""

import pytest
from pydantic import ValidationError

from vibeaudit.models import (
    AuditReport,
    Metrics,
    ProjectMetadata,
    Secret,
    Severity,
    Vulnerability,
)


class TestSeverity:
    def test_valores_del_enum(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"


class TestVulnerability:
    def test_linea_debe_ser_mayor_que_cero(self):
        with pytest.raises(ValidationError):
            Vulnerability(rule="r", file="f.py", line=0, severity=Severity.HIGH)

    def test_linea_negativa_invalida(self):
        with pytest.raises(ValidationError):
            Vulnerability(rule="r", file="f.py", line=-3, severity=Severity.HIGH)

    def test_rule_vacia_invalida(self):
        with pytest.raises(ValidationError):
            Vulnerability(rule="", file="f.py", line=1, severity=Severity.HIGH)

    def test_snippet_se_limpia(self):
        vuln = Vulnerability(
            rule="r", file="f.py", line=1, severity=Severity.LOW, snippet="  x  "
        )
        assert vuln.snippet == "x"


class TestSecret:
    def test_linea_debe_ser_mayor_que_cero(self):
        with pytest.raises(ValidationError):
            Secret(type="t", file="f.py", line=0, severity=Severity.HIGH)


class TestMetrics:
    def test_populate_by_name(self):
        metrics = Metrics(lines_of_code=10, test_files=2)
        assert metrics.lines_of_code == 10
        assert metrics.test_files == 2

    def test_conteos_negativos_invalidos(self):
        with pytest.raises(ValidationError):
            Metrics(lines_of_code=-1)

    def test_aliases_al_serializar(self):
        metrics = Metrics(
            lines_of_code=10,
            test_files=2,
            dependencies_with_cves=["lodash"],
            vulnerabilities_by_severity={"HIGH": 3},
        )
        dumped = metrics.model_dump_json(by_alias=True)
        assert '"linesOfCode":10' in dumped
        assert '"testFiles":2' in dumped
        assert '"dependenciesWithCves"' in dumped
        assert '"vulnerabilitiesBySeverity"' in dumped


class TestProjectMetadata:
    def test_populate_by_name_con_alias(self):
        project = ProjectMetadata(name="demo", iac_files=["main.tf"])
        assert project.iac_files == ["main.tf"]

    def test_nombre_vacio_invalido(self):
        with pytest.raises(ValidationError):
            ProjectMetadata(name="")


class TestAuditReport:
    def test_reporte_completo_con_aliases(self):
        report = AuditReport(
            project=ProjectMetadata(name="demo", iac_files=["main.tf"]),
            vulnerabilities=[
                Vulnerability(rule="r", file="f.py", line=1, severity=Severity.HIGH)
            ],
            secrets=[Secret(type="aws", file="c.py", line=2, severity=Severity.CRITICAL)],
            iac_issues=[
                Vulnerability(rule="ckv", file="main.tf", line=3, severity=Severity.MEDIUM)
            ],
            cicd_issues=[
                Vulnerability(rule="cicd-x", file="ci.yml", line=1, severity=Severity.HIGH)
            ],
            custom_issues=[
                Vulnerability(rule="custom-x", file="app.py", line=2, severity=Severity.MEDIUM)
            ],
            metrics=Metrics(),
        )
        dumped = report.model_dump_json(by_alias=True)
        assert '"iacFiles"' in dumped
        assert '"iacIssues"' in dumped
        assert '"vulnerabilitiesBySeverity"' in dumped
        assert '"cicdIssues"' in dumped
        assert '"customIssues"' in dumped

    def test_valores_por_defecto(self):
        report = AuditReport(project=ProjectMetadata(name="demo"), metrics=Metrics())
        assert report.vulnerabilities == []
        assert report.secrets == []
        assert report.iac_issues == []
        assert report.cicd_issues == []
        assert report.custom_issues == []

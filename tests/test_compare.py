"""Tests de la comparativa LLM vs SonarQube y del import de hallazgos LLM."""

from vibeaudit.compare import compare, to_text
from vibeaudit.sonar import to_sonar_issues
from vibeaudit.models import (
    AuditReport,
    LLMFinding,
    Metrics,
    ProjectMetadata,
    Severity,
    Vulnerability,
)


def make_report(llm_findings, vulns=()):
    return AuditReport(
        project=ProjectMetadata(name="demo", commit_hash="abc"),
        vulnerabilities=list(vulns),
        llm_findings=llm_findings,
        metrics=Metrics(lines_of_code=100),
    )


def llm(title, files, checklist=None):
    return LLMFinding(
        title=title,
        severity=Severity.HIGH,
        checklist_ref=checklist,
        evidence="evidencia",
        recommendation="recomendación",
        related_files=files,
    )


def sonar_issue(file_path, rule="sast-python.eval.usage"):
    return {
        "engineId": "external_vibeaudit",
        "ruleId": rule,
        "severity": "CRITICAL",
        "type": "VULNERABILITY",
        "primaryLocation": {"filePath": file_path, "textRange": {}},
    }


class TestCompare:
    def test_hallazgo_llm_unico_cuando_no_hay_issue_en_sus_archivos(self):
        report = make_report([llm("No usar eval", ["src/a.py"])])
        result = compare(report.model_dump(by_alias=True), [sonar_issue("src/b.py")])
        assert result["summary"] == {
            "total": 1,
            "covered_by_sonar": 0,
            "unique_llm": 1,
        }
        assert result["details"][0]["coveredBySonar"] is False

    def test_hallazgo_llm_coincide_cuando_sonar_tiene_issue_en_mismo_archivo(self):
        report = make_report([llm("No usar eval", ["src/a.py"])])
        result = compare(
            report.model_dump(by_alias=True),
            [sonar_issue("src/a.py", "sast-python.eval.usage")],
        )
        assert result["summary"]["covered_by_sonar"] == 1
        assert result["summary"]["unique_llm"] == 0
        assert result["details"][0]["matchingSonarRules"] == [
            "sast-python.eval.usage"
        ]

    def test_sonar_engines_cuenta_por_prefijo(self):
        report = make_report([])
        result = compare(
            report.model_dump(by_alias=True),
            [sonar_issue("a.py", "sast-x"), sonar_issue("b.py", "iac-y")],
        )
        assert result["sonar_imported"] == 2
        assert result["sonar_engines"] == {"sast": 1, "iac": 1}

    def test_to_text_es_legible(self):
        report = make_report([llm("No usar eval", ["src/a.py"])])
        result = compare(report.model_dump(by_alias=True), [])
        text = to_text(result)
        assert "Hallazgos del auditor LLM : 1" in text
        assert "únicos del LLM" in text


class TestSonarLLMImport:
    def test_llm_findings_se_exportan_a_sonar(self):
        report = make_report(
            [llm("No usar eval", ["src/a.py"], checklist="12-factor.config")]
        )
        payload = to_sonar_issues(report)
        rules = [i["ruleId"] for i in payload["issues"]]
        assert "llm-12-factor.config" in rules
        issue = next(
            i for i in payload["issues"] if i["ruleId"] == "llm-12-factor.config"
        )
        assert issue["primaryLocation"]["filePath"] == "src/a.py"
        assert "Recomendación" in issue["primaryLocation"]["message"]

    def test_llm_sin_archivos_se_ancla_al_primer_iac(self):
        report = make_report(
            [LLMFinding(title="Revisar logs", severity=Severity.LOW)],
        )
        report.project.iac_files = ["Dockerfile"]
        payload = to_sonar_issues(report)
        assert payload["issues"][0]["primaryLocation"]["filePath"] == "Dockerfile"
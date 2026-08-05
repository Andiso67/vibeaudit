"""Tests de la comparativa multi-repo: score, ranking y comando CLI."""

import json

from typer.testing import CliRunner

from vibeaudit.cli import app
from vibeaudit.models import (
    AuditReport,
    Metrics,
    ProjectMetadata,
    Severity,
    Vulnerability,
)
from vibeaudit.multirepo import (
    SEVERITY_WEIGHTS,
    ranking,
    ranking_csv,
    ranking_html,
    score_report,
)

runner = CliRunner()


def _report(name: str, sev: Severity, n: int, loc: int = 1000) -> AuditReport:
    return AuditReport(
        project=ProjectMetadata(name=name),
        vulnerabilities=[
            Vulnerability(rule="r", file="a.py", line=1, severity=sev)
            for _ in range(n)
        ],
        metrics=Metrics(lines_of_code=loc),
    )


class FakeScanner:
    def __init__(self, repo_path, *args, **kwargs):
        self.repo_path = repo_path

    def scan(self):
        return []


def test_score_pondera_por_severidad():
    crit = score_report(_report("a", Severity.CRITICAL, 1))
    assert crit["score"] == SEVERITY_WEIGHTS["CRITICAL"]
    assert crit["total"] == 1

    mezcla = score_report(
        AuditReport(
            project=ProjectMetadata(name="m"),
            vulnerabilities=[
                Vulnerability(rule="r", file="a.py", line=1, severity=Severity.CRITICAL),
                Vulnerability(rule="r", file="a.py", line=1, severity=Severity.HIGH),
                Vulnerability(rule="r", file="a.py", line=1, severity=Severity.MEDIUM),
                Vulnerability(rule="r", file="a.py", line=1, severity=Severity.LOW),
            ],
            metrics=Metrics(lines_of_code=1000),
        )
    )
    assert mezcla["score"] == 10 + 5 + 2 + 1
    assert mezcla["density"] == round(18.0 / 1.0, 2)


def test_ranking_ordena_por_score():
    a = score_report(_report("riesgoso", Severity.CRITICAL, 3))
    b = score_report(_report("tranquilo", Severity.LOW, 1))
    ordered = ranking([b, a])
    assert [r["name"] for r in ordered] == ["riesgoso", "tranquilo"]
    assert ordered[0]["position"] == 1
    assert ordered[1]["position"] == 2


def test_ranking_csv_y_html():
    results = ranking(
        [score_report(_report("a", Severity.HIGH, 2))]
    )
    csv_text = ranking_csv(results)
    assert "posicion,repositorio" in csv_text
    assert "a" in csv_text
    html_text = ranking_html(results)
    assert "Ranking de riesgo" in html_text
    assert "HIGH·2" in html_text


def test_compare_multi_genera_ranking(monkeypatch, tmp_path):
    for cls in (
        "GitleaksScanner",
        "SemgrepScanner",
        "CheckovScanner",
        "CICDScanner",
        "DependencyScanner",
        "CustomRulesScanner",
    ):
        monkeypatch.setattr("vibeaudit.cli." + cls, FakeScanner)

    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    for repo in (repo_a, repo_b):
        repo.mkdir()
        (repo / "main.py").write_text("print('hola')\n")
    salida = tmp_path / "ranking"
    result = runner.invoke(
        app,
        ["compare-multi", str(repo_a), str(repo_b), "--output", str(salida)],
    )
    assert result.exit_code == 0, result.output
    assert "Ranking de riesgo" in result.output
    assert (salida / "ranking-riesgo.csv").exists()
    assert (salida / "ranking-riesgo.html").exists()
    assert (salida / "ranking-riesgo.json").exists()
    data = json.loads((salida / "ranking-riesgo.json").read_text())
    assert len(data) == 2
    assert data[0]["position"] == 1


def test_compare_multi_con_un_solo_repo_rechazado(monkeypatch, tmp_path):
    repo_a = tmp_path / "repo-a"
    repo_a.mkdir()
    (repo_a / "main.py").write_text("print('hola')\n")
    result = runner.invoke(app, ["compare-multi", str(repo_a)])
    assert result.exit_code == 1

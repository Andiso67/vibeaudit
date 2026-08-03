"""Tests del CLI (scan): validación de flags y flujo con --path."""

import json
import subprocess

from typer.testing import CliRunner

from vibeaudit.cli import app

runner = CliRunner()


class FakeScanner:
    """Scanner falso que no ejecuta herramientas externas."""

    def __init__(self, repo_path, *args, **kwargs):
        self.repo_path = repo_path

    def scan(self):
        return []


def test_scan_sin_repo_url_ni_path_es_error(monkeypatch):
    monkeypatch.setattr("vibeaudit.cli.RepoIngester", FakeRepoIngester)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1
    assert "Indica --repo-url o --path" in result.output


def test_scan_con_repo_url_y_path_es_error(monkeypatch):
    monkeypatch.setattr("vibeaudit.cli.RepoIngester", FakeRepoIngester)
    result = runner.invoke(
        app, ["scan", "--repo-url", "https://github.com/a/b", "--path", "/tmp"]
    )
    assert result.exit_code == 1
    assert "Indica --repo-url o --path" in result.output


def test_scan_branch_y_tag_juntos_es_error(monkeypatch):
    monkeypatch.setattr("vibeaudit.cli.RepoIngester", FakeRepoIngester)
    result = runner.invoke(
        app,
        [
            "scan",
            "--repo-url",
            "https://github.com/a/b",
            "--branch",
            "main",
            "--tag",
            "v1.0",
        ],
    )
    assert result.exit_code == 1
    assert "no ambos" in result.output


def test_scan_path_con_token_es_error(monkeypatch):
    monkeypatch.setattr("vibeaudit.cli.RepoIngester", FakeRepoIngester)
    result = runner.invoke(
        app, ["scan", "--path", "/tmp", "--token", "tok"]
    )
    assert result.exit_code == 1
    assert "solo aplican con --repo-url" in result.output


def test_scan_path_con_depth_es_error(monkeypatch):
    monkeypatch.setattr("vibeaudit.cli.RepoIngester", FakeRepoIngester)
    result = runner.invoke(
        app, ["scan", "--path", "/tmp", "--depth", "5"]
    )
    assert result.exit_code == 1
    assert "solo aplican con --repo-url" in result.output


def test_scan_depth_invalido_lo_rechaza_typer(monkeypatch):
    monkeypatch.setattr("vibeaudit.cli.RepoIngester", FakeRepoIngester)
    result = runner.invoke(
        app, ["scan", "--repo-url", "https://github.com/a/b", "--depth", "0"]
    )
    assert result.exit_code != 0
    assert "depth" in result.output


def test_scan_con_branch_y_depth_genera_reporte(monkeypatch, tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("print('hola')\n")
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"], cwd=repo_dir, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo_dir, check=True)

    monkeypatch.setattr("vibeaudit.cli.GitleaksScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.SemgrepScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CheckovScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CICDScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.DependencyScanner", FakeScanner)

    salida = tmp_path / "reporte.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--repo-url",
            str(repo_dir),
            "--branch",
            "main",
            "--depth",
            "2",
            "--output",
            str(salida),
        ],
    )

    assert result.exit_code == 0, result.output
    reporte = json.loads(salida.read_text())
    assert reporte["project"]["defaultBranch"] == "main"


def test_scan_con_path_genera_reporte(monkeypatch, tmp_path):
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / "main.py").write_text("print('hola')\n")

    monkeypatch.setattr("vibeaudit.cli.GitleaksScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.SemgrepScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CheckovScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CICDScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.DependencyScanner", FakeScanner)

    salida = tmp_path / "reporte.json"
    result = runner.invoke(
        app, ["scan", "--path", str(proyecto), "--output", str(salida)]
    )

    assert result.exit_code == 0, result.output
    reporte = json.loads(salida.read_text())
    assert reporte["project"]["name"] == "proyecto"


def test_scan_con_dashboard_genera_html_extra(monkeypatch, tmp_path):
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / "main.py").write_text("print('hola')\n")

    monkeypatch.setattr("vibeaudit.cli.GitleaksScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.SemgrepScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CheckovScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CICDScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.DependencyScanner", FakeScanner)

    salida = tmp_path / "reporte.json"
    result = runner.invoke(
        app,
        ["scan", "--path", str(proyecto), "--output", str(salida), "--dashboard"],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(salida.read_text())["project"]["name"] == "proyecto"
    dashboard = tmp_path / "reporte-dashboard.html"
    assert dashboard.exists()
    content = dashboard.read_text()
    assert "<title>Dashboard — proyecto</title>" in content
    assert 'type="application/json"' in content
    assert "Dashboard guardado en" in result.output


class FakeLLMAuditor:
    def __init__(self, report, *args, **kwargs):
        self.report = report

    def audit(self):
        from vibeaudit.models import LLMFinding, Severity

        return [
            LLMFinding(
                title="Secretos en el código",
                severity=Severity.CRITICAL,
                checklist_ref="12-factor.config",
                evidence="ev",
            )
        ]


class FakeLLMUnavailable:
    def __init__(self, report, *args, **kwargs):
        self.report = report

    def audit(self):
        from vibeaudit.llm import LLMUnavailableError

        raise LLMUnavailableError("motor caido")


def test_scan_con_llm_anade_findings(monkeypatch, tmp_path):
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / "main.py").write_text("print('hola')\n")

    monkeypatch.setattr("vibeaudit.cli.GitleaksScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.SemgrepScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CheckovScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CICDScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.DependencyScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.LLMAuditor", FakeLLMAuditor)

    salida = tmp_path / "reporte.json"
    result = runner.invoke(
        app, ["scan", "--path", str(proyecto), "--output", str(salida), "--llm"]
    )

    assert result.exit_code == 0, result.output
    reporte = json.loads(salida.read_text())
    assert len(reporte["llmFindings"]) == 1
    assert reporte["llmFindings"][0]["checklistRef"] == "12-factor.config"
    assert "1 hallazgos LLM" in " ".join(result.output.split())


def test_scan_llm_indisponible_avisa_y_continua(monkeypatch, tmp_path):
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / "main.py").write_text("print('hola')\n")

    monkeypatch.setattr("vibeaudit.cli.GitleaksScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.SemgrepScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CheckovScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CICDScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.DependencyScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.LLMAuditor", FakeLLMUnavailable)

    salida = tmp_path / "reporte.json"
    result = runner.invoke(
        app, ["scan", "--path", str(proyecto), "--output", str(salida), "--llm"]
    )

    assert result.exit_code == 0, result.output
    assert "Advertencia" in result.output
    assert "sin análisis LLM" in result.output
    reporte = json.loads(salida.read_text())
    assert reporte["llmFindings"] == []
    assert reporte["project"]["name"] == "proyecto"


def test_scan_sin_llm_no_invoca_auditor(monkeypatch, tmp_path):
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / "main.py").write_text("print('hola')\n")

    monkeypatch.setattr("vibeaudit.cli.GitleaksScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.SemgrepScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CheckovScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CICDScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.DependencyScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.LLMAuditor", FakeLLMAuditor)

    salida = tmp_path / "reporte.json"
    result = runner.invoke(
        app, ["scan", "--path", str(proyecto), "--output", str(salida)]
    )

    assert result.exit_code == 0, result.output
    reporte = json.loads(salida.read_text())
    assert "llmFindings" in reporte
    assert reporte["llmFindings"] == []


class FakeRepoIngester:
    """Ingester falso para aislar la validación de flags."""

    def __init__(self, *args, **kwargs):
        raise AssertionError("No debería instanciarse en validaciones de flags")


class FakeScannerConIac:
    """Scanner falso que aporta un issue de IaC real (CKV_AWS_20)."""

    def __init__(self, repo_path, *args, **kwargs):
        self.repo_path = repo_path

    def scan(self):
        from vibeaudit.models import Severity, Vulnerability

        return [
            Vulnerability(
                rule="CKV_AWS_20",
                file="infra/main.tf",
                line=1,
                severity=Severity.HIGH,
            )
        ]


def test_scan_sin_memory_no_crea_directorio(monkeypatch, tmp_path):
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / "main.py").write_text("print('hola')\n")
    memoria = tmp_path / "memoria"

    monkeypatch.setattr("vibeaudit.cli.GitleaksScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CICDScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.DependencyScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CustomRulesScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.SemgrepScanner", FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CheckovScanner", FakeScanner)

    result = runner.invoke(
        app, ["scan", "--path", str(proyecto), "--output", str(tmp_path / "r.json")]
    )
    assert result.exit_code == 0, result.output
    assert not memoria.exists()


def test_scan_memory_segunda_vez_detecta_recurrente(monkeypatch, tmp_path):
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / "main.py").write_text("print('hola')\n")
    memoria = tmp_path / "memoria"
    salida = tmp_path / "reporte.json"

    def scan():
        return runner.invoke(
            app,
            ["scan", "--path", str(proyecto), "--output", str(salida), "--memory", str(memoria)],
        )

    for cls in (
        "GitleaksScanner",
        "SemgrepScanner",
        "CICDScanner",
        "DependencyScanner",
        "CustomRulesScanner",
    ):
        monkeypatch.setattr("vibeaudit.cli." + cls, FakeScanner)
    monkeypatch.setattr("vibeaudit.cli.CheckovScanner", FakeScannerConIac)

    primera = scan()
    assert primera.exit_code == 0, primera.output
    assert json.loads(salida.read_text())["recurrentFindings"] == []

    segunda = scan()
    assert segunda.exit_code == 0, segunda.output
    reporte = json.loads(salida.read_text())
    assert len(reporte["recurrentFindings"]) == 1
    assert reporte["recurrentFindings"][0]["rule"] == "CKV_AWS_20"
    assert reporte["recurrentFindings"][0]["occurrences"] == 2
    assert "recurrentes" in segunda.output


def test_memory_add_y_list(tmp_path):
    memoria = tmp_path / "memoria"
    result = runner.invoke(
        app,
        [
            "memory",
            "add",
            str(memoria),
            "--rule",
            "CKV_AWS_20",
            "--fix",
            "Añadir public_access_block",
            "--framework",
            "AWS WAF",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Memoria actualizada" in result.output

    listing = runner.invoke(app, ["memory", "list", str(memoria)])
    assert listing.exit_code == 0, listing.output
    assert "CKV_AWS_20" in listing.output
    assert "public_access_block" in listing.output


def test_scan_con_deliverables_genera_entregables(monkeypatch, tmp_path):
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / "main.py").write_text("print('hola')\n")
    entregables = tmp_path / "entregables"

    for cls in (
        "GitleaksScanner",
        "SemgrepScanner",
        "CICDScanner",
        "DependencyScanner",
        "CustomRulesScanner",
        "CheckovScanner",
    ):
        monkeypatch.setattr("vibeaudit.cli." + cls, FakeScanner)

    result = runner.invoke(
        app,
        [
            "scan",
            "--path",
            str(proyecto),
            "--output",
            str(tmp_path / "r.json"),
            "--deliverables",
            str(entregables),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Entregables" in result.output
    for name in (
        "c4-context.mmd",
        "c4-container.mmd",
        "roadmap.md",
        "backlog.csv",
        "backlog.json",
    ):
        assert (entregables / name).exists(), f"falta {name}"

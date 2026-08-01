"""Tests del CLI (scan): validación de flags y flujo con --path."""

import json

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


class FakeRepoIngester:
    """Ingester falso para aislar la validación de flags."""

    def __init__(self, *args, **kwargs):
        raise AssertionError("No debería instanciarse en validaciones de flags")

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


class FakeRepoIngester:
    """Ingester falso para aislar la validación de flags."""

    def __init__(self, *args, **kwargs):
        raise AssertionError("No debería instanciarse en validaciones de flags")

"""Tests del CustomRulesScanner (reglas custom 'Vibe Coding')."""

import json
from pathlib import Path

import pytest

from vibeaudit.models import Severity
from vibeaudit.scanners.custom import CustomRulesScanner


class FakeResult:
    """Imita el resultado de subprocess.run."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


SEMGREP_JSON = json.dumps(
    {
        "results": [
            {
                "check_id": "custom.no-sql-select-star",
                "path": "/repo/app.py",
                "start": {"line": 3},
                "extra": {
                    "severity": "WARNING",
                    "lines": 'SELECT * FROM users',
                },
            },
            {
                "check_id": "custom.no-any-ts",
                "path": "/repo/foo.ts",
                "start": {"line": 10},
                "extra": {
                    "severity": "ERROR",
                    "lines": "const x: any = 1;",
                },
            },
            {
                "check_id": "custom.use-logger",
                "path": "/repo/util.js",
                "start": {"line": 5},
                "extra": {
                    "severity": "INFO",
                    "lines": "console.log(1)",
                },
            },
        ],
        "errors": [],
    }
)


def make_scanner(tmp_path, rules_dir=None):
    """Scanner con repo_path en tmp_path (rutas relativas funcionales)."""
    return CustomRulesScanner(repo_path=tmp_path, rules_dir=rules_dir)


def test_parse_output_incluye_todas_las_severidades(tmp_path):
    findings = make_scanner(tmp_path)._parse_output(SEMGREP_JSON)

    assert len(findings) == 3
    severities = {f.severity for f in findings}
    assert severities == {Severity.MEDIUM, Severity.HIGH, Severity.LOW}


def test_parse_output_rutas_relativas(tmp_path):
    findings = make_scanner(tmp_path)._parse_output(
        SEMGREP_JSON.replace("/repo", str(tmp_path))
    )
    assert findings[0].file == "app.py"
    assert findings[0].line == 3
    assert findings[0].rule == "custom.no-sql-select-star"


def test_parse_output_quita_namespace_del_rules_dir(tmp_path):
    rules_dir = tmp_path / "rules"
    namespace = ".".join(p for p in str(rules_dir).split("/") if p)
    findings = make_scanner(tmp_path)._parse_output(
        SEMGREP_JSON.replace(
            "custom.",
            f"{namespace}.custom.",
        ),
        str(rules_dir),
    )
    assert findings[0].rule == "custom.no-sql-select-star"
    assert findings[1].rule == "custom.no-any-ts"


def test_parse_output_quita_namespace_de_subdirectorios(tmp_path):
    rules_dir = tmp_path / "rules"
    (rules_dir / "sub").mkdir(parents=True)
    (rules_dir / "sub" / "extra.yml").write_text("rules: []")
    namespace = ".".join(p for p in str(rules_dir).split("/") if p)
    findings = make_scanner(tmp_path)._parse_output(
        SEMGREP_JSON.replace(
            "custom.",
            f"{namespace}.sub.custom.",
        ),
        str(rules_dir),
    )
    assert findings[0].rule == "custom.no-sql-select-star"


def test_scan_resuelve_path_relativo(monkeypatch, tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "regla.yml").write_text("rules: []")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeResult(stdout="{}")

    monkeypatch.setattr("vibeaudit.scanners.custom.subprocess.run", fake_run)
    monkeypatch.setattr(
        CustomRulesScanner, "is_installed", staticmethod(lambda: True)
    )
    scanner = CustomRulesScanner(repo_path=tmp_path, rules_dir=rules_dir)
    scanner.scan()
    assert str(rules_dir.resolve()) in captured["cmd"]
    assert rules_dir.resolve() in [Path(c) for c in captured["cmd"]]


def test_scan_rules_dir_vacio_avisa_y_no_ejecuta(monkeypatch, tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    called = []

    def fake_run(cmd, **kwargs):
        called.append(cmd)
        return FakeResult(stdout="{}")

    monkeypatch.setattr("vibeaudit.scanners.custom.subprocess.run", fake_run)
    monkeypatch.setattr(
        CustomRulesScanner, "is_installed", staticmethod(lambda: True)
    )
    scanner = CustomRulesScanner(repo_path=tmp_path, rules_dir=rules_dir)
    assert scanner.scan() == []
    assert called == []


def test_parse_output_json_invalido_vacia_lista(tmp_path):
    assert make_scanner(tmp_path)._parse_output("no es json") == []


def test_parse_output_con_config_invalido_avisa(tmp_path, capsys):
    out = json.dumps(
        {
            "results": [],
            "errors": [
                {
                    "code": 5,
                    "message": "Invalid YAML file ../broken/bad.yml:\n\tmapping values are not allowed here",
                },
                {
                    "code": 7,
                    "message": "invalid configuration file found (1 configs were invalid)",
                },
            ],
        }
    )
    assert make_scanner(tmp_path)._parse_output(out, str(tmp_path)) == []
    captured = capsys.readouterr()
    assert "YAML inválido" in captured.out


def test_parse_output_con_error_escaneo_avisa(tmp_path, capsys):
    out = json.dumps(
        {
            "results": [],
            "errors": [{"code": 3, "message": "file was too big"}],
        }
    )
    assert make_scanner(tmp_path)._parse_output(out, str(tmp_path)) == []
    captured = capsys.readouterr()
    assert "errores de escaneo" in captured.out


def test_scan_usa_config_rules_dir(monkeypatch, tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "regla.yml").write_text("rules: []")

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeResult(stdout="{}")

    monkeypatch.setattr("vibeaudit.scanners.custom.subprocess.run", fake_run)
    monkeypatch.setattr(
        CustomRulesScanner, "is_installed", staticmethod(lambda: True)
    )
    scanner = CustomRulesScanner(repo_path=tmp_path, rules_dir=tmp_path / "rules")
    assert scanner.scan() == []
    assert "--config" in captured["cmd"]
    assert str(tmp_path / "rules") in captured["cmd"]


def test_scan_sin_resultados_stdout_vacio(monkeypatch, tmp_path):
    (tmp_path / "rules").mkdir()

    def fake_run(cmd, **kwargs):
        return FakeResult(stdout="")

    monkeypatch.setattr("vibeaudit.scanners.custom.subprocess.run", fake_run)
    monkeypatch.setattr(
        CustomRulesScanner, "is_installed", staticmethod(lambda: True)
    )
    scanner = CustomRulesScanner(repo_path=tmp_path, rules_dir=tmp_path / "rules")
    assert scanner.scan() == []


def test_scan_rules_dir_inexistente(tmp_path):
    scanner = CustomRulesScanner(
        repo_path=tmp_path, rules_dir=tmp_path / "no-existe"
    )
    with pytest.raises(ValueError):
        scanner.scan()


def test_scan_semgrep_no_instalado(monkeypatch, tmp_path):
    (tmp_path / "rules").mkdir()
    monkeypatch.setattr(
        CustomRulesScanner, "is_installed", staticmethod(lambda: False)
    )
    scanner = CustomRulesScanner(repo_path=tmp_path, rules_dir=tmp_path / "rules")
    with pytest.raises(RuntimeError):
        scanner.scan()


def test_scan_semgrep_exit_2_error(monkeypatch, tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "regla.yml").write_text("rules: []")

    def fake_run(cmd, **kwargs):
        return FakeResult(returncode=2, stderr="boom")

    monkeypatch.setattr("vibeaudit.scanners.custom.subprocess.run", fake_run)
    monkeypatch.setattr(
        CustomRulesScanner, "is_installed", staticmethod(lambda: True)
    )
    scanner = CustomRulesScanner(repo_path=tmp_path, rules_dir=tmp_path / "rules")
    with pytest.raises(RuntimeError):
        scanner.scan()


def test_is_installed_ausente(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("vibeaudit.scanners.custom.subprocess.run", fake_run)
    assert CustomRulesScanner.is_installed() is False


def test_is_installed_presente(monkeypatch):
    def fake_run(cmd, **kwargs):
        return FakeResult(returncode=0, stdout="1.2.3")

    monkeypatch.setattr("vibeaudit.scanners.custom.subprocess.run", fake_run)
    assert CustomRulesScanner.is_installed() is True


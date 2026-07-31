"""Tests de los scanners usando monkeypatch de subprocess.run."""

import subprocess

import pytest

from vibeaudit.models import Severity
from vibeaudit.scanners.checkov import CheckovScanner
from vibeaudit.scanners.gitleaks import GitleaksScanner
from vibeaudit.scanners.semgrep import SemgrepScanner


class FakeResult:
    """Imita el resultado de subprocess.run."""

    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def fake_run(monkeypatch, responses):
    """Sustituye subprocess.run por una función que responde según el argumento."""
    def _run(args, **kwargs):
        key = tuple(args[:2])
        return responses.get(key, responses.get("default", FakeResult(1)))

    monkeypatch.setattr("subprocess.run", _run)


GITLEAKS_JSON = (
    '[{"RuleID":"aws-access-token","StartLine":23,"File":"src/config.py"},'
    '{"RuleID":"generic-api-key","StartLine":5,"File":"app.js"}]'
)


class TestGitleaksScanner:
    def test_is_installed_true(self, monkeypatch):
        fake_run(monkeypatch, {("gitleaks", "version"): FakeResult(0, "8.18.0")})
        assert GitleaksScanner.is_installed() is True

    def test_is_installed_false_sin_binario(self, monkeypatch):
        def _raise(args, **kwargs):
            raise FileNotFoundError("no existe")

        monkeypatch.setattr("subprocess.run", _raise)
        assert GitleaksScanner.is_installed() is False

    def test_scan_con_hallazgos_exit_1(self, monkeypatch, tmp_path):
        fake_run(
            monkeypatch,
            {
                ("gitleaks", "version"): FakeResult(0, "8.18.0"),
                ("gitleaks", "detect"): FakeResult(1, GITLEAKS_JSON),
            },
        )
        secrets = GitleaksScanner(tmp_path).scan()

        assert len(secrets) == 2
        assert secrets[0].type == "aws-access-token"
        assert secrets[0].line == 23
        assert secrets[0].file == "src/config.py"
        assert secrets[0].severity == Severity.CRITICAL
        assert secrets[1].severity == Severity.HIGH

    def test_scan_sin_hallazgos_exit_0(self, monkeypatch, tmp_path):
        fake_run(
            monkeypatch,
            {
                ("gitleaks", "version"): FakeResult(0, "8.18.0"),
                ("gitleaks", "detect"): FakeResult(0, ""),
            },
        )
        assert GitleaksScanner(tmp_path).scan() == []

    def test_scan_sin_hallazgos_exit_1_json_vacio(self, monkeypatch, tmp_path):
        fake_run(
            monkeypatch,
            {
                ("gitleaks", "version"): FakeResult(0, "8.18.0"),
                ("gitleaks", "detect"): FakeResult(1, "[]"),
            },
        )
        assert GitleaksScanner(tmp_path).scan() == []

    def test_scan_error_exit_126(self, monkeypatch, tmp_path):
        fake_run(
            monkeypatch,
            {
                ("gitleaks", "version"): FakeResult(0, "8.18.0"),
                ("gitleaks", "detect"): FakeResult(126, "", "boom"),
            },
        )
        with pytest.raises(RuntimeError):
            GitleaksScanner(tmp_path).scan()

    def test_scan_no_instalado_lanza_runtimeerror(self, monkeypatch, tmp_path):
        fake_run(monkeypatch, {("gitleaks", "version"): FakeResult(1)})
        with pytest.raises(RuntimeError):
            GitleaksScanner(tmp_path).scan()


SEMGREP_JSON = (
    '{"results":['
    '{"check_id":"python.lang.security.eval","path":"app.py","start":{"line":42},'
    '"extra":{"severity":"ERROR","lines":"eval(x)"}},'
    '{"check_id":"python.lang.bad-xor","path":"lib.py","start":{"line":7},'
    '"extra":{"severity":"WARNING","lines":"a ^ b"}},'
    '{"check_id":"python.lang.info-rule","path":"info.py","start":{"line":1},'
    '"extra":{"severity":"INFO","lines":"x"}}'
    '],"errors":[]}'
)


class TestSemgrepScanner:
    def test_filtra_solo_high_critical(self, monkeypatch, tmp_path):
        fake_run(
            monkeypatch,
            {
                ("semgrep", "--version"): FakeResult(0, "1.100.0"),
                ("semgrep", "scan"): FakeResult(1, SEMGREP_JSON),
            },
        )
        vulns = SemgrepScanner(tmp_path).scan()

        assert len(vulns) == 1
        assert vulns[0].rule == "python.lang.security.eval"
        assert vulns[0].line == 42
        assert vulns[0].severity == Severity.HIGH
        assert vulns[0].snippet == "eval(x)"

    def test_sin_hallazgos_exit_0(self, monkeypatch, tmp_path):
        fake_run(
            monkeypatch,
            {
                ("semgrep", "--version"): FakeResult(0, "1.100.0"),
                ("semgrep", "scan"): FakeResult(0, '{"results":[],"errors":[]}'),
            },
        )
        assert SemgrepScanner(tmp_path).scan() == []

    def test_exit_2_es_error(self, monkeypatch, tmp_path):
        fake_run(
            monkeypatch,
            {
                ("semgrep", "--version"): FakeResult(0, "1.100.0"),
                ("semgrep", "scan"): FakeResult(2, "", "scan error"),
            },
        )
        with pytest.raises(RuntimeError, match="código 2"):
            SemgrepScanner(tmp_path).scan()

    def test_errores_de_escaneo_no_fallan(self, monkeypatch, tmp_path):
        fake_run(
            monkeypatch,
            {
                ("semgrep", "--version"): FakeResult(0, "1.100.0"),
                ("semgrep", "scan"): FakeResult(
                    0, '{"results":[],"errors":[{"message":"no files matched"}]}'
                ),
            },
        )
        assert SemgrepScanner(tmp_path).scan() == []


CHECKOV_JSON = (
    '{"results":{"failed_checks":['
    '{"check_id":"CKV_AWS_1","check_name":"IAM password policy",'
    '"file":"/tmp/repo/main.tf","file_line_range":[1,20],'
    '"repo_file_path":"/main.tf","severity":"HIGH"},'
    '{"check_id":"CKV_AWS_2","check_name":"Other",'
    '"file":"/tmp/repo/main.tf","file_line_range":[5,10],'
    '"repo_file_path":"/main.tf"}'
    ']}}'
)


class TestCheckovScanner:
    def test_sin_archivos_iac_devuelve_vacio(self, monkeypatch, tmp_path):
        (tmp_path / "not_iac.txt").write_text("hola")
        fake_run(monkeypatch, {("checkov", "--version"): FakeResult(0, "3.2.0")})
        assert CheckovScanner(tmp_path).scan() == []

    def test_scan_con_terraform(self, monkeypatch, tmp_path):
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        fake_run(
            monkeypatch,
            {
                ("checkov", "--version"): FakeResult(0, "3.2.0"),
                ("checkov", "-d"): FakeResult(0, CHECKOV_JSON),
            },
        )
        vulns = CheckovScanner(tmp_path).scan()

        assert len(vulns) == 2
        assert vulns[0].rule == "CKV_AWS_1"
        assert vulns[0].file == "/main.tf"
        assert vulns[0].line == 1
        assert vulns[0].severity == Severity.HIGH
        assert vulns[1].severity == Severity.HIGH

    def test_scan_con_warnings_exit_1_no_falla(self, monkeypatch, tmp_path):
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        fake_run(
            monkeypatch,
            {
                ("checkov", "--version"): FakeResult(0, "3.2.0"),
                ("checkov", "-d"): FakeResult(
                    1, CHECKOV_JSON, "WARNI unsupported instruction SET"
                ),
            },
        )
        vulns = CheckovScanner(tmp_path).scan()
        assert len(vulns) == 2

    def test_parse_formato_lista_checkov3(self, tmp_path):
        # Checkov 3.x devuelve una lista de check_types
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        raw = (
            '[{"check_type": "terraform", "results": {"failed_checks": ['
            '{"check_id": "CKV_AWS_1", "check_name": "x", "file": "/main.tf",'
            '"file_line_range": [1, 2], "repo_file_path": "/main.tf", "severity": "HIGH"}'
            ']}},'
            '{"check_type": "github_actions", "results": {"failed_checks": ['
            '{"check_id": "CKV_GHA_7", "check_name": "y", "file": "/ci.yml",'
            '"file_line_range": [3, 4], "repo_file_path": "/.github/workflows/ci.yml",'
            '"severity": "CRITICAL"}'
            ']}}]'
        )
        vulns = CheckovScanner(tmp_path)._parse_output(raw)
        assert len(vulns) == 2
        assert vulns[0].rule == "CKV_AWS_1"
        assert vulns[1].rule == "CKV_GHA_7"
        assert vulns[1].severity == Severity.CRITICAL

    def test_scan_exit_2_es_error(self, monkeypatch, tmp_path):
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        fake_run(
            monkeypatch,
            {
                ("checkov", "--version"): FakeResult(0, "3.2.0"),
                ("checkov", "-d"): FakeResult(2, "", "boom"),
            },
        )
        with pytest.raises(RuntimeError):
            CheckovScanner(tmp_path).scan()

    def test_detecta_k8s_por_contenido(self, tmp_path):
        (tmp_path / "deployment.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\n"
        )
        scanner = CheckovScanner(tmp_path)
        assert scanner._find_iac_files() == ["deployment.yaml"]

    def test_no_detecta_yaml_plano(self, tmp_path):
        (tmp_path / "config.yaml").write_text("key: value\n")
        scanner = CheckovScanner(tmp_path)
        assert scanner._find_iac_files() == []

    def test_checkov_instalado(self, monkeypatch):
        fake_run(monkeypatch, {("checkov", "--version"): FakeResult(0, "3.2.0")})
        assert CheckovScanner.is_installed() is True

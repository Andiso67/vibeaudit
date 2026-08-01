"""Tests de los scanners usando monkeypatch de subprocess.run."""

import subprocess
from pathlib import Path

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


class RunRecorder:
    """Registra las llamadas a subprocess.run para inspección en tests."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        key = tuple(args[:2])
        return self.responses.get(key, self.responses.get("default", FakeResult(1)))


def fake_run(monkeypatch, responses):
    """Sustituye subprocess.run por un recorder que responde según el argumento."""
    recorder = RunRecorder(responses)
    monkeypatch.setattr("subprocess.run", recorder)
    return recorder


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

    @staticmethod
    def _fake_run_con_reporte(monkeypatch, returncode, payload, stderr=""):
        """Fake de subprocess.run que escribe el reporte en el tempfile."""

        def _run(args, **kwargs):
            if args[0] == "gitleaks" and args[1] == "version":
                return FakeResult(0, "8.18.0")
            report_idx = args.index("--report-path") + 1
            Path(args[report_idx]).write_text(payload)
            return FakeResult(returncode, "", stderr)

        monkeypatch.setattr("subprocess.run", _run)

    def test_scan_con_hallazgos_exit_1(self, monkeypatch, tmp_path):
        self._fake_run_con_reporte(
            monkeypatch, 1, GITLEAKS_JSON, "WRN leaks found: 2"
        )
        secrets = GitleaksScanner(tmp_path).scan()

        assert len(secrets) == 2
        assert secrets[0].type == "aws-access-token"
        assert secrets[0].line == 23
        assert secrets[0].file == "src/config.py"
        assert secrets[0].severity == Severity.CRITICAL
        assert secrets[1].severity == Severity.HIGH

    def test_scan_sin_hallazgos_exit_0(self, monkeypatch, tmp_path):
        self._fake_run_con_reporte(monkeypatch, 0, "[]")
        assert GitleaksScanner(tmp_path).scan() == []

    def test_scan_sin_hallazgos_exit_1_json_vacio(self, monkeypatch, tmp_path):
        self._fake_run_con_reporte(monkeypatch, 1, "[]", "WRN leaks found: 0")
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

    def test_scan_exit_1_con_ftl_es_error(self, monkeypatch, tmp_path):
        self._fake_run_con_reporte(
            monkeypatch,
            1,
            "",
            "FTL Report path is not writable: /dev/stdout permission denied",
        )
        with pytest.raises(RuntimeError, match="Gitleaks falló"):
            GitleaksScanner(tmp_path).scan()

    def test_scan_sin_archivo_reporte_devuelve_vacio(self, monkeypatch, tmp_path):
        def _run(args, **kwargs):
            if args[0] == "gitleaks" and args[1] == "version":
                return FakeResult(0, "8.18.0")
            return FakeResult(0, "")

        monkeypatch.setattr("subprocess.run", _run)
        assert GitleaksScanner(tmp_path).scan() == []

    def test_scan_sin_commits_usa_no_git(self, monkeypatch, tmp_path):
        (tmp_path / ".git").mkdir()
        calls = []

        def _run(args, **kwargs):
            calls.append(args)
            if args[0] == "gitleaks" and args[1] == "version":
                return FakeResult(0, "8.18.0")
            if args[0] == "git":
                return FakeResult(128, "", "fatal: ambiguous argument 'HEAD'")
            report_idx = args.index("--report-path") + 1
            Path(args[report_idx]).write_text("[]")
            return FakeResult(0, "")

        monkeypatch.setattr("subprocess.run", _run)
        GitleaksScanner(tmp_path).scan()
        detect = next(a for a in calls if a[0] == "gitleaks" and a[1] == "detect")
        assert "--no-git" in detect

    def test_scan_con_commits_no_usa_no_git(self, monkeypatch, tmp_path):
        (tmp_path / ".git").mkdir()
        calls = []

        def _run(args, **kwargs):
            calls.append(args)
            if args[0] == "gitleaks" and args[1] == "version":
                return FakeResult(0, "8.18.0")
            if args[0] == "git":
                return FakeResult(0, "abc123")
            report_idx = args.index("--report-path") + 1
            Path(args[report_idx]).write_text("[]")
            return FakeResult(0, "")

        monkeypatch.setattr("subprocess.run", _run)
        GitleaksScanner(tmp_path).scan()
        detect = next(a for a in calls if a[0] == "gitleaks" and a[1] == "detect")
        assert "--no-git" not in detect

    def test_scan_no_instalado_lanza_runtimeerror(self, monkeypatch, tmp_path):
        fake_run(monkeypatch, {("gitleaks", "version"): FakeResult(1)})
        with pytest.raises(RuntimeError):
            GitleaksScanner(tmp_path).scan()

    def test_parse_salida_malformada_no_crash(self, tmp_path):
        scanner = GitleaksScanner(tmp_path)
        cases = [
            "[1, 2, 3]",
            '"no es lista"',
            '[{"RuleID": null, "File": "a.py", "StartLine": 1}]',
            '[{"RuleID": "generic", "File": null, "StartLine": 1}]',
            '[{"RuleID": "generic", "File": "a.py", "StartLine": 0}]',
            '[{"RuleID": "generic", "File": "a.py", "StartLine": null}]',
            '[{"RuleID": "generic", "File": "a.py", "StartLine": 1}, "basura"]',
        ]
        for raw in cases:
            assert scanner._parse_output(raw) is not None

    def test_parse_salida_malformada_conserva_validos(self, tmp_path):
        raw = (
            '[{"RuleID": null, "File": null, "StartLine": 0},'
            '{"RuleID": "aws-access-token", "File": "a.py", "StartLine": 7}]'
        )
        secrets = GitleaksScanner(tmp_path)._parse_output(raw)
        assert len(secrets) == 1
        assert secrets[0].type == "aws-access-token"
        assert secrets[0].line == 7
        assert secrets[0].severity == Severity.CRITICAL

    def test_parse_ruta_absoluta_se_relativiza_al_repo(self, tmp_path):
        raw = (
            f'[{{"RuleID": "aws-access-token", "File": "{tmp_path}/app.py",'
            f'"StartLine": 3}}]'
        )
        secrets = GitleaksScanner(tmp_path)._parse_output(raw)
        assert secrets[0].file == "app.py"

    def test_parse_ruta_fuera_del_repo_se_conserva(self, tmp_path):
        raw = (
            f'[{{"RuleID": "generic", "File": "{tmp_path}/../externo.py",'
            f'"StartLine": 3}}]'
        )
        secrets = GitleaksScanner(tmp_path)._parse_output(raw)
        assert secrets[0].file == f"{tmp_path}/../externo.py"


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

    def test_scan_exit_raro_stdout_vacio_avisa(self, monkeypatch, tmp_path, capsys):
        fake_run(
            monkeypatch,
            {
                ("semgrep", "--version"): FakeResult(0, "1.100.0"),
                ("semgrep", "scan"): FakeResult(7, "", "config inválido"),
            },
        )
        assert SemgrepScanner(tmp_path).scan() == []
        assert "config inválido" in capsys.readouterr().out

    def test_parse_salida_malformada_no_crash(self, tmp_path):
        scanner = SemgrepScanner(tmp_path)
        cases = [
            "[1, 2, 3]",
            '{"results": null, "errors": []}',
            '{"results": [{"check_id": "x", "path": "a.py", "start": {"line": 1}, '
            '"extra": null}], "errors": []}',
            '{"results": [{"check_id": "x", "path": "a.py", "start": {"line": 1}, '
            '"extra": {}}], "errors": []}',
            '{"results": [{"check_id": "x", "path": "a.py", "start": {"line": 0}, '
            '"extra": {"severity": "ERROR"}}], "errors": []}',
            '{"results": [{"check_id": "x", "path": null, "start": {"line": 1}, '
            '"extra": {"severity": "ERROR"}}], "errors": []}',
            '{"results": [{"check_id": null, "path": "a.py", "start": {"line": 1}, '
            '"extra": {"severity": "ERROR"}}], "errors": []}',
            '{"results": [{"check_id": "x", "path": "a.py", "start": {"line": 1}, '
            '"extra": {"severity": "ERROR", "lines": [1, 2]}}], "errors": []}',
            '{"results": ["zzz"], "errors": []}',
        ]
        for raw in cases:
            assert scanner._parse_output(raw) is not None

    def test_parse_salida_malformada_conserva_validos(self, tmp_path):
        raw = (
            '{"results": ['
            '{"check_id": null, "path": null, "start": {"line": 0}, "extra": {}},'
            '{"check_id": "python.lang.security.eval", "path": "app.py", '
            '"start": {"line": 9}, "extra": {"severity": "ERROR", "lines": "eval(x)"}}'
            '], "errors": []}'
        )
        vulns = SemgrepScanner(tmp_path)._parse_output(raw)
        assert len(vulns) == 1
        assert vulns[0].rule == "python.lang.security.eval"
        assert vulns[0].line == 9
        assert vulns[0].severity == Severity.HIGH


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

    def test_detecta_templates_cfn_con_type_dict(self, tmp_path):
        # Template con Fn::Rain::Module (Type como dict) rompe checkov 3.3.x
        template = tmp_path / "vpc.yaml"
        template.write_text(
            "AWSTemplateFormatVersion: '2010-09-09'\n"
            "Resources:\n"
            "  Network:\n"
            "    Type: !Rain::Module '../../RainModules/vpc.yml'\n"
        )
        scanner = CheckovScanner(tmp_path)
        assert scanner._find_unsupported_cfn_files() == ["vpc.yaml"]

    def test_no_detecta_templates_cfn_normales(self, tmp_path):
        (tmp_path / "bucket.yaml").write_text(
            "AWSTemplateFormatVersion: '2010-09-09'\n"
            "Resources:\n"
            "  Bucket:\n"
            "    Type: AWS::S3::Bucket\n"
        )
        scanner = CheckovScanner(tmp_path)
        assert scanner._find_unsupported_cfn_files() == []

    def test_scan_agrega_skip_path(self, monkeypatch, tmp_path):
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        (tmp_path / "vpc.yaml").write_text(
            "AWSTemplateFormatVersion: '2010-09-09'\n"
            "Resources:\n"
            "  Network:\n"
            "    Type: !Rain::Module '../../RainModules/vpc.yml'\n"
        )
        recorder = fake_run(
            monkeypatch,
            {
                ("checkov", "--version"): FakeResult(0, "3.2.0"),
                ("checkov", "-d"): FakeResult(0, CHECKOV_JSON),
            },
        )
        CheckovScanner(tmp_path).scan()
        scan_cmd = recorder.calls[-1]
        assert "--skip-path" in scan_cmd
        assert "vpc.yaml" in scan_cmd

    def test_parse_salida_malformada_no_crash(self, tmp_path):
        scanner = CheckovScanner(tmp_path)
        cases = [
            "[1, 2, 3]",
            '[{"results": {"failed_checks": null}}]',
            '[{"results": null}]',
            '[{"results": {"failed_checks": [{"check_id": "C1", '
            '"repo_file_path": "/r/a.py", "file_line_range": [], "severity": "HIGH"}]}}]',
            '[{"results": {"failed_checks": [{"check_id": "C1", '
            '"repo_file_path": null, "file": null, "file_line_range": [3, 4], '
            '"severity": "HIGH"}]}}]',
            '[{"results": {"failed_checks": [{"check_id": null, '
            '"repo_file_path": "/r/a.py", "file_line_range": [3, 4], '
            '"severity": "HIGH"}]}}]',
            '[{"results": {"failed_checks": ["zzz"]}}]',
            '[{"results": {"failed_checks": [{"check_id": "C1", '
            '"repo_file_path": "/r/a.py", "file_line_range": [3, 4], '
            '"severity": 123}]}}]',
            '[{"results": {"failed_checks": [{"check_id": "C1", '
            '"repo_file_path": "/r/a.py", "file_line_range": [3, 4], '
            '"severity": "HIGH", "check_name": [1, 2]}]}}]',
        ]
        for raw in cases:
            assert scanner._parse_output(raw) is not None

    def test_parse_salida_malformada_conserva_validos(self, tmp_path):
        raw = (
            '[{"results": {"failed_checks": ['
            '{"check_id": null, "repo_file_path": null, "file_line_range": [], '
            '"severity": null},'
            '{"check_id": "CKV_AWS_1", "repo_file_path": "/main.tf", '
            '"file_line_range": [1, 20], "severity": "LOW"}'
            ']}}]'
        )
        vulns = CheckovScanner(tmp_path)._parse_output(raw)
        assert len(vulns) == 1
        assert vulns[0].rule == "CKV_AWS_1"
        assert vulns[0].line == 1
        assert vulns[0].severity == Severity.LOW

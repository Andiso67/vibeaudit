"""Tests de AuditReporter."""

import json
import re

from vibeaudit.models import (
    AuditReport,
    DependencyVulnerability,
    Metrics,
    ProjectMetadata,
    Secret,
    Severity,
    Vulnerability,
)
from vibeaudit.reporter import AuditReporter


def make_repo(tmp_path):
    """Crea un repo con código, tests y un archivo no contable."""
    (tmp_path / "app.py").write_text("a = 1\nb = 2\nc = 3\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("x = 1\ny = 2\n")
    (tmp_path / "data.txt").write_text("uno\ndos\ntres\ncuatro\ncinco\n")
    return tmp_path


def make_reporter(repo_path, extra_issues=None, cicd_issues=None):
    return AuditReporter(
        project=ProjectMetadata(name="demo", iac_files=["main.tf"]),
        vulnerabilities=[
            Vulnerability(rule="r1", file="app.py", line=1, severity=Severity.HIGH),
            Vulnerability(rule="r2", file="app.py", line=2, severity=Severity.CRITICAL),
        ],
        secrets=[
            Secret(type="aws", file="c.py", line=2, severity=Severity.CRITICAL)
        ],
        iac_issues=extra_issues
        or [
            Vulnerability(rule="ckv", file="main.tf", line=3, severity=Severity.MEDIUM)
        ],
        cicd_issues=cicd_issues or [],
        repo_path=repo_path,
    )


class TestAuditReporter:
    def test_metricas_loc_y_tests(self, tmp_path):
        repo = make_repo(tmp_path)
        report = make_reporter(repo).build()

        assert report.metrics.lines_of_code == 5
        assert report.metrics.test_files == 1

    def test_metricas_ignoran_venv_y_node_modules(self, tmp_path):
        make_repo(tmp_path)
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "site-packages").mkdir(parents=True)
        (tmp_path / ".venv" / "site-packages" / "dependencia.py").write_text("a = 1\n" * 500)
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "paquete.js").write_text("b = 2\n" * 300)
        (tmp_path / ".venv" / "site-packages" / "test_x.py").write_text("c = 3\n")

        report = make_reporter(tmp_path).build()

        assert report.metrics.lines_of_code == 5
        assert report.metrics.test_files == 1

    def test_conteo_por_severidad(self, tmp_path):
        repo = make_repo(tmp_path)
        report = make_reporter(repo).build()

        assert report.metrics.vulnerabilities_by_severity == {
            "HIGH": 1,
            "CRITICAL": 1,
            "MEDIUM": 1,
        }

    def test_build_cachea_el_reporte(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = make_reporter(repo)

        first = reporter.build()
        second = reporter.build()

        assert first is second

    def test_to_json_usa_aliases_camelcase(self, tmp_path):
        repo = make_repo(tmp_path)
        data = json.loads(make_reporter(repo).to_json())

        assert data["project"]["name"] == "demo"
        assert data["project"]["iacFiles"] == ["main.tf"]
        assert "linesOfCode" in data["metrics"]
        assert "vulnerabilitiesBySeverity" in data["metrics"]
        assert "iacIssues" in data

    def test_cicd_issues_en_json(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = make_reporter(
            repo,
            cicd_issues=[
                Vulnerability(
                    rule="cicd-github-pr-target-no-permissions",
                    file=".github/workflows/ci.yml",
                    line=3,
                    severity=Severity.HIGH,
                )
            ],
        )
        data = json.loads(reporter.to_json())
        assert len(data["cicdIssues"]) == 1
        assert data["cicdIssues"][0]["rule"] == "cicd-github-pr-target-no-permissions"

    def test_sin_cicd_issues_campo_vacio(self, tmp_path):
        repo = make_repo(tmp_path)
        data = json.loads(make_reporter(repo).to_json())
        assert data["cicdIssues"] == []

    def test_custom_issues_en_json(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = AuditReporter(
            project=ProjectMetadata(name="demo", iac_files=["main.tf"]),
            vulnerabilities=[],
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            custom_issues=[
                Vulnerability(
                    rule="custom.no-sql-select-star",
                    file="app.py",
                    line=3,
                    severity=Severity.MEDIUM,
                )
            ],
            repo_path=repo,
        )
        data = json.loads(reporter.to_json())
        assert len(data["customIssues"]) == 1
        assert data["customIssues"][0]["rule"] == "custom.no-sql-select-star"
        assert data["customIssues"][0]["severity"] == "MEDIUM"

    def test_sin_custom_issues_campo_vacio(self, tmp_path):
        repo = make_repo(tmp_path)
        data = json.loads(make_reporter(repo).to_json())
        assert data["customIssues"] == []

    def test_save_to_file(self, tmp_path):
        repo = make_repo(tmp_path)
        out = tmp_path / "out" / "report.json"
        make_reporter(repo).save_to_file(out)

        data = json.loads(out.read_text())
        assert data["project"]["name"] == "demo"

    def test_sin_repo_path_loc_cero(self, tmp_path):
        report = make_reporter(None).build()
        assert report.metrics.lines_of_code == 0
        assert report.metrics.test_files == 0


def make_reporter_con_deps(repo_path):
    """Reporter con vulnerabilidades de dependencias para reportes legibles."""
    return AuditReporter(
        project=ProjectMetadata(
            name="demo",
            repository_url="https://github.com/demo/demo",
            default_branch="main",
            commit_hash="a" * 40,
        ),
        vulnerabilities=[
            Vulnerability(
                rule="python.lang.security.eval",
                file="app.py",
                line=42,
                severity=Severity.HIGH,
                snippet="eval(x)",
            )
        ],
        secrets=[Secret(type="aws", file="c.py", line=2, severity=Severity.CRITICAL)],
        iac_issues=[],
        cicd_issues=[],
        dependency_vulnerabilities=[
            DependencyVulnerability(
                name="axios",
                ecosystem="npm",
                version="0.21.1",
                direct=True,
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                fixed_version="0.31.1",
                cve_ids=["CVE-2021-3749"],
                summary="Prototype pollution",
            )
        ],
        repo_path=repo_path,
    )


class TestReportesLegibles:
    def test_save_markdown_incluye_secciones(self, tmp_path):
        repo = make_repo(tmp_path)
        out = tmp_path / "report.md"
        make_reporter_con_deps(repo).save_markdown(out)
        content = out.read_text()

        assert "# Auditoría de demo" in content
        assert "**Repositorio**: https://github.com/demo/demo" in content
        assert "## Vulnerabilidades (SAST)" in content
        assert "`python.lang.security.eval` — **HIGH** — app.py:42" in content
        assert "eval(x)" in content
        assert "## Dependencias con CVEs" in content
        assert "axios@0.21.1 (npm) — **CRITICAL**" in content
        assert "corregida en 0.31.1" in content
        assert "CVE-2021-3749" in content
        assert "## Métricas" in content

    def test_save_markdown_sin_hallazgos(self, tmp_path):
        repo = make_repo(tmp_path)
        out = tmp_path / "report.md"
        AuditReporter(
            project=ProjectMetadata(name="demo"),
            repo_path=repo,
        ).save_markdown(out)
        content = out.read_text()

        assert "No se encontraron hallazgos." in content
        assert "| **Total** | **0** |" in content

    def test_save_html_incluye_tablas(self, tmp_path):
        repo = make_repo(tmp_path)
        out = tmp_path / "report.html"
        make_reporter_con_deps(repo).save_html(out)
        content = out.read_text()

        assert "<!DOCTYPE html>" in content
        assert "<title>Auditoría de demo</title>" in content
        assert "python.lang.security.eval" in content
        assert "CVE-2021-3749" in content
        assert "corregida en <code>0.31.1</code>" in content
        assert "app.py:42" in content
        assert '<span class="badge" style="background: #ea580c;">HIGH</span>' in content

    def test_save_html_sin_hallazgos(self, tmp_path):
        repo = make_repo(tmp_path)
        out = tmp_path / "report.html"
        AuditReporter(
            project=ProjectMetadata(name="demo"),
            repo_path=repo,
        ).save_html(out)
        content = out.read_text()

        assert "<!DOCTYPE html>" in content
        assert content.count("No se encontraron hallazgos.") >= 6

    def test_save_html_escapa_codigo_peligroso(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = AuditReporter(
            project=ProjectMetadata(name="x"),
            vulnerabilities=[
                Vulnerability(
                    rule='"><script>alert(1)</script>',
                    file="app.py",
                    line=1,
                    severity=Severity.HIGH,
                    snippet="<script>alert('x')</script>",
                )
            ],
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            repo_path=repo,
        )
        out = tmp_path / "report.html"
        reporter.save_html(out)
        content = out.read_text()

        assert "<script>alert(1)</script>" not in content
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content

    def test_save_markdown_y_html_crean_directorios_padre(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = make_reporter(repo)
        md = tmp_path / "out" / "report.md"
        html_file = tmp_path / "out" / "report.html"
        reporter.save_markdown(md)
        reporter.save_html(html_file)
        assert md.exists()
        assert html_file.exists()

    def test_save_markdown_snippet_con_triple_backtick_no_rompe_fence(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = AuditReporter(
            project=ProjectMetadata(name="demo"),
            vulnerabilities=[
                Vulnerability(
                    rule="r1",
                    file="app.py",
                    line=1,
                    severity=Severity.HIGH,
                    snippet='print("""\n```\nmarkdown\n```\n""")',
                )
            ],
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            repo_path=repo,
        )
        out = tmp_path / "report.md"
        reporter.save_markdown(out)
        content = out.read_text()

        assert content.count("```") % 2 == 0
        assert "````" in content

    def test_save_markdown_rule_con_backticks_no_rompe_inline_code(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = AuditReporter(
            project=ProjectMetadata(name="demo"),
            vulnerabilities=[
                Vulnerability(
                    rule="rule`con`ticks",
                    file="a.py",
                    line=1,
                    severity=Severity.MEDIUM,
                    snippet=None,
                )
            ],
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            repo_path=repo,
        )
        out = tmp_path / "report.md"
        reporter.save_markdown(out)
        content = out.read_text()

        assert "``rule`con`ticks``" in content

    def test_save_markdown_snippet_con_fence_y_blank_line(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = AuditReporter(
            project=ProjectMetadata(name="demo"),
            vulnerabilities=[
                Vulnerability(
                    rule="test-rule",
                    file="a.py",
                    line=1,
                    severity=Severity.HIGH,
                    snippet="print('x')",
                )
            ],
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            repo_path=repo,
        )
        out = tmp_path / "report.md"
        reporter.save_markdown(out)
        content = out.read_text()

        assert "\n\n```\nprint('x')\n```" in content

    @staticmethod
    def _embedded_json(content):
        """Extrae y parsea el JSON embebido en el dashboard."""
        marker = 'type="application/json">'
        start = content.index(marker) + len(marker)
        end = content.index("</script>", start)
        return json.loads(content[start:end])

    def test_save_dashboard_incluye_datos_embebidos(self, tmp_path):
        repo = make_repo(tmp_path)
        out = tmp_path / "dashboard.html"
        make_reporter_con_deps(repo).save_dashboard(out)
        content = out.read_text()

        assert "<!DOCTYPE html>" in content
        assert "<title>Dashboard — demo</title>" in content
        assert 'type="application/json"' in content
        assert "id=\"filter\"" in content
        assert "severity-bars" in content

        data = self._embedded_json(content)
        assert data["project"]["name"] == "demo"
        assert data["vulnerabilities"][0]["rule"] == "python.lang.security.eval"
        assert data["metrics"]["dependencyVulnerabilities"][0]["cveIds"] == [
            "CVE-2021-3749"
        ]

    def test_save_dashboard_sin_hallazgos(self, tmp_path):
        repo = make_repo(tmp_path)
        out = tmp_path / "dashboard.html"
        AuditReporter(
            project=ProjectMetadata(name="demo"),
            repo_path=repo,
        ).save_dashboard(out)
        content = out.read_text()

        assert "<!DOCTYPE html>" in content
        assert "No se encontraron hallazgos." in content
        assert self._embedded_json(content)["vulnerabilities"] == []

    def test_save_dashboard_escapa_secuencias_peligrosas(self, tmp_path):
        repo = make_repo(tmp_path)
        reporter = AuditReporter(
            project=ProjectMetadata(name="x"),
            vulnerabilities=[
                Vulnerability(
                    rule='</script><script>alert(1)</script>',
                    file="app.py",
                    line=1,
                    severity=Severity.HIGH,
                    snippet="<!-- payload -->",
                )
            ],
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            repo_path=repo,
        )
        out = tmp_path / "dashboard.html"
        reporter.save_dashboard(out)
        content = out.read_text()

        assert "</script><script>alert(1)" not in content
        assert "<\\/script>" in content
        assert "<\\u0021--" in content
        data = self._embedded_json(content)
        assert data["vulnerabilities"][0]["snippet"] == "<!-- payload -->"

    def test_save_dashboard_crea_directorios_padre(self, tmp_path):
        repo = make_repo(tmp_path)
        out = tmp_path / "out" / "nested" / "dashboard.html"
        make_reporter(repo).save_dashboard(out)
        assert out.exists()

    def test_print_summary_total_incluye_secretos(self, tmp_path, capsys):
        repo = make_repo(tmp_path)
        reporter = AuditReporter(
            project=ProjectMetadata(name="demo"),
            vulnerabilities=[
                Vulnerability(rule="r1", file="a.py", line=1, severity=Severity.HIGH)
            ],
            secrets=[
                Secret(type="aws", file="b.py", line=2, severity=Severity.CRITICAL),
                Secret(type="generic", file="c.py", line=3, severity=Severity.HIGH),
            ],
            iac_issues=[
                Vulnerability(rule="ckv1", file="main.tf", line=1, severity=Severity.MEDIUM)
            ],
            cicd_issues=[],
            custom_issues=[],
            repo_path=repo,
        )
        reporter.print_summary()
        output = capsys.readouterr().out

        def count_of(row_name):
            for line in output.splitlines():
                if row_name in line:
                    return int(re.search(r"\d+", line.split(row_name)[1]).group())
            raise AssertionError(f"Fila no encontrada: {row_name}")

        assert count_of("Secretos filtrados") == 2
        assert count_of("Total de hallazgos") == 4

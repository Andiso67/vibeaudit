"""Tests del generador de entregables (C4, roadmap, backlog) sin red."""

import csv
import io
import json

from vibeaudit.deliverables import (
    DeliverablesGenerator,
    PHASE_BY_SEVERITY,
    PHASE_DESCRIPTIONS,
)
from vibeaudit.models import (
    AuditReport,
    CloudIssue,
    CloudResource,
    LLMFinding,
    Metrics,
    ProjectMetadata,
    Secret,
    Severity,
    Vulnerability,
)


def sample_report() -> AuditReport:
    project = ProjectMetadata(name="demo-repo", languages=["python"])
    return AuditReport(
        project=project,
        vulnerabilities=[
            Vulnerability(
                rule="python.eval.usage",
                file="src/app.py",
                line=12,
                severity=Severity.CRITICAL,
                snippet="eval(user_input)",
            )
        ],
        secrets=[
            Secret(type="aws-access-token", file=".env", line=3, severity=Severity.HIGH)
        ],
        iac_issues=[
            Vulnerability(
                rule="CKV_AWS_20",
                file="main.tf",
                line=4,
                severity=Severity.HIGH,
                snippet="s3 bucket",
            )
        ],
        cloud_issues=[
            CloudIssue(
                provider="aws",
                rule="aws-s3-bucket-public",
                resource="s3://corp-assets",
                resource_type="s3-bucket",
                severity=Severity.HIGH,
                description="ACL público",
                recommendation="Bloquear acceso público",
            )
        ],
        llm_findings=[
            LLMFinding(
                title="IAM sin principio de menor privilegio",
                severity=Severity.MEDIUM,
                checklist_ref="waf.iam-least-privilege",
            )
        ],
        metrics=Metrics(),
    )


class TestC4Diagrams:
    def test_context_es_mermaid_fenced(self):
        report = sample_report()
        gen = DeliverablesGenerator(report)
        context = gen.c4_context()
        assert context.startswith("```mermaid")
        assert context.endswith("```")
        assert "demo-repo" in context  # nombre del proyecto auditado
        assert "Usuarios del servicio" in context

    def test_container_enumera_contenedores_del_cliente(self):
        gen = DeliverablesGenerator(sample_report())
        diagram = gen.c4_container()
        assert "demo-repo" in diagram
        assert "Aplicación" in diagram
        assert "subgraph" in diagram

    def test_diagramas_reflejan_tecnologias_detectadas(self):
        report = AuditReport(
            project=ProjectMetadata(
                name="golf-tracker",
                frameworks=["Next.js"],
                iac_files=["Dockerfile", "docker-compose.yml"],
                repository_url="https://github.com/Andiso67/golf-tracker.git",
            ),
            cloud_resources=[
                CloudResource(
                    provider="aws",
                    resource_type="s3-bucket",
                    resource="s3://bucket",
                    region="us-east-1",
                )
            ],
            metrics=Metrics(lines_of_code=10),
        )
        gen = DeliverablesGenerator(report)
        context = gen.c4_context()
        assert "Aplicación web Next.js" in context
        assert "Amazon Web Services" in context
        assert "S3" in context
        assert "GitHub" in context
        assert "VibeAudit" not in context  # ya no describe el proceso propio
        container = gen.c4_container()
        assert "Amazon S3" in container
        assert "Docker" in container


class TestBacklog:
    def test_csv_tiene_cabecera_y_filas(self, tmp_path):
        gen = DeliverablesGenerator(sample_report())
        content = gen.backlog_csv()
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        assert reader.fieldnames == [
            "id", "seccion", "regla", "archivo", "linea", "severidad", "fase", "recomendacion"
        ]
        assert len(rows) == 5  # SAST + secrets + iac + cloud + llm
        by_rule = {r["regla"] for r in rows}
        assert "python.eval.usage" in by_rule
        kinds = {r["seccion"] for r in rows}
        assert kinds == {"sast", "secrets", "iac", "cloud", "llm"}

    def test_json_incluye_hallazgos_y_fases(self, tmp_path):
        gen = DeliverablesGenerator(sample_report())
        payload = json.loads(gen.backlog_json())
        assert payload["project"] == "demo-repo"
        assert payload["fases"] == {str(k): v for k, v in PHASE_DESCRIPTIONS.items()}
        assert len(payload["hallazgos"]) == 5
        assert payload["resumen_por_seccion"]["sast"] == 1

    def test_fase_segun_severidad(self):
        assert PHASE_BY_SEVERITY["CRITICAL"] == 1
        assert PHASE_BY_SEVERITY["HIGH"] == 1
        assert PHASE_BY_SEVERITY["MEDIUM"] == 2
        assert PHASE_BY_SEVERITY["LOW"] == 3

    def test_roadmap_agrupa_por_fase(self, tmp_path):
        gen = DeliverablesGenerator(sample_report())
        md = gen.roadmap_markdown()
        assert "## Fase 1" in md
        assert "## Fase 2" in md
        assert "## Fase 3" in md
        assert "Sin hallazgos en esta fase." in md  # fase 3 vacía en el sample


class TestGenerate:
    def test_generate_escribe_9_archivos(self, tmp_path):
        out = tmp_path / "entregables"
        gen = DeliverablesGenerator(sample_report())
        files = gen.generate(out)
        assert set(files) == {
            "c4-context.mmd",
            "c4-container.mmd",
            "roadmap.md",
            "backlog.csv",
            "backlog.json",
            "informe-central.md",
            "informe-central.html",
            "informe-ejecutivo.html",
            "informe-ejecutivo.pdf",
        }
        assert (out / "c4-context.mmd").exists()
        assert (out / "informe-central.html").exists()
        assert out.is_dir()

    def test_informe_ejecutivo_html_no_incluye_secretos(self, tmp_path):
        gen = DeliverablesGenerator(sample_report())
        html_content = gen.informe_ejecutivo_html()
        assert "Informe ejecutivo" in html_content
        assert "AKIA" not in html_content
        assert "ghp_" not in html_content
        assert "contraseña" not in html_content.lower()

    def test_informe_ejecutivo_pdf_genera_bytes_validos(self, tmp_path):
        gen = DeliverablesGenerator(sample_report())
        pdf = gen.informe_ejecutivo_pdf()
        assert pdf[:5] == b"%PDF-"
        assert len(pdf) > 1000

    def test_self_publish_copia_reporte_e_informe(self, tmp_path):
        from vibeaudit.cli import self_publish

        gen = DeliverablesGenerator(sample_report())
        gen.generate(tmp_path / "entregables")
        webroot = tmp_path / "webroot"
        self_publish(
            webroot,
            sample_report(),
            deliverables=tmp_path / "entregables",
        )
        pub = webroot / "public"
        assert (pub / "audit-report.json").exists()
        assert (pub / "deliverables" / "informe-central.html").exists()
        assert (pub / "deliverables" / "backlog.csv").exists()


class TestInformeCentral:
    def test_markdown_reune_todos_los_entregables(self, tmp_path):
        gen = DeliverablesGenerator(sample_report())
        md = gen.informe_markdown()
        assert "# Informe central — demo-repo" in md
        assert "## 2. Resumen ejecutivo" in md
        assert "## 3. Diagrama C4 — Contexto" in md
        assert "## 4. Diagrama C4 — Contenedores" in md
        assert "## 5. Roadmap de remediación por fases" in md
        assert "## 6. Backlog de remediación" in md
        assert "## 7. Entregables descargables" in md
        assert "[`backlog.csv`](./backlog.csv)" in md
        assert "```mermaid" in md  # embebe el diagrama C4

    def test_html_embebe_tablas_y_escapa_contenido(self):
        gen = DeliverablesGenerator(sample_report())
        page = gen.informe_html()
        assert "<html" in page and "</html>" in page
        assert "Datos del proyecto" in page
        assert "python.eval.usage" in page
        assert '<span style=' in page  # pills de severidad
        assert 'class="mermaid"' in page  # diagramas C4 renderizados vía mermaid.js
        assert "mermaid.min.js" in page
        assert "flowchart" in page

    def test_html_roadmap_por_fases_y_enlaces(self):
        gen = DeliverablesGenerator(sample_report())
        page = gen.informe_html()
        assert "<h3>Fase 1</h3>" in page
        assert "<h3>Fase 2</h3>" in page
        assert "<h3>Fase 3</h3>" in page
        assert "Sin hallazgos en esta fase" in page  # fase 3 vacía en el sample
        assert "Entregables descargables" in page
        assert "backlog.csv" in page and "backlog.json" in page
        assert "roadmap.md" in page and "c4-context.mmd" in page

    def test_html_backlog_no_trunca_recomendacion(self):
        report = AuditReport(
            project=ProjectMetadata(name="repo"),
            vulnerabilities=[
                Vulnerability(
                    rule="x.y",
                    file="a.py",
                    line=1,
                    severity=Severity.HIGH,
                    snippet="",
                )
            ],
            metrics=Metrics(lines_of_code=10),
        )
        page = DeliverablesGenerator(report).informe_html()
        # el fallback DEFAULT_RECOMMENDATION se muestra completo, sin cortes de 120
        assert "Revisar el hallazgo" in page

    def test_informe_include_en_generate(self, tmp_path):
        out = tmp_path / "out"
        gen = DeliverablesGenerator(sample_report())
        gen.generate(out)
        md = (out / "informe-central.md").read_text()
        html_page = (out / "informe-central.html").read_text()
        assert "## 2. Resumen ejecutivo" in md
        assert "<table" in html_page

    def test_deps_entra_en_backlog(self, tmp_path):
        from vibeaudit.models import DependencyVulnerability

        report = AuditReport(
            project=ProjectMetadata(name="repo", languages=["js"]),
            metrics=Metrics(
                dependency_vulnerabilities=[
                    DependencyVulnerability(
                        name="axios",
                        ecosystem="npm",
                        version="0.21.0",
                        direct=True,
                        cve_ids=["CVE-2021-3749"],
                        severity=Severity.HIGH,
                        fixed_version="0.21.1",
                        summary="DoS",
                    )
                ]
            ),
        )
        gen = DeliverablesGenerator(report)
        payload = json.loads(gen.backlog_json())
        assert payload["resumen_por_seccion"]["deps"] == 1
        dep = payload["hallazgos"][0]
        assert dep["kind"] == "deps"
        assert "0.21.1" in dep["recommendation"]
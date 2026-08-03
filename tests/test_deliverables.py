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
        assert gen.c4_context().startswith("```mermaid")
        assert "VibeAudit" in gen.c4_context()
        assert "AuditReport" in gen.c4_context()

    def test_container_enumera_contenedores(self):
        gen = DeliverablesGenerator(sample_report())
        diagram = gen.c4_container()
        assert "CLI (Typer)" in diagram
        assert "RepoIngester" in diagram
        assert "AuditReporter" in diagram


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
    def test_generate_escribe_5_archivos(self, tmp_path):
        out = tmp_path / "entregables"
        gen = DeliverablesGenerator(sample_report())
        files = gen.generate(out)
        assert set(files) == {
            "c4-context.mmd",
            "c4-container.mmd",
            "roadmap.md",
            "backlog.csv",
            "backlog.json",
        }
        assert (out / "c4-context.mmd").exists()
        assert out.is_dir()

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
"""Generación del JSON maestro de auditoría."""

import json
import os
from collections import Counter
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from vibeaudit.models import (
    AuditReport,
    DependencyVulnerability,
    Metrics,
    ProjectMetadata,
    Secret,
    Severity,
    Vulnerability,
)

console = Console()

# Extensiones de código contadas para LOC
CODE_EXTENSIONS = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".html",
    ".css",
    ".sh",
)

# Patrones de nombres de archivos de test
TEST_PATTERNS = (
    "test_",
    "_test",
    ".test.",
    ".spec.",
)


class AuditReporter:
    """Agrega resultados de scanners, calcula métricas y genera el reporte."""

    def __init__(
        self,
        project: ProjectMetadata,
        vulnerabilities: Optional[List[Vulnerability]] = None,
        secrets: Optional[List[Secret]] = None,
        iac_issues: Optional[List[Vulnerability]] = None,
        repo_path: Optional[Path] = None,
        dependency_vulnerabilities: Optional[List[DependencyVulnerability]] = None,
    ):
        self.project = project
        self.vulnerabilities = vulnerabilities or []
        self.secrets = secrets or []
        self.iac_issues = iac_issues or []
        self.repo_path = repo_path
        self.dependency_vulnerabilities = dependency_vulnerabilities or []
        self._cached_report: Optional[AuditReport] = None

    def _count_lines_of_code(self) -> int:
        """Cuenta líneas totales de archivos de código en el repo."""
        if self.repo_path is None or not self.repo_path.exists():
            return 0

        total = 0
        for root, _dirs, files in os.walk(self.repo_path):
            if ".git" in root:
                continue
            for filename in files:
                if filename.endswith(CODE_EXTENSIONS):
                    full_path = os.path.join(root, filename)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            total += sum(1 for _ in f)
                    except OSError:
                        continue
        return total

    def _count_test_files(self) -> int:
        """Cuenta archivos de test en el repo."""
        if self.repo_path is None or not self.repo_path.exists():
            return 0

        count = 0
        for root, _dirs, files in os.walk(self.repo_path):
            if ".git" in root:
                continue
            for filename in files:
                name = filename.lower()
                if any(pattern in name for pattern in TEST_PATTERNS):
                    count += 1
        return count

    def build(self) -> AuditReport:
        """Construye el AuditReport completo con métricas calculadas."""
        if self._cached_report is not None:
            return self._cached_report

        all_issues = self.vulnerabilities + self.iac_issues
        severity_counts = Counter(issue.severity.value for issue in all_issues)

        dependency_names = sorted(
            {v.name for v in self.dependency_vulnerabilities}
        )

        metrics = Metrics(
            lines_of_code=self._count_lines_of_code(),
            test_files=self._count_test_files(),
            dependencies_with_cves=dependency_names,
            dependency_vulnerabilities=self.dependency_vulnerabilities,
            vulnerabilities_by_severity=dict(severity_counts),
        )
        self._cached_report = AuditReport(
            project=self.project,
            vulnerabilities=self.vulnerabilities,
            secrets=self.secrets,
            iac_issues=self.iac_issues,
            metrics=metrics,
        )
        return self._cached_report

    def to_json(self, indent: int = 2) -> str:
        """Serializa el reporte a JSON legible (con aliases camelCase)."""
        return self.build().model_dump_json(indent=indent, by_alias=True)

    def save_to_file(self, path: Path) -> None:
        """Guarda el reporte JSON en un archivo (crea directorios padre)."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_json(), encoding="utf-8")

    def print_summary(self) -> None:
        """Muestra un resumen en consola usando Rich."""
        report = self.build()
        table = Table(title=f"Resumen de auditoría — {report.project.name}")
        table.add_column("Hallazgo", style="cyan")
        table.add_column("Cantidad", justify="right")

        total_vulns = len(report.vulnerabilities)
        total_issues = (
            total_vulns
            + len(report.iac_issues)
            + len(report.metrics.dependency_vulnerabilities)
        )
        table.add_row("Vulnerabilidades (SAST)", str(total_vulns))
        table.add_row("Problemas de IaC", str(len(report.iac_issues)))
        table.add_row("Secretos filtrados", str(len(report.secrets)))
        table.add_row(
            "Dependencias con CVEs", str(len(report.metrics.dependency_vulnerabilities))
        )
        table.add_row("Total de hallazgos", str(total_issues))
        table.add_row("Líneas de código", f"{report.metrics.lines_of_code:,}")
        table.add_row("Archivos de test", str(report.metrics.test_files))

        console.print(table)

        severity_table = Table(title="Vulnerabilidades por severidad")
        severity_table.add_column("Severidad", style="bold")
        severity_table.add_column("Cantidad", justify="right")
        for severity in Severity:
            count = report.metrics.vulnerabilities_by_severity.get(severity.value, 0)
            if count > 0:
                severity_table.add_row(severity.value, str(count))
        console.print(severity_table)

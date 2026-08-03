"""Generación del JSON maestro de auditoría y reportes legibles (HTML/Markdown)."""

import html
import json
import os
from collections import Counter
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from vibeaudit.models import (
    AuditReport,
    CloudIssue,
    DependencyVulnerability,
    LLMFinding,
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

# Colores por severidad para el reporte HTML
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#16a34a",
    "INFO": "#2563eb",
}


class AuditReporter:
    """Agrega resultados de scanners, calcula métricas y genera el reporte."""

    def __init__(
        self,
        project: ProjectMetadata,
        vulnerabilities: Optional[List[Vulnerability]] = None,
        secrets: Optional[List[Secret]] = None,
        iac_issues: Optional[List[Vulnerability]] = None,
        cicd_issues: Optional[List[Vulnerability]] = None,
        repo_path: Optional[Path] = None,
        dependency_vulnerabilities: Optional[List[DependencyVulnerability]] = None,
        custom_issues: Optional[List[Vulnerability]] = None,
        llm_findings: Optional[List[LLMFinding]] = None,
        cloud_issues: Optional[List[CloudIssue]] = None,
    ):
        self.project = project
        self.vulnerabilities = vulnerabilities or []
        self.secrets = secrets or []
        self.iac_issues = iac_issues or []
        self.cicd_issues = cicd_issues or []
        self.repo_path = repo_path
        self.dependency_vulnerabilities = dependency_vulnerabilities or []
        self.custom_issues = custom_issues or []
        self.llm_findings = llm_findings or []
        self.cloud_issues = cloud_issues or []
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
            cicd_issues=self.cicd_issues,
            custom_issues=self.custom_issues,
            llm_findings=self.llm_findings,
            cloud_issues=self.cloud_issues,
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

    def _summary_rows(self) -> List[tuple]:
        """Filas del resumen (tipo de hallazgo, cantidad)."""
        report = self.build()
        return [
            ("Vulnerabilidades (SAST)", len(report.vulnerabilities)),
            ("Problemas de IaC", len(report.iac_issues)),
            ("Riesgos de CI/CD", len(report.cicd_issues)),
            ("Reglas custom", len(report.custom_issues)),
            ("Seguridad en la nube", len(report.cloud_issues)),
            ("Secretos filtrados", len(report.secrets)),
            ("Hallazgos LLM", len(report.llm_findings)),
            ("Dependencias con CVEs", len(report.metrics.dependency_vulnerabilities)),
        ]

    @staticmethod
    def _md_fence(snippet: str) -> str:
        """Fence de code block que no colisiona con los backticks del snippet."""
        max_run = 0
        current = 0
        for ch in snippet:
            if ch == "`":
                current += 1
                max_run = max(max_run, current)
            else:
                current = 0
        return "`" * (max_run + 1) if max_run >= 3 else "```"

    @staticmethod
    def _md_code(text: str) -> str:
        """Code span Markdown que soporta backticks internos (delimitador dinámico)."""
        max_run = 0
        current = 0
        for ch in text:
            if ch == "`":
                current += 1
                max_run = max(max_run, current)
            else:
                current = 0
        delim = "`" * (max_run + 1)
        return f"{delim}{text}{delim}"

    @staticmethod
    def _md_issue(rule: str, file: str, line: int, severity: Severity, snippet) -> str:
        """Renderiza un hallazgo con archivo/línea en Markdown."""
        md = (
            f"### {AuditReporter._md_code(rule)} — **{severity.value}** — "
            f"{file}:{line}"
        )
        if snippet:
            fence = AuditReporter._md_fence(snippet)
            md += f"\n\n{fence}\n{snippet}\n{fence}"
        return md

    @staticmethod
    def _md_dep(dep) -> str:
        """Renderiza una vulnerabilidad de dependencia en Markdown."""
        md = (
            f"### {dep.name}@{dep.version} ({dep.ecosystem}) — "
            f"**{dep.severity.value}**"
        )
        details = []
        if dep.cvss_score is not None:
            details.append(f"CVSS {dep.cvss_score}")
        if dep.fixed_version:
            details.append(f"corregida en {dep.fixed_version}")
        if dep.cve_ids:
            details.append(", ".join(dep.cve_ids))
        if details:
            md += f" — {', '.join(details)}"
        if dep.summary:
            md += f"\n\n{dep.summary}"
        return md

    @staticmethod
    def _md_llm(finding) -> str:
        """Renderiza un hallazgo del auditor LLM en Markdown."""
        md = (
            f"### {AuditReporter._md_code(finding.title)} — "
            f"**{finding.severity.value}**"
        )
        if finding.checklist_ref:
            md += f" — `{finding.checklist_ref}`"
        if finding.evidence:
            md += f"\n\n{finding.evidence}"
        if finding.recommendation:
            md += f"\n\n**Recomendación:** {finding.recommendation}"
        return md

    @staticmethod
    def _md_cloud(issue) -> str:
        """Renderiza un hallazgo de nube en Markdown."""
        md = (
            f"### {AuditReporter._md_code(issue.rule)} — "
            f"**{issue.severity.value}** — `{issue.provider}` — "
            f"{issue.resource}"
        )
        if issue.description:
            md += f"\n\n{issue.description}"
        if issue.recommendation:
            md += f"\n\n**Recomendación:** {issue.recommendation}"
        return md

    def save_markdown(self, path: Path) -> None:
        """Guarda el reporte en Markdown legible para humanos."""
        report = self.build()
        lines = [f"# Auditoría de {report.project.name}", ""]

        meta = []
        if report.project.repository_url:
            meta.append(f"**Repositorio**: {report.project.repository_url}")
        if report.project.default_branch:
            meta.append(f"**Rama**: {report.project.default_branch}")
        if report.project.commit_hash:
            meta.append(f"**Commit**: {report.project.commit_hash}")
        if meta:
            lines.append(" · ".join(meta))
            lines.append("")

        lines.append("## Resumen")
        lines.append("")
        lines.append("| Tipo de hallazgo | Cantidad |")
        lines.append("|---|---|")
        rows = self._summary_rows()
        for label, count in rows:
            lines.append(f"| {label} | {count} |")
        lines.append(f"| **Total** | **{sum(c for _, c in rows)}** |")
        lines.append("")

        sections = [
            ("Vulnerabilidades (SAST)", [
                self._md_issue(v.rule, v.file, v.line, v.severity, v.snippet)
                for v in report.vulnerabilities
            ]),
            ("Secretos filtrados", [
                self._md_issue(s.type, s.file, s.line, s.severity, None)
                for s in report.secrets
            ]),
            ("Problemas de IaC", [
                self._md_issue(v.rule, v.file, v.line, v.severity, v.snippet)
                for v in report.iac_issues
            ]),
            ("Riesgos de CI/CD", [
                self._md_issue(v.rule, v.file, v.line, v.severity, v.snippet)
                for v in report.cicd_issues
            ]),
            ("Reglas custom", [
                self._md_issue(v.rule, v.file, v.line, v.severity, v.snippet)
                for v in report.custom_issues
            ]),
            ("Auditoría LLM (checklists)", [
                self._md_llm(f) for f in report.llm_findings
            ]),
            ("Seguridad en la nube", [
                self._md_cloud(c) for c in report.cloud_issues
            ]),
            ("Dependencias con CVEs", [
                self._md_dep(d) for d in report.metrics.dependency_vulnerabilities
            ]),
        ]
        for title, items in sections:
            lines.append(f"## {title}")
            lines.append("")
            lines.append(
                "\n\n".join(items) if items else "No se encontraron hallazgos."
            )
            lines.append("")

        lines.append("## Métricas")
        lines.append("")
        lines.append(f"- Líneas de código: {report.metrics.lines_of_code:,}")
        lines.append(f"- Archivos de test: {report.metrics.test_files}")
        cve_names = ", ".join(report.metrics.dependencies_with_cves)
        lines.append(f"- Dependencias con CVEs: {cve_names or 'ninguna'}")
        severity_counts = report.metrics.vulnerabilities_by_severity
        if severity_counts:
            formatted = ", ".join(
                f"{key}: {count}" for key, count in severity_counts.items()
            )
            lines.append(f"- Vulnerabilidades por severidad: {formatted}")
        lines.append("")

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def _html_escaped(value) -> str:
        """Escapa un valor para insertarlo en HTML."""
        return html.escape(str(value))

    def _html_badge(self, severity: Severity) -> str:
        """Badge HTML con el color de la severidad."""
        color = SEVERITY_COLORS.get(severity.value, "#6b7280")
        return (
            f'<span class="badge" style="background: {color};">'
            f"{severity.value}</span>"
        )

    def _html_issues_table(self, issues: List, is_secret: bool = False) -> str:
        """Tabla HTML de hallazgos con regla, archivo, severidad y detalle."""
        if not issues:
            return "<p>No se encontraron hallazgos.</p>"
        rows = []
        for issue in issues:
            rule = getattr(issue, "rule", None) or getattr(issue, "type", "")
            snippet = getattr(issue, "snippet", None)
            detail = (
                f"<pre>{self._html_escaped(snippet)}</pre>" if snippet else ""
            )
            rows.append(
                "<tr>"
                f"<td><code>{self._html_escaped(rule)}</code></td>"
                f"<td>{self._html_escaped(issue.file)}:{issue.line}</td>"
                f"<td>{self._html_badge(issue.severity)}</td>"
                f"<td>{detail}</td>"
                "</tr>"
            )
        return (
            "<table><thead><tr>"
            "<th>Regla</th><th>Archivo</th><th>Severidad</th><th>Detalle</th>"
            "</tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )

    def _html_deps_table(self, deps: List) -> str:
        """Tabla HTML de vulnerabilidades de dependencias."""
        if not deps:
            return "<p>No se encontraron hallazgos.</p>"
        rows = []
        for dep in deps:
            fix = (
                f"corregida en <code>{self._html_escaped(dep.fixed_version)}</code>"
                if dep.fixed_version
                else "sin fix"
            )
            cves = ", ".join(self._html_escaped(c) for c in dep.cve_ids)
            detail = f"{fix} — {cves}" if cves else fix
            rows.append(
                "<tr>"
                f"<td><code>{self._html_escaped(dep.name)}@{self._html_escaped(dep.version)}</code></td>"
                f"<td>{self._html_escaped(dep.ecosystem)}</td>"
                f"<td>{self._html_badge(dep.severity)}</td>"
                f"<td>{detail}</td>"
                "</tr>"
            )
        return (
            "<table><thead><tr>"
            "<th>Paquete</th><th>Ecosistema</th><th>Severidad</th><th>Detalle</th>"
            "</tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )

    def _html_cloud_table(self, issues: List) -> str:
        """Tabla HTML de hallazgos de seguridad en la nube."""
        if not issues:
            return "<p>No se encontraron hallazgos.</p>"
        rows = []
        for issue in issues:
            detail = issue.description or ""
            if issue.recommendation:
                detail = (
                    f"{detail} — <strong>Recomendación:</strong> "
                    f"{self._html_escaped(issue.recommendation)}"
                )
            rows.append(
                "<tr>"
                f"<td><code>{self._html_escaped(issue.rule)}</code></td>"
                f"<td>{self._html_escaped(issue.provider)}</td>"
                f"<td><code>{self._html_escaped(issue.resource)}</code></td>"
                f"<td>{self._html_badge(issue.severity)}</td>"
                f"<td>{detail}</td>"
                "</tr>"
            )
        return (
            "<table><thead><tr>"
            "<th>Regla</th><th>Proveedor</th><th>Recurso</th>"
            "<th>Severidad</th><th>Detalle</th>"
            "</tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )

    def _html_llm_table(self, findings: List) -> str:
        """Tabla HTML de hallazgos del auditor LLM."""
        if not findings:
            return "<p>No se encontraron hallazgos.</p>"
        rows = []
        for finding in findings:
            detail = finding.evidence or ""
            if finding.recommendation:
                detail = f"{detail} — <strong>Recomendación:</strong> {finding.recommendation}"
            rows.append(
                "<tr>"
                f"<td><strong>{self._html_escaped(finding.title)}</strong></td>"
                f"<td>{self._html_badge(finding.severity)}</td>"
                f"<td>{self._html_escaped(finding.checklist_ref) or '—'}</td>"
                f"<td>{detail}</td>"
                "</tr>"
            )
        return (
            "<table><thead><tr>"
            "<th>Hallazgo</th><th>Severidad</th><th>Checklist</th><th>Detalle</th>"
            "</tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )

    def save_html(self, path: Path) -> None:
        """Guarda el reporte en HTML autocontenido (sin JS ni CSS externo)."""
        report = self.build()

        meta = []
        if report.project.repository_url:
            meta.append(
                f"<p><strong>Repositorio:</strong> "
                f"{self._html_escaped(report.project.repository_url)}</p>"
            )
        if report.project.default_branch:
            meta.append(
                f"<p><strong>Rama:</strong> "
                f"{self._html_escaped(report.project.default_branch)}</p>"
            )
        if report.project.commit_hash:
            meta.append(
                f"<p><strong>Commit:</strong> "
                f"{self._html_escaped(report.project.commit_hash[:12])}</p>"
            )

        rows = self._summary_rows()
        summary_rows = "".join(
            f"<tr><td>{self._html_escaped(label)}</td>"
            f"<td>{count}</td></tr>"
            for label, count in rows
        )
        total = sum(c for _, c in rows)

        sections = "".join(
            f"<section><h2>{self._html_escaped(title)}</h2>{table}</section>"
            for title, table in [
                ("Vulnerabilidades (SAST)", self._html_issues_table(report.vulnerabilities)),
                ("Secretos filtrados", self._html_issues_table(report.secrets)),
                ("Problemas de IaC", self._html_issues_table(report.iac_issues)),
                ("Riesgos de CI/CD", self._html_issues_table(report.cicd_issues)),
                ("Reglas custom", self._html_issues_table(report.custom_issues)),
                (
                    "Auditoría LLM (checklists)",
                    self._html_llm_table(report.llm_findings),
                ),
                (
                    "Seguridad en la nube",
                    self._html_cloud_table(report.cloud_issues),
                ),
                (
                    "Dependencias con CVEs",
                    self._html_deps_table(report.metrics.dependency_vulnerabilities),
                ),
            ]
        )

        severity_items = "".join(
            f"<li><strong>{self._html_escaped(key)}:</strong> {count}</li>"
            for key, count in report.metrics.vulnerabilities_by_severity.items()
        )

        document = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Auditoría de {self._html_escaped(report.project.name)}</title>
<style>
body {{ font-family: -apple-system, 'Segoe UI', sans-serif; margin: 2rem auto;
       max-width: 64rem; padding: 0 1rem; color: #1f2937; }}
h1 {{ border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem; }}
section {{ margin-top: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #e5e7eb; padding: 0.5rem; text-align: left;
         vertical-align: top; }}
th {{ background: #f9fafb; }}
code {{ background: #f3f4f6; padding: 0.1rem 0.3rem; border-radius: 4px; }}
pre {{ background: #f9fafb; padding: 0.5rem; overflow-x: auto;
       border-radius: 4px; }}
.badge {{ color: #fff; padding: 0.1rem 0.5rem; border-radius: 9999px;
         font-size: 0.8rem; font-weight: 600; }}
</style>
</head>
<body>
<h1>Auditoría de {self._html_escaped(report.project.name)}</h1>
{''.join(meta)}
<h2>Resumen</h2>
<table>
<thead><tr><th>Tipo de hallazgo</th><th>Cantidad</th></tr></thead>
<tbody>{summary_rows}
<tr><td><strong>Total</strong></td><td><strong>{total}</strong></td></tr></tbody>
</table>
{sections}
<h2>Métricas</h2>
<ul>
<li><strong>Líneas de código:</strong> {report.metrics.lines_of_code:,}</li>
<li><strong>Archivos de test:</strong> {report.metrics.test_files}</li>
<li><strong>Dependencias con CVEs:</strong> {self._html_escaped(', '.join(report.metrics.dependencies_with_cves)) or 'ninguna'}</li>
</ul>
<ul>{severity_items}</ul>
</body>
</html>
"""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(document, encoding="utf-8")

    def save_dashboard(self, path: Path) -> None:
        """Guarda un dashboard HTML interactivo (autocontenido, sin JS externo).

        El JSON maestro se embebe en un <script type="application/json"> para que
        funcione abriendo el archivo con file:// (sin servidor). El render usa
        textContent (sin innerHTML) y se escapan las secuencias que romperían
        el bloque de datos (</script> y <!--).
        """
        report = self.build()
        raw_json = self.to_json()
        embedded = raw_json.replace("</", "<\\/").replace("<!--", "<\\u0021--")

        meta = []
        if report.project.repository_url:
            meta.append(report.project.repository_url)
        if report.project.default_branch:
            meta.append(f"rama {report.project.default_branch}")
        if report.project.commit_hash:
            meta.append(report.project.commit_hash[:12])

        document = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Dashboard — {self._html_escaped(report.project.name)}</title>
<style>
body {{ font-family: -apple-system, 'Segoe UI', sans-serif; margin: 2rem auto;
       max-width: 72rem; padding: 0 1rem; color: #1f2937; }}
h1 {{ border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem; }}
#meta {{ color: #6b7280; margin: 0.25rem 0 1rem; }}
.cards {{ display: flex; flex-wrap: wrap; gap: 1rem; }}
.card {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 0.75rem 1rem;
        min-width: 9rem; background: #f9fafb; }}
.card .label {{ color: #6b7280; font-size: 0.85rem; }}
.card .num {{ font-size: 2rem; font-weight: 700; }}
.card.total {{ border-color: #1f2937; background: #1f2937; color: #fff; }}
.card.total .label {{ color: #9ca3af; }}
section {{ margin-top: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #e5e7eb; padding: 0.5rem; text-align: left;
         vertical-align: top; }}
th {{ background: #f9fafb; }}
pre {{ background: #f9fafb; padding: 0.5rem; overflow-x: auto;
      border-radius: 4px; margin: 0; }}
.badge {{ color: #fff; padding: 0.1rem 0.5rem; border-radius: 9999px;
         font-size: 0.8rem; font-weight: 600; }}
.bar-row {{ display: flex; align-items: center; gap: 0.5rem; margin: 0.35rem 0; }}
.bar-label {{ width: 6rem; font-weight: 600; }}
.bar-track {{ flex: 1; background: #f3f4f6; height: 1.25rem; border-radius: 6px; }}
.bar-fill {{ height: 100%; border-radius: 6px; }}
.bar-count {{ width: 3rem; text-align: right; color: #6b7280; }}
#filter {{ width: 100%; padding: 0.5rem; border: 1px solid #e5e7eb;
          border-radius: 6px; margin-bottom: 1rem; font-size: 1rem; }}
</style>
</head>
<body>
<h1>Dashboard — {self._html_escaped(report.project.name)}</h1>
<p id="meta">{self._html_escaped(" · ".join(meta))}</p>
<input id="filter" type="search" placeholder="Filtrar hallazgos (regla, archivo, CVE...)" autocomplete="off">
<div id="cards" class="cards"></div>
<h2>Severidades</h2>
<div id="severity-bars"></div>
<h2>Métricas</h2>
<ul id="metrics"></ul>
<div id="sections"></div>
<script id="audit-data" type="application/json">{embedded}</script>
<script>
(function () {{
  var COLORS = {{CRITICAL:'#dc2626', HIGH:'#ea580c', MEDIUM:'#d97706', LOW:'#16a34a', INFO:'#2563eb'}};
  var ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  var data = JSON.parse(document.getElementById('audit-data').textContent);

  function el(tag, cls, text) {{
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }}
  function badge(sev) {{
    var b = el('span', 'badge', sev);
    b.style.background = COLORS[sev] || '#6b7280';
    return b;
  }}

  var totals = [
    ['SAST', data.vulnerabilities.length],
    ['Secretos', data.secrets.length],
    ['IaC', data.iacIssues.length],
    ['CI/CD', data.cicdIssues.length],
    ['Reglas custom', data.customIssues.length],
    ['LLM', data.llmFindings.length],
    ['Nube', data.cloudIssues.length],
    ['Checklists', data.checklists ? data.checklists.length : 0],
    ['Recurrentes', data.recurrentFindings.length],
    ['Deps con CVEs', data.metrics.dependencyVulnerabilities.length]
  ];
  var grand = totals.reduce(function (s, t) {{ return s + t[1]; }}, 0);
  var cards = document.getElementById('cards');
  totals.forEach(function (t) {{
    var c = el('div', 'card');
    c.appendChild(el('div', 'label', t[0]));
    c.appendChild(el('div', 'num', String(t[1])));
    cards.appendChild(c);
  }});
  var g = el('div', 'card total');
  g.appendChild(el('div', 'label', 'Total hallazgos'));
  g.appendChild(el('div', 'num', String(grand)));
  cards.appendChild(g);

  var counts = {{}};
  ORDER.forEach(function (s) {{ counts[s] = 0; }});
  function countSev(items) {{
    (items || []).forEach(function (it) {{
      var v = it.severity;
      if (v && counts[v] !== undefined) counts[v]++;
    }});
  }}
  countSev(data.vulnerabilities);
  countSev(data.secrets);
  countSev(data.iacIssues);
  countSev(data.cicdIssues);
  countSev(data.customIssues);
  countSev(data.llmFindings);
  countSev(data.cloudIssues);
  countSev(data.metrics.dependencyVulnerabilities);
  var max = Math.max.apply(null, ORDER.map(function (s) {{ return counts[s]; }}).concat([1]));
  var bars = document.getElementById('severity-bars');
  ORDER.forEach(function (s) {{
    var row = el('div', 'bar-row');
    row.appendChild(el('div', 'bar-label', s));
    var track = el('div', 'bar-track');
    var fill = el('div', 'bar-fill');
    fill.style.width = (counts[s] / max * 100) + '%';
    fill.style.background = COLORS[s];
    track.appendChild(fill);
    row.appendChild(track);
    row.appendChild(el('div', 'bar-count', String(counts[s])));
    bars.appendChild(row);
  }});

  var m = document.getElementById('metrics');
  m.appendChild(el('li', null, 'Líneas de código: ' + (data.metrics.linesOfCode || 0).toLocaleString()));
  m.appendChild(el('li', null, 'Archivos de test: ' + (data.metrics.testFiles || 0)));
  var cveNames = (data.metrics.dependenciesWithCves || []).join(', ');
  m.appendChild(el('li', null, 'Dependencias con CVEs: ' + (cveNames || 'ninguna')));

  function issueCells(it) {{
    var rule = it.rule || it.type || '';
    var tdBadge = el('td');
    tdBadge.appendChild(badge(it.severity));
    var tdSnippet = el('td');
    if (it.snippet) tdSnippet.appendChild(el('pre', null, it.snippet));
    return [el('td', null, rule), el('td', null, it.file + ':' + it.line), tdBadge, tdSnippet];
  }}
  function depCells(d) {{
    var detail = [];
    detail.push(d.fixedVersion ? 'corregida en ' + d.fixedVersion : 'sin fix');
    if (d.cveIds && d.cveIds.length) detail.push(d.cveIds.join(', '));
    if (d.summary) detail.push(d.summary);
    var tdBadge = el('td');
    tdBadge.appendChild(badge(d.severity));
    return [
      el('td', null, d.name + '@' + d.version),
      el('td', null, d.ecosystem),
      tdBadge,
      el('td', null, detail.join(' — '))
    ];
  }}
  function llmCells(f) {{
    var detail = [];
    if (f.evidence) detail.push(f.evidence);
    if (f.recommendation) detail.push('Recomendación: ' + f.recommendation);
    var tdBadge = el('td');
    tdBadge.appendChild(badge(f.severity));
    return [
      el('td', null, f.title),
      el('td', null, f.checklistRef || '—'),
      tdBadge,
      el('td', null, detail.join(' — '))
    ];
  }}
  function cloudCells(c) {{
    var detail = [];
    if (c.description) detail.push(c.description);
    if (c.recommendation) detail.push('Recomendación: ' + c.recommendation);
    var tdBadge = el('td');
    tdBadge.appendChild(badge(c.severity));
    return [
      el('td', null, c.rule),
      el('td', null, c.provider),
      el('td', null, c.resource),
      tdBadge,
      el('td', null, detail.join(' — '))
    ];
  }}
  var sections = [
    {{ id: 'sec-sast', title: 'Vulnerabilidades (SAST)', items: data.vulnerabilities, cells: issueCells, headers: ['Regla', 'Archivo', 'Severidad', 'Detalle'] }},
    {{ id: 'sec-secrets', title: 'Secretos filtrados', items: data.secrets, cells: issueCells, headers: ['Regla', 'Archivo', 'Severidad', 'Detalle'] }},
    {{ id: 'sec-iac', title: 'Problemas de IaC', items: data.iacIssues, cells: issueCells, headers: ['Regla', 'Archivo', 'Severidad', 'Detalle'] }},
    {{ id: 'sec-cicd', title: 'Riesgos de CI/CD', items: data.cicdIssues, cells: issueCells, headers: ['Regla', 'Archivo', 'Severidad', 'Detalle'] }},
    {{ id: 'sec-custom', title: 'Reglas custom', items: data.customIssues, cells: issueCells, headers: ['Regla', 'Archivo', 'Severidad', 'Detalle'] }},
    {{ id: 'sec-cloud', title: 'Seguridad en la nube', items: data.cloudIssues, cells: cloudCells, headers: ['Regla', 'Proveedor', 'Recurso', 'Severidad', 'Detalle'] }},
    {{ id: 'sec-llm', title: 'Auditoría LLM (checklists)', items: data.llmFindings, cells: llmCells, headers: ['Hallazgo', 'Checklist', 'Severidad', 'Detalle'] }},
    {{ id: 'sec-deps', title: 'Dependencias con CVEs', items: data.metrics.dependencyVulnerabilities, cells: depCells, headers: ['Paquete', 'Ecosistema', 'Severidad', 'Detalle'] }}
  ];
  var sectionsEl = document.getElementById('sections');
  sections.forEach(function (s) {{
    var sec = el('section');
    sec.id = s.id;
    sec.appendChild(el('h2', null, s.title));
    var table = el('table');
    var thead = el('thead');
    var headRow = el('tr');
    s.headers.forEach(function (h) {{ headRow.appendChild(el('th', null, h)); }});
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = el('tbody');
    if (s.items && s.items.length) {{
      s.items.forEach(function (it) {{
        var row = el('tr');
        s.cells(it).forEach(function (c) {{ row.appendChild(c); }});
        tbody.appendChild(row);
      }});
    }} else {{
      var emptyRow = el('tr');
      var emptyTd = el('td', null, 'No se encontraron hallazgos.');
      emptyTd.colSpan = s.headers.length;
      emptyRow.appendChild(emptyTd);
      tbody.appendChild(emptyRow);
    }}
    table.appendChild(tbody);
    sec.appendChild(table);
    sectionsEl.appendChild(sec);
  }});

  var filter = document.getElementById('filter');
  filter.addEventListener('input', function () {{
    var q = filter.value.toLowerCase();
    sections.forEach(function (s) {{
      var sec = document.getElementById(s.id);
      var rows = sec.querySelectorAll('tbody tr');
      var anyVisible = false;
      rows.forEach(function (r) {{
        var hit = r.textContent.toLowerCase().indexOf(q) !== -1;
        r.style.display = hit ? '' : 'none';
        if (hit) anyVisible = true;
      }});
      sec.style.display = anyVisible ? '' : 'none';
    }});
  }});
}})();
</script>
</body>
</html>
"""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(document, encoding="utf-8")

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
            + len(report.cicd_issues)
            + len(report.custom_issues)
            + len(report.cloud_issues)
            + len(report.secrets)
            + len(report.llm_findings)
            + len(report.metrics.dependency_vulnerabilities)
        )
        table.add_row("Vulnerabilidades (SAST)", str(total_vulns))
        table.add_row("Problemas de IaC", str(len(report.iac_issues)))
        table.add_row("Riesgos de CI/CD", str(len(report.cicd_issues)))
        table.add_row("Reglas custom", str(len(report.custom_issues)))
        table.add_row("Seguridad en la nube", str(len(report.cloud_issues)))
        table.add_row("Secretos filtrados", str(len(report.secrets)))
        table.add_row("Hallazgos LLM", str(len(report.llm_findings)))
        table.add_row("Checklists aplicados", str(len(report.checklists)))
        table.add_row(
            "Hallazgos recurrentes (memoria)", str(len(report.recurrent_findings))
        )
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
        severity_counts = Counter()
        for items in (
            report.vulnerabilities,
            report.secrets,
            report.iac_issues,
            report.cicd_issues,
            report.custom_issues,
            report.cloud_issues,
            report.llm_findings,
            report.metrics.dependency_vulnerabilities,
        ):
            severity_counts.update(issue.severity.value for issue in items)
        for severity in Severity:
            count = severity_counts.get(severity.value, 0)
            if count > 0:
                severity_table.add_row(severity.value, str(count))
        console.print(severity_table)

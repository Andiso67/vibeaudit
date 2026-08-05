"""Generador de entregables de cliente (ítem 6 del Sprint 3).

A partir del JSON maestro (AuditReport) se generan, con --deliverables <dir>:
  - c4-context.mmd      # Diagrama C4 nivel 1 (Contexto) en Mermaid
  - c4-container.mmd    # Diagrama C4 nivel 2 (Contenedores) en Mermaid
  - roadmap.md          # Roadmap por fases según severidad de hallazgos
  - backlog.csv         # Backlog de remediación (CSV)
  - backlog.json        # Backlog de remediación (JSON)
  - informe-central.md  # Informe central: reúne C4, roadmap y backlog (MD)
  - informe-central.html  # Informe central en HTML autocontenido/imprimible

Todo determinista y sin red, para poder verificarlo en tests y CI.
"""

import csv
import html
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

# Fase de roadmap sugerida según severidad del hallazgo
PHASE_BY_SEVERITY = {
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 3,
}

PHASE_DESCRIPTIONS = {
    1: "Remediación inmediata (0-2 semanas): riesgos graves o explotables.",
    2: "Remediación a corto plazo (2-6 semanas): endurecer y reducir superficie.",
    3: "Mejora continua (más de 6 semanas): higiene y deuda técnica.",
}

COLUMN_HEADERS = [
    "id",
    "seccion",
    "regla",
    "archivo",
    "linea",
    "severidad",
    "fase",
    "recomendacion",
]

DEFAULT_RECOMMENDATION = {
    "sast": "Revisar el hallazgo y aplicar la regla / patch correspondiente.",
    "secrets": "Rota la credencial filtrada y elimínala del repositorio.",
    "iac": "Corregir la configuración de infraestructura señalada.",
    "cicd": "Endurecer el pipeline CI/CD según el hallazgo.",
    "custom": "Aplicar la convención 'Vibe Coding' incumplida.",
    "cloud": "Endurecer la configuración del recurso en la nube.",
    "llm": "Aplicar la recomendación del auditor.",
    "deps": "Actualizar o parchear la dependencia vulnerable.",
}


def _sev_value(sev) -> str:
    """Normaliza un Severity (enum) a su cadena en mayúsculas."""
    value = sev.value if hasattr(sev, "value") else str(sev)
    return str(value).upper()


class DeliverablesGenerator:
    """Genera los entregables de cliente en un directorio de salida."""

    def __init__(self, report):
        self.report = report

    def generate(self, out_dir: Path) -> Dict[str, Path]:
        """Escribe los entregables en out_dir y devuelve {nombre: Path}."""
        out_dir.mkdir(parents=True, exist_ok=True)
        files: Dict[str, Path] = {}
        for name, content in [
            ("c4-context.mmd", self.c4_context()),
            ("c4-container.mmd", self.c4_container()),
            ("roadmap.md", self.roadmap_markdown()),
            ("backlog.csv", self.backlog_csv()),
            ("backlog.json", self.backlog_json()),
            ("informe-central.md", self.informe_markdown()),
            ("informe-central.html", self.informe_html()),
            ("informe-ejecutivo.html", self.informe_ejecutivo_html()),
            ("informe-ejecutivo.pdf", self.informe_ejecutivo_pdf()),
        ]:
            path = out_dir / name
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
            files[name] = path
        return files

    # --- Diagramas C4 (Mermaid), generados a partir del reporte ---

    def _components(self) -> dict:
        """Detecta los componentes del proyecto auditado desde el reporte."""
        meta = self.report.project
        deps = {d.name.lower() for d in self.report.metrics.dependency_vulnerabilities}
        iac = " ".join(f.lower() for f in (meta.iac_files or []))
        fw = [f.lower() for f in meta.frameworks]

        # Tipos de recursos de nube: de cloud_resources y de las rules de issues
        cloud_types = {r.resource_type for r in self.report.cloud_resources}
        for issue in self.report.cloud_issues:
            rule = (issue.rule or "").lower()
            if "s3" in rule:
                cloud_types.add("s3-bucket")
            if "security-group" in rule or "ec2" in rule:
                cloud_types.add("security-group")

        web_label = "Aplicación"
        web_hint = ""
        if any("next" in f for f in fw):
            web_label, web_hint = "Aplicación web Next.js", "Next.js"
        elif any("react" in f for f in fw) or deps & {"react", "react-dom"}:
            web_label, web_hint = "Aplicación web React", "React"
        elif any(f in fw for f in ("vue", "angular", "svelte")):
            web_label, web_hint = f"Aplicación web {fw[0].title()}", fw[0]
        elif any(f in fw for f in ("express", "fastify", "hono", "django", "fastapi", "flask")):
            web_label, web_hint = f"API web ({fw[0].title()})", fw[0]

        api = None
        api_hint = next(
            (n for n in ("hono", "express", "fastify", "nestjs", "fastapi", "flask", "django") if n in deps),
            None,
        )
        if api_hint:
            api = f"API ({api_hint.title()})"

        db = None
        if "postgres" in iac or deps & {"prisma", "pg", "postgres", "pgvector"}:
            db = "PostgreSQL"
        elif "mysql" in iac or deps & {"mysql", "mysql2"}:
            db = "MySQL"
        elif "mongo" in iac or deps & {"mongoose", "mongodb"}:
            db = "MongoDB"
        elif "redis" in iac or "redis" in deps:
            db = "Redis"

        return {
            "web_label": web_label,
            "web_hint": web_hint,
            "api": api,
            "db": db,
            "has_s3": "s3-bucket" in cloud_types,
            "has_ec2": "security-group" in cloud_types,
            "has_docker": "dockerfile" in iac or "docker-compose" in iac,
            "has_cicd": bool(self.report.cicd_issues),
            "buckets": sum(1 for r in self.report.cloud_resources if r.resource_type == "s3-bucket"),
            "sgs": sum(1 for r in self.report.cloud_resources if r.resource_type == "security-group"),
        }

    def c4_context(self) -> str:
        """C4 nivel 1: el sistema auditado y su entorno (datos del reporte)."""
        meta = self.report.project
        comp = self._components()
        lines = [
            "```mermaid",
            "flowchart TD",
            f'    SYS["{meta.name}<br/>{comp["web_label"]}"]',
            '    U["Usuarios del servicio"]',
            "    U -->|usan| SYS",
        ]
        if meta.repository_url:
            lines += [
                f'    GH["GitHub<br/>({meta.repository_url.split("/")[-1]})"]',
                "    SYS -->|desarrollado en| GH",
            ]
        if comp["db"]:
            lines += [
                f'    DB["{comp["db"]}<br/>(base de datos)"]',
                "    SYS -->|persiste en| DB",
            ]
        cloud_bits = []
        if comp["has_s3"]:
            cloud_bits.append("S3")
        if comp["has_ec2"]:
            cloud_bits.append("EC2/VPC")
        if cloud_bits:
            lines += [
                f'    AWS["Amazon Web Services<br/>({", ".join(cloud_bits)})"]',
                "    SYS -->|corre y almacena en| AWS",
            ]
        if comp["has_cicd"]:
            lines += [
                '    CI["CI/CD<br/>(workflow)" ]',
                "    SYS -->|se despliega vía| CI",
            ]
        lines.append("```")
        return "\n".join(lines)

    def c4_container(self) -> str:
        """C4 nivel 2: contenedores del sistema auditado (datos del reporte)."""
        meta = self.report.project
        comp = self._components()
        lines = [
            "```mermaid",
            "flowchart LR",
            f'    subgraph APP["{meta.name}"]',
            f'        WEB["{comp["web_label"]}"]',
        ]
        if comp["api"]:
            lines += [
                f'        API["{comp["api"]}"]',
                "        WEB -->|HTTP| API",
            ]
        if comp["db"]:
            api_or_web = "API" if comp["api"] else "WEB"
            lines += [
                f'        DB["{comp["db"]}"]',
                f"        {api_or_web} -->|persiste| DB",
            ]
        lines.append("    end")
        if comp["has_s3"] or comp["has_ec2"]:
            targets = []
            if comp["has_s3"]:
                lines.append('    S3["Amazon S3<br/>(almacenamiento)"]')
                targets.append("S3")
            if comp["has_ec2"]:
                lines.append('    NET["Amazon EC2 / VPC"]')
                targets.append("NET")
            source = "API" if comp["api"] else "WEB"
            for target in targets:
                lines.append(f"    {source} -->|usa| {target}")
        if comp["has_docker"]:
            lines += [
                '    DKR["Contenedores<br/>(Docker)"]',
                f"    {'API' if comp['api'] else 'WEB'} -->|empaquetado en| DKR",
            ]
        lines.append("```")
        return "\n".join(lines)

    # --- Hallazgos normalizados ---

    def _entry(
        self,
        kind: str,
        rule: str,
        severity: str,
        file: str = "",
        line: str = "",
        recommendation: str = "",
        snippet: str = "",
    ) -> dict:
        return {
            "kind": kind,
            "id": f"{kind}-{rule}",
            "rule": rule,
            "file": file,
            "line": line,
            "severity": severity,
            "phase": PHASE_BY_SEVERITY.get(severity, 3),
            "recommendation": recommendation
            or DEFAULT_RECOMMENDATION.get(kind, "Revisar el hallazgo."),
            "snippet": snippet[:200],
        }

    def _grouped_findings(self):
        """Devuelve (entries, counters): lista plana de hallazgos y conteos."""
        entries: List[dict] = []
        counters: Dict[str, int] = {}

        def add(kind, rule, severity, file, line, recommendation="", snippet=""):
            entry = self._entry(kind, rule, severity, file, line, recommendation, snippet)
            entries.append(entry)
            counters[kind] = counters.get(kind, 0) + 1

        for kind, resolver in [
            ("sast", self._sast_entries),
            ("secrets", self._secrets_entries),
            ("iac", self._iac_entries),
            ("cicd", self._cicd_entries),
            ("custom", self._custom_entries),
            ("cloud", self._cloud_entries),
            ("llm", self._llm_entries),
        ]:
            for entry in resolver():
                entries.append(entry)
        for entry in self._deps_entries():
            entries.append(entry)

        counters = {
            kind: sum(1 for e in entries if e["kind"] == kind) for kind in (
                "sast", "secrets", "iac", "cicd", "custom", "cloud", "llm", "deps"
            )
        }
        return entries, counters

    def _sast_entries(self) -> List[dict]:
        return [
            self._entry(
                "sast",
                v.rule,
                _sev_value(v.severity),
                v.file,
                str(v.line),
                snippet=v.snippet or "",
            )
            for v in self.report.vulnerabilities
        ]

    def _secrets_entries(self) -> List[dict]:
        return [
            self._entry(
                "secrets",
                s.type,
                _sev_value(s.severity),
                s.file,
                str(s.line),
            )
            for s in self.report.secrets
        ]

    def _iac_entries(self) -> List[dict]:
        return [
            self._entry(
                "iac",
                v.rule,
                _sev_value(v.severity),
                v.file,
                str(v.line),
                snippet=v.snippet or "",
            )
            for v in self.report.iac_issues
        ]

    def _cicd_entries(self) -> List[dict]:
        return [
            self._entry(
                "cicd",
                v.rule,
                _sev_value(v.severity),
                v.file,
                str(v.line),
                snippet=v.snippet or "",
            )
            for v in self.report.cicd_issues
        ]

    def _custom_entries(self) -> List[dict]:
        return [
            self._entry(
                "custom",
                v.rule,
                _sev_value(v.severity),
                v.file,
                str(v.line),
                snippet=v.snippet or "",
            )
            for v in self.report.custom_issues
        ]

    def _cloud_entries(self) -> List[dict]:
        return [
            self._entry(
                "cloud",
                issue.rule,
                _sev_value(issue.severity),
                file=issue.resource,
                recommendation=issue.recommendation,
                snippet=issue.description,
            )
            for issue in self.report.cloud_issues
        ]

    def _llm_entries(self) -> List[dict]:
        return [
            self._entry(
                "llm",
                f.title,
                _sev_value(f.severity),
                recommendation=f.recommendation or "",
                snippet=f.evidence or "",
            )
            for f in self.report.llm_findings
        ]

    def _deps_entries(self) -> List[dict]:
        return [
            self._entry(
                "deps",
                f"{dep.name}@{dep.version}",
                _sev_value(dep.severity),
                recommendation=(
                    f"Corregir dependencia {dep.name}@{dep.version}; "
                    + (
                        f"disponible en {dep.fixed_version}"
                        if dep.fixed_version
                        else "sin versión corregida aún"
                    )
                ),
                snippet=dep.summary or "",
            )
            for dep in self.report.metrics.dependency_vulnerabilities
        ]

    # --- Markdown / CSV / JSON ---

    def roadmap_markdown(self) -> str:
        entries, _counters = self._grouped_findings()
        lines = [
            f"# Roadmap de remediación — {self.report.project.name}",
            "",
            f"**Repositorio:** {self.report.project.repository_url or '—'}",
            "",
            f"**Total de hallazgos considerados:** {len(entries)}",
            "",
        ]
        for phase in (1, 2, 3):
            items = [e for e in entries if e["phase"] == phase]
            lines.append(f"## Fase {phase}")
            lines.append("")
            lines.append(PHASE_DESCRIPTIONS[phase])
            lines.append("")
            if not items:
                lines.append("Sin hallazgos en esta fase.")
            else:
                lines.append("| ID | Tipo | Regla | Archivo | Severidad |")
                lines.append("|---|---|---|---|---|")
                for e in items:
                    loc = f"{e['file']}:{e['line']}" if e["file"] else ""
                    lines.append(
                        f"| `{e['id']}` | {e['kind']} | `{e['rule']}` | {loc} | **{e['severity']}** |"
                    )
            lines.append("")
        return "\n".join(lines)

    def backlog_csv(self) -> str:
        entries, _counters = self._grouped_findings()
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=COLUMN_HEADERS)
        writer.writeheader()
        for entry in entries:
            writer.writerow(
                {
                    "id": entry["id"],
                    "seccion": entry["kind"],
                    "regla": entry["rule"],
                    "archivo": entry["file"],
                    "linea": entry["line"],
                    "severidad": entry["severity"],
                    "fase": entry["phase"],
                    "recomendacion": entry["recommendation"],
                }
            )
        return buffer.getvalue()

    def backlog_json(self) -> str:
        entries, counters = self._grouped_findings()
        payload = {
            "project": self.report.project.name,
            "fases": {str(k): v for k, v in PHASE_DESCRIPTIONS.items()},
            "hallazgos": entries,
            "resumen_por_seccion": counters,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    # --- Informe central (reúne todos los entregables) ---

    def _summary_lines(self) -> List[str]:
        """Líneas de resumen ejecutivo: contadores por sección y severidad."""
        entries, counters = self._grouped_findings()
        sev_counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for entry in entries:
            sev_counts[entry["severity"]] = sev_counts.get(entry["severity"], 0) + 1
        lines = [
            "| Sección | Hallazgos |",
            "|---|---:|",
        ]
        for kind in (
            "sast", "secrets", "iac", "cicd", "custom", "cloud", "llm", "deps",
        ):
            lines.append(f"| {kind} | {counters.get(kind, 0)} |")
        lines.append(f"| **Total** | **{len(entries)}** |")
        lines.append("")
        lines.append("**Por severidad:** " + ", ".join(
            f"{sev} x {n}" for sev, n in sev_counts.items() if n
        ))
        lines.append("")
        return lines

    def _backlog_table(self) -> str:
        """Tabla markdown compacta del backlog completo."""
        entries, _counters = self._grouped_findings()
        lines = ["| ID | Tipo | Regla | Archivo | Severidad | Recomendación |", "|---|---|---|---|---|---|"]
        for e in entries:
            loc = f"{e['file']}:{e['line']}" if e["file"] else "—"
            rec = (e["recommendation"] or "")[:80].replace("|", "\\|")
            lines.append(
                f"| `{e['id']}` | {e['kind']} | `{e['rule']}` | {loc} | "
                f"**{e['severity']}** | {rec} |"
            )
        return "\n".join(lines)

    def informe_markdown(self) -> str:
        """Informe central autocontenido: reúne C4, roadmap y backlog."""
        meta = self.report.project
        metrics = self.report.metrics
        lines = [
            f"# Informe central — {meta.name}",
            "",
            "> Auditoría generada por **VibeAudit**. Este documento reúne todos "
            "los entregables del análisis.",
            "",
            "## 1. Datos del proyecto",
            "",
            f"- **Repositorio:** {meta.repository_url or '—'}",
            f"- **Rama:** {meta.default_branch or '—'}",
            f"- **Commit:** {meta.commit_hash or '—'}",
            f"- **Lenguajes:** {', '.join(meta.languages) or '—'}",
            f"- **Frameworks:** {', '.join(meta.frameworks) or '—'}",
            f"- **Líneas de código:** {metrics.lines_of_code or 0}",
            f"- **Archivos de test:** {metrics.test_files or 0}",
            "",
            "## 2. Resumen ejecutivo",
            "",
        ]
        lines.extend(self._summary_lines())
        lines += [
            "## 3. Diagrama C4 — Contexto (nivel 1)",
            "",
            self.c4_context().strip(),
            "",
            "## 4. Diagrama C4 — Contenedores (nivel 2)",
            "",
            self.c4_container().strip(),
            "",
            "## 5. Roadmap de remediación por fases",
            "",
            self.roadmap_markdown().strip(),
            "",
            "## 6. Backlog de remediación",
            "",
            self._backlog_table(),
            "",
            "## 7. Índice de informes y entregables",
            "",
            "### Entregables generados junto a este informe",
            "",
            "- [`c4-context.mmd`](./c4-context.mmd) — diagrama de contexto (Mermaid).",
            "- [`c4-container.mmd`](./c4-container.mmd) — diagrama de contenedores (Mermaid).",
            "- [`roadmap.md`](./roadmap.md) — roadmap por fases según severidad.",
            "- [`backlog.csv`](./backlog.csv) — backlog de remediación (CSV).",
            "- [`backlog.json`](./backlog.json) — backlog de remediación (JSON).",
            "- [`informe-central.md`](./informe-central.md) — este informe (Markdown).",
            "- [`informe-central.html`](./informe-central.html) — este informe (HTML).",
            "- [`informe-ejecutivo.html`](./informe-ejecutivo.html) — informe one-page para stakeholders.",
            "- [`informe-ejecutivo.pdf`](./informe-ejecutivo.pdf) — el mismo informe en PDF.",
            "",
            "### Informes y datos asociados",
            "",
            "Se generan junto al reporte o en la raíz del dashboard (si los flujos "
            "`--sonar-json`, `--publish`, `compare-multi` y `remediate` se ejecutaron):",
            "",
            "- [`audit-report.json`](../audit-report.json) — reporte maestro (JSON).",
            "- [`audit-history.json`](../audit-history.json) — evolución y snapshots.",
            "- [`sonar-issues.json`](../sonar-issues.json) — issues para importar a SonarQube.",
            "- [`remediaciones.md`](./remediaciones.md) — informe de diffs propuestos (MD).",
            "- [`remediaciones.json`](./remediaciones.json) — informe de diffs propuestos (JSON).",
            "- [`remediaciones.patch`](./remediaciones.patch) — patch unificado propuesto.",
            "- [`ranking-riesgo.html`](./ranking-riesgo.html) — ranking multi-repo (HTML).",
            "- [`ranking-riesgo.json`](./ranking-riesgo.json) — ranking multi-repo (JSON).",
            "- [`ranking-riesgo.csv`](./ranking-riesgo.csv) — ranking multi-repo (CSV).",
            "",
        ]
        return "\n".join(lines)

    def _mermaid_body(self, diagram: str) -> str:
        """Devuelve el cuerpo del diagrama Mermaid sin los fences ```mermaid."""
        return "\n".join(
            line for line in diagram.splitlines() if not line.strip().startswith("```")
        ).strip()

    def informe_html(self) -> str:
        """Informe central en HTML autocontenido (estilos inline, imprimible)."""
        meta = self.report.project
        metrics = self.report.metrics

        def esc(text) -> str:
            return html.escape(str(text or ""))

        entries, counters = self._grouped_findings()
        sev_counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for entry in entries:
            sev_counts[entry["severity"]] = sev_counts.get(entry["severity"], 0) + 1

        sev_color = {
            "CRITICAL": "#d93025", "HIGH": "#ea8600", "MEDIUM": "#f2c300",
            "LOW": "#188038", "INFO": "#5f6368",
        }
        section_label = {
            "sast": "Vulnerabilidades (SAST)", "secrets": "Secretos filtrados",
            "iac": "Problemas de IaC", "cicd": "Riesgos CI/CD",
            "custom": "Reglas custom", "cloud": "Seguridad en la nube",
            "llm": "Hallazgos LLM", "deps": "Dependencias con CVEs",
        }
        summary_rows = "\n".join(
            f"<tr><td>{section_label.get(k, k)}</td><td align='right'>{counters.get(k, 0)}</td></tr>"
            for k in ("sast", "secrets", "iac", "cicd", "custom", "cloud", "llm", "deps")
        )
        sev_spans = " ".join(
            f"<span style='background:{sev_color[s]};color:#fff;padding:2px 8px;"
            f"border-radius:10px;font-size:12px;'>{s} x {n}</span>"
            for s, n in sev_counts.items() if n
        )
        backlog_rows = []
        for e in entries:
            color = sev_color.get(e["severity"], "#5f6368")
            backlog_rows.append(
                f"<tr><td><code>{esc(e['id'])}</code></td><td>{esc(e['kind'])}</td>"
                f"<td><code>{esc(e['rule'])}</code></td><td>{esc(e['file'])}</td>"
                f"<td style='color:{color};font-weight:700;'>{esc(e['severity'])}</td>"
                f"<td style='word-wrap:break-word;'>{esc(e['recommendation'])}</td></tr>"
            )
        phases_rows = []
        for phase in (1, 2, 3):
            items = [e for e in entries if e["phase"] == phase]
            rows = "".join(
                f"<tr><td><code>{esc(e['id'])}</code></td><td>{esc(e['kind'])}</td>"
                f"<td><code>{esc(e['rule'])}</code></td><td>{esc(e['file'])}</td>"
                f"<td style='color:{sev_color.get(e['severity'], '#5f6368')};"
                f"font-weight:700;'>{esc(e['severity'])}</td></tr>"
                for e in items
            )
            content = (
                f"<tr><td colspan='5'>Sin hallazgos en esta fase.</td></tr>"
                if not items
                else rows
            )
            phases_rows.append(
                f"<h3>Fase {phase}</h3><p>{esc(PHASE_DESCRIPTIONS[phase])}</p>"
                f"<table style='border-collapse:collapse;width:100%;font-size:13px;'>"
                f"<tr><th style='text-align:left;border-bottom:1px solid #ccc;padding:6px;'>ID</th>"
                f"<th style='text-align:left;border-bottom:1px solid #ccc;padding:6px;'>Tipo</th>"
                f"<th style='text-align:left;border-bottom:1px solid #ccc;padding:6px;'>Regla</th>"
                f"<th style='text-align:left;border-bottom:1px solid #ccc;padding:6px;'>Archivo</th>"
                f"<th style='text-align:left;border-bottom:1px solid #ccc;padding:6px;'>Severidad</th></tr>"
                f"{content}</table>"
            )
        deliverables_links = "\n".join(
            f"<li><a href='{name}' style='text-decoration:none;'>"
            f"<code>{name}</code></a> — {description}</li>"
            for name, description in [
                ("c4-context.mmd", "diagrama C4 de contexto (Mermaid)"),
                ("c4-container.mmd", "diagrama C4 de contenedores (Mermaid)"),
                ("roadmap.md", "roadmap de remediación (Markdown)"),
                ("backlog.csv", "backlog de remediación (CSV)"),
                ("backlog.json", "backlog de remediación (JSON)"),
                ("informe-central.md", "este informe en Markdown"),
                ("informe-central.html", "este informe (HTML)"),
                ("informe-ejecutivo.html", "informe one-page para stakeholders"),
                ("informe-ejecutivo.pdf", "informe ejecutivo en PDF"),
            ]
        )
        associated_links = "\n".join(
            f"<li><a href='{href}' style='text-decoration:none;'>"
            f"<code>{name}</code></a> — {description}</li>"
            for name, href, description in [
                ("audit-report.json", "../audit-report.json",
                 "reporte maestro (JSON)"),
                ("audit-history.json", "../audit-history.json",
                 "evolución y snapshots (dashboard)"),
                ("sonar-issues.json", "../sonar-issues.json",
                 "issues para importar a SonarQube"),
                ("remediaciones.md", "remediaciones.md",
                 "informe de diffs propuestos (MD)"),
                ("remediaciones.json", "remediaciones.json",
                 "informe de diffs propuestos (JSON)"),
                ("remediaciones.patch", "remediaciones.patch",
                 "patch unificado propuesto"),
                ("ranking-riesgo.html", "ranking-riesgo.html",
                 "comparativa multi-repo (HTML)"),
                ("ranking-riesgo.json", "ranking-riesgo.json",
                 "comparativa multi-repo (JSON)"),
                ("ranking-riesgo.csv", "ranking-riesgo.csv",
                 "comparativa multi-repo (CSV)"),
            ]
        )
        mermaid_style = (
            "background:#f5f5f5;border:1px solid #ddd;border-radius:4px;"
            "padding:10px;"
        )
        context_body = self._mermaid_body(self.c4_context())
        container_body = self._mermaid_body(self.c4_container())
        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe central — {esc(meta.name)}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{startOnLoad:true, theme:'default'}});</script>
</head>
<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:0 auto;padding:24px;color:#202124;">
<h1>Informe central — {esc(meta.name)}</h1>
<p><em>Auditoría generada por <strong>VibeAudit</strong>. Este documento reúne todos los entregables del análisis.</em></p>

<h2>1. Datos del proyecto</h2>
<table style="border-collapse:collapse;width:100%;">
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Repositorio</th><td style="border-bottom:1px solid #ccc;padding:6px;">{esc(meta.repository_url)}</td></tr>
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Rama</th><td style="border-bottom:1px solid #ccc;padding:6px;">{esc(meta.default_branch)}</td></tr>
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Commit</th><td style="border-bottom:1px solid #ccc;padding:6px;"><code>{esc(meta.commit_hash)}</code></td></tr>
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Lenguajes</th><td style="border-bottom:1px solid #ccc;padding:6px;">{esc(', '.join(meta.languages))}</td></tr>
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Frameworks</th><td style="border-bottom:1px solid #ccc;padding:6px;">{esc(', '.join(meta.frameworks))}</td></tr>
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Líneas de código</th><td style="border-bottom:1px solid #ccc;padding:6px;">{esc(metrics.lines_of_code or 0)}</td></tr>
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Archivos de test</th><td style="border-bottom:1px solid #ccc;padding:6px;">{esc(metrics.test_files or 0)}</td></tr>
</table>

<h2>2. Resumen ejecutivo</h2>
<table style="border-collapse:collapse;width:60%;">
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Sección</th><th style="text-align:right;border-bottom:1px solid #ccc;padding:6px;">Hallazgos</th></tr>
{summary_rows}
<tr><td style="border-bottom:1px solid #ccc;padding:6px;"><strong>Total</strong></td><td style="border-bottom:1px solid #ccc;padding:6px;text-align:right;"><strong>{len(entries)}</strong></td></tr>
</table>
<p>{sev_spans}</p>

<h2>3. Diagrama C4 — Contexto (nivel 1)</h2>
<pre class="mermaid" style="{mermaid_style}">{context_body}</pre>
<p><em>Código fuente: <code>c4-context.mmd</code></em></p>

<h2>4. Diagrama C4 — Contenedores (nivel 2)</h2>
<pre class="mermaid" style="{mermaid_style}">{container_body}</pre>
<p><em>Código fuente: <code>c4-container.mmd</code></em></p>

<h2>5. Roadmap de remediación por fases</h2>
{"".join(phases_rows)}

<h2>6. Backlog de remediación</h2>
<table style="border-collapse:collapse;width:100%;font-size:13px;table-layout:fixed;">
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">ID</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Tipo</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Regla</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Archivo</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Severidad</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Recomendación</th></tr>
{"".join(backlog_rows)}
</table>

<h2>7. Índice de informes y entregables</h2>
<h3>Entregables generados junto a este informe</h3>
<ul>
{deliverables_links}
</ul>
<h3>Informes y datos asociados</h3>
<p>Se generan junto al reporte o en la raíz del dashboard (si se ejecutaron
<code>--sonar-json</code>, <code>--publish</code>, <code>compare-multi</code> y
<code>remediate</code>):</p>
<ul>
{associated_links}
</ul>
</body>
</html>
"""

    # --- Informe ejecutivo (one-page para stakeholders, sin secretos) ---

    def _ejecutivo_datos(self) -> Dict:
        """Datos resumidos del informe ejecutivo (nunca incluye secretos)."""
        meta = self.report.project
        metrics = self.report.metrics
        entries, counters = self._grouped_findings()
        sev_counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for entry in entries:
            sev_counts[entry["severity"]] = sev_counts.get(entry["severity"], 0) + 1
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        top = sorted(
            entries,
            key=lambda e: (sev_order.get(e["severity"], 9), e["file"] or ""),
        )[:12]
        critical = sev_counts.get("CRITICAL", 0)
        if critical:
            estado, color = "Riesgo crítico", "#d93025"
        elif sev_counts.get("HIGH", 0):
            estado, color = "Atención requerida", "#ea8600"
        elif sev_counts.get("MEDIUM", 0):
            estado, color = "Mejoras recomendadas", "#f2c300"
        else:
            estado, color = "Sin hallazgos relevantes", "#188038"
        return {
            "entries": entries,
            "counters": counters,
            "sev_counts": sev_counts,
            "top": top,
            "estado": estado,
            "estado_color": color,
        }

    def informe_ejecutivo_html(self) -> str:
        """Informe one-page para stakeholders: métricas, semáforo y top hallazgos.

        Diseñado para imprimirse/exportarse a PDF desde el navegador. No
        incluye secretos ni contenido sensible en claro.
        """
        meta = self.report.project
        metrics = self.report.metrics
        d = self._ejecutivo_datos()

        def esc(text) -> str:
            return html.escape(str(text or ""))

        sev_color = {
            "CRITICAL": "#d93025", "HIGH": "#ea8600", "MEDIUM": "#f2c300",
            "LOW": "#188038", "INFO": "#5f6368",
        }
        badges = " ".join(
            f"<span style='background:{sev_color[s]};color:#fff;padding:3px 10px;"
            f"border-radius:12px;font-weight:600;'>{s} · {n}</span>"
            for s, n in d["sev_counts"].items() if n
        )
        top_rows = "".join(
            f"<tr><td>{esc(e['kind'])}</td><td><code>{esc(e['rule'])}</code></td>"
            f"<td><code>{esc(e['file'])}</code></td>"
            f"<td style='color:{sev_color.get(e['severity'], '#5f6368')};"
            f"font-weight:700;'>{esc(e['severity'])}</td>"
            f"<td>{esc(e['recommendation'])}</td></tr>"
            for e in d["top"]
        )
        fecha = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        nube = self.report.cloud_issues
        nube_html = (
            f"<p>🟠 {len(nube)} configuraciones inseguras detectadas "
            f"en {len(self.report.cloud_resources)} recursos analizados.</p>"
            if nube
            else "<p>✅ Sin configuraciones inseguras en la nube.</p>"
        )
        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe ejecutivo — {esc(meta.name)}</title>
<style>
  body {{ font-family: system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
         max-width: 860px; margin: 0 auto; padding: 28px; color: #202124; }}
  h1 {{ font-size: 26px; margin-bottom: 4px; }}
  .meta {{ color: #5f6368; font-size: 13px; }}
  .estado {{ display:inline-block; color:#fff; font-weight:700;
             padding:6px 16px; border-radius:6px; font-size:15px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  th {{ text-align: left; border-bottom: 1px solid #ccc; padding: 6px; }}
  td {{ border-bottom: 1px solid #eee; padding: 6px; }}
  @media print {{ body {{ padding: 0; }} }}
</style>
</head>
<body>
<h1>Informe ejecutivo — {esc(meta.name)}</h1>
<p class="meta">{esc(meta.repository_url or "origen local")} · {esc(meta.default_branch or "—")} · {fecha}</p>
<p><span class="estado" style="background:{d['estado_color']};">{esc(d['estado'])}</span></p>

<h2>Métricas</h2>
<table>
<tr><th>Líneas de código</th><td>{esc(metrics.lines_of_code or 0)}</td>
    <th>Archivos de test</th><td>{esc(metrics.test_files or 0)}</td></tr>
<tr><th>Hallazgos totales</th><td>{len(d['entries'])}</td>
    <th>Dependencias con CVE</th><td>{len(self.report.metrics.dependency_vulnerabilities)}</td></tr>
<tr><th>Frameworks</th><td colspan="3">{esc(', '.join(meta.frameworks) or '—')}</td></tr>
</table>
<p>{badges}</p>

<h2>Principales hallazgos (top 12)</h2>
<table>
<tr><th>Tipo</th><th>Regla</th><th>Archivo</th><th>Severidad</th><th>Recomendación</th></tr>
{top_rows or "<tr><td colspan='5'>Sin hallazgos.</td></tr>"}
</table>

<h2>Seguridad en la nube</h2>
{nube_html}

<h2>Siguientes pasos</h2>
<p>Revisa el <a href="informe-central.html">informe central</a> (diagramas C4, roadmap
por fases y backlog completo) y el <a href="roadmap.md">roadmap</a> para el detalle de remediación.</p>
<p class="meta">Generado por VibeAudit. Documento ejecutivo: no incluye secretos ni contenido sensible.</p>
</body>
</html>
"""

    def informe_ejecutivo_pdf(self) -> bytes:
        """PDF one-page (reportlab) con métricas, semáforo y top hallazgos."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        meta = self.report.project
        metrics = self.report.metrics
        d = self._ejecutivo_datos()

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=16 * mm,
            bottomMargin=16 * mm,
            title=f"Informe ejecutivo — {meta.name}",
        )
        styles = getSampleStyleSheet()
        h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=20, spaceAfter=2)
        h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceBefore=10)
        small = ParagraphStyle(
            "small", parent=styles["Normal"], fontSize=9, textColor=colors.grey
        )
        sev_color = {
            "CRITICAL": colors.HexColor("#d93025"),
            "HIGH": colors.HexColor("#ea8600"),
            "MEDIUM": colors.HexColor("#b8860b"),
            "LOW": colors.HexColor("#188038"),
            "INFO": colors.HexColor("#5f6368"),
        }

        top_table = Table(
            [
                ["Tipo", "Regla", "Archivo", "Severidad", "Recomendación"]
            ]
            + [
                [e["kind"], e["rule"], e["file"] or "", e["severity"],
                 e["recommendation"]]
                for e in d["top"]
            ],
            colWidths=[18 * mm, 34 * mm, 40 * mm, 18 * mm, 62 * mm],
            repeatRows=1,
        )
        story = [
            Paragraph(f"Informe ejecutivo — {meta.name}", h1),
            Paragraph(
                f"{meta.repository_url or 'origen local'} · "
                f"{meta.default_branch or '—'} · "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                small,
            ),
            Spacer(1, 4),
            Paragraph(f"<b>Estado: {d['estado']}</b>", styles["Normal"]),
            Spacer(1, 2),
            Paragraph(
                " · ".join(
                    f"{s}: {n}" for s, n in d["sev_counts"].items() if n
                ) or "Sin hallazgos",
                styles["Normal"],
            ),
            Spacer(1, 8),
            Paragraph("Métricas", h2),
            Table(
                [
                    ["Líneas de código", metrics.lines_of_code or 0,
                     "Archivos de test", metrics.test_files or 0],
                    ["Hallazgos totales", len(d["entries"]),
                     "Dependencias con CVE",
                     len(self.report.metrics.dependency_vulnerabilities)],
                    ["Frameworks", ", ".join(meta.frameworks) or "—", "", ""],
                ],
                colWidths=[40 * mm, 45 * mm, 40 * mm, 45 * mm],
            ),
            Spacer(1, 4),
            Paragraph("Principales hallazgos (top 12)", h2),
            top_table,
            Spacer(1, 4),
            Paragraph("Seguridad en la nube", h2),
            Paragraph(
                f"{len(self.report.cloud_issues)} configuraciones inseguras en "
                f"{len(self.report.cloud_resources)} recursos analizados."
                if self.report.cloud_issues
                else "Sin configuraciones inseguras.",
                styles["Normal"],
            ),
            Spacer(1, 6),
            Paragraph("Generado por VibeAudit. Sin secretos ni contenido sensible.", small),
        ]
        for table in story:
            if isinstance(table, Table):
                table.setStyle(
                    TableStyle(
                        [
                            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.93, 0.93, 0.93)),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ]
                    )
                )
        for row_idx, entry in enumerate(d["top"], start=1):
            top_table.setStyle(
                TableStyle(
                    [
                        ("TEXTCOLOR", (3, row_idx), (3, row_idx),
                         sev_color.get(entry["severity"], colors.black)),
                    ]
                )
            )
        doc.build(story)
        return buffer.getvalue()
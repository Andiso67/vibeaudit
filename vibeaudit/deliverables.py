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
from pathlib import Path
from typing import Dict, List

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
        ]:
            path = out_dir / name
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
            "## 7. Entregables descargables",
            "",
            "Los entregables individuales se generan junto a este informe. "
            "Pulsa el enlace (desde el mismo directorio) para abrirlos:",
            "",
            "- [`c4-context.mmd`](./c4-context.mmd) — diagrama de contexto (Mermaid).",
            "- [`c4-container.mmd`](./c4-container.mmd) — diagrama de contenedores (Mermaid).",
            "- [`roadmap.md`](./roadmap.md) — roadmap por fases según severidad.",
            "- [`backlog.csv`](./backlog.csv) — backlog de remediación (CSV).",
            "- [`backlog.json`](./backlog.json) — backlog de remediación (JSON).",
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

<h2>7. Entregables descargables</h2>
<p>Pulsa cada enlace para abrir o descargar el entregable individual.</p>
<ul>
{deliverables_links}
</ul>
</body>
</html>
"""
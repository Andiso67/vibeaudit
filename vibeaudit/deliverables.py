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

    # --- Diagramas C4 (Mermaid) ---

    def c4_context(self) -> str:
        """C4 nivel 1: contexto del sistema de pre-auditoría."""
        return "\n".join(
            [
                "```mermaid",
                "flowchart TD",
                '    A["Usuario cliente<br/>(solicita la pre-auditoría)"]',
                "    B[\"VibeAudit<br/>Pre-auditoría automatizada en 48h\"]",
                '    C["JSON maestro<br/>(AuditReport)"]',
                '    D["Dashboard de cliente<br/>(Next.js)"]',
                '    E["Entregables<br/>C4 / roadmap / backlog"]',
                "    A -->|pide auditoría| B",
                "    B -->|genera| C",
                "    C -->|lee| D",
                "    C -->|deriva| E",
                "```",
            ]
        )

    def c4_container(self) -> str:
        """C4 nivel 2: contenedores de VibeAudit."""
        return "\n".join(
            [
                "```mermaid",
                "flowchart LR",
                '    subgraph VB["VibeAudit"]',
                '        CLI["CLI (Typer)<br/>vibeaudit scan"]',
                '        ING["RepoIngester<br/>clone + detección"]',
                '        SCAN["Scanners<br/>gitleaks / semgrep / checkov<br/>CI-CD / custom / deps / nube"]',
                '        LLM["Auditor LLM<br/>Ollama / OpenAI"]',
                '        MEM["Memoria local<br/>hallazgos recurrentes"]',
                '        REPO["AuditReporter<br/>JSON / HTML / MD / dashboard"]',
                '        DELIV["Entregables<br/>C4 / roadmap / backlog"]',
                "    end",
                "    ING -->|almacena| SCAN",
                "    SCAN -->|hallazgos| LLM",
                "    SCAN -->|hallazgos| REPO",
                "    LLM -->|llmFindings| REPO",
                "    MEM -->|recurrentFindings| REPO",
                "    REPO -->|JSON maestro| DELIV",
                "```",
            ]
        )

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
            "## 7. Entregables individuales",
            "",
            "- `c4-context.mmd` — diagrama de contexto (Mermaid).",
            "- `c4-container.mmd` — diagrama de contenedores (Mermaid).",
            "- `roadmap.md` — roadmap por fases según severidad.",
            "- `backlog.csv` — backlog de remediación (CSV).",
            "- `backlog.json` — backlog de remediación (JSON).",
            "- `informe-central.html` — este informe en HTML.",
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
            rec = (e["recommendation"] or "")[:120]
            backlog_rows.append(
                f"<tr><td><code>{esc(e['id'])}</code></td><td>{esc(e['kind'])}</td>"
                f"<td><code>{esc(e['rule'])}</code></td><td>{esc(e['file'])}</td>"
                f"<td style='color:{color};font-weight:700;'>{esc(e['severity'])}</td>"
                f"<td>{esc(rec)}</td></tr>"
            )
        mermaid_style = (
            "background:#f5f5f5;border:1px solid #ddd;border-radius:4px;"
            "padding:10px;font-family:monospace;white-space:pre;overflow-x:auto;"
        )
        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe central — {esc(meta.name)}</title>
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
<pre style="{mermaid_style}">{esc(self._mermaid_body(self.c4_context()))}</pre>

<h2>4. Diagrama C4 — Contenedores (nivel 2)</h2>
<pre style="{mermaid_style}">{esc(self._mermaid_body(self.c4_container()))}</pre>

<h2>5. Roadmap de remediación por fases</h2>
<table style="border-collapse:collapse;width:100%;">
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Fase</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Descripción</th><th style="text-align:right;border-bottom:1px solid #ccc;padding:6px;">Hallazgos</th></tr>
{f"".join(
    "<tr><td style='border-bottom:1px solid #eee;padding:6px;'>Fase " + str(ph) + "</td>"
    "<td style='border-bottom:1px solid #eee;padding:6px;'>" + esc(PHASE_DESCRIPTIONS[ph]) + "</td>"
    "<td style='border-bottom:1px solid #eee;padding:6px;text-align:right;'>" + str(sum(1 for e in entries if e['phase'] == ph)) + "</td></tr>"
    for ph in (1, 2, 3)
)}

<h2>6. Backlog de remediación</h2>
<table style="border-collapse:collapse;width:100%;font-size:13px;">
<tr><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">ID</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Tipo</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Regla</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Archivo</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Severidad</th><th style="text-align:left;border-bottom:1px solid #ccc;padding:6px;">Recomendación</th></tr>
{"".join(backlog_rows)}
</table>

<h2>7. Entregables individuales</h2>
<ul>
<li><code>c4-context.mmd</code> — diagrama de contexto (Mermaid).</li>
<li><code>c4-container.mmd</code> — diagrama de contenedores (Mermaid).</li>
<li><code>roadmap.md</code> — roadmap por fases según severidad.</li>
<li><code>backlog.csv</code> — backlog de remediación (CSV).</li>
<li><code>backlog.json</code> — backlog de remediación (JSON).</li>
<li><code>informe-central.html</code> — este informe en HTML.</li>
</ul>
</body>
</html>
"""
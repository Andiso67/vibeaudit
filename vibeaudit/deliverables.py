"""Generador de entregables de cliente (ítem 6 del Sprint 3).

A partir del JSON maestro (AuditReport) se generan, con --deliverables <dir>:
  - c4-context.mmd      # Diagrama C4 nivel 1 (Contexto) en Mermaid
  - c4-container.mmd    # Diagrama C4 nivel 2 (Contenedores) en Mermaid
  - roadmap.md          # Roadmap por fases según severidad de hallazgos
  - backlog.csv         # Backlog de remediación (CSV)
  - backlog.json        # Backlog de remediación (JSON)

Todo determinista y sin red, para poder verificarlo en tests y CI.
"""

import csv
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
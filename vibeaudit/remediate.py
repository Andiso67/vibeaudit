"""Informe de remediación en forma de diffs propuestos (item 5 del Sprint 6).

Solo genera el informe (patch unificado + JSON + Markdown). NUNCA modifica
archivos del repositorio: la remediación queda como propuesta revisable.
"""

import difflib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

ACTION_DIFF = "diff"
ACTION_COMMAND = "comando"
ACTION_MANUAL = "revision-manual"


def _propose_line_removal(
    source_dir: Optional[Path], file: str, line: int, reason: str
) -> Dict:
    """Propone eliminar la línea `line` de `file` con un diff unificado."""
    path = Path(source_dir) / file if source_dir else None
    if path is None or not path.is_file():
        return {
            "diff": None,
            "nota": f"Archivo no disponible en --source para generar diff: {file}",
        }
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if line < 1 or line > len(lines):
        return {"diff": None, "nota": f"Línea {line} fuera de rango en {file}"}
    removed = lines[line - 1]
    new_lines = [l for i, l in enumerate(lines, start=1) if i != line]
    diff = "".join(
        difflib.unified_diff(
            lines,
            new_lines,
            fromfile=f"a/{file}",
            tofile=f"b/{file}",
            lineterm="",
        )
    )
    diff = f"diff --git a/{file} b/{file}\n" + diff
    return {"diff": diff, "nota": reason, "removed": removed.strip()}


def _dep_command(dep_name: str, ecosystem: str, fixed_version: Optional[str] = None) -> str:
    target = fixed_version or "latest"
    if ecosystem == "npm":
        return f"npm install {dep_name}@{target} && npm audit fix"
    if ecosystem == "pip":
        return f"pip install --upgrade {dep_name}=={target}"
    return f"Actualizar {dep_name} a {target}"


def build_proposals(report, source_dir: Optional[Path] = None) -> List[Dict]:
    """Construye propuestas de remediación (diffs/comandos/revisión) por hallazgo."""
    proposals: List[Dict] = []

    def add(kind: str, rule: str, severity, file: str, line: int,
            action: str, diff: Optional[Dict] = None,
            command: Optional[str] = None, nota: str = "") -> None:
        proposals.append(
            {
                "id": len(proposals) + 1,
                "kind": kind,
                "rule": rule,
                "severity": severity.value if hasattr(severity, "value") else str(severity),
                "file": file,
                "line": line,
                "action": action,
                "diff": (diff or {}).get("diff"),
                "nota": (diff or {}).get("nota", nota),
                "removed": (diff or {}).get("removed"),
                "command": command,
            }
        )

    for secret in report.secrets:
        add(
            "secrets", secret.type, secret.severity, secret.file, secret.line,
            ACTION_DIFF,
            diff=_propose_line_removal(
                source_dir, secret.file, secret.line,
                "Eliminar la credencial filtrada y rotarla después.",
            ),
            command=f"Rotar la credencial {secret.type} en el proveedor",
        )

    for issue in report.custom_issues:
        rule = issue.rule or ""
        if "console.log" in rule or rule == "vibe-js-console-log":
            add(
                "custom", rule, issue.severity, issue.file, issue.line,
                ACTION_DIFF,
                diff=_propose_line_removal(
                    source_dir, issue.file, issue.line,
                    "Eliminar el console.log o sustituirlo por logging estructurado.",
                ),
            )
        else:
            add(
                "custom", rule, issue.severity, issue.file, issue.line,
                ACTION_MANUAL,
                nota="Revisión manual: requiere criterio de implementación.",
            )

    for dep in report.metrics.dependency_vulnerabilities:
        add(
            "deps", dep.name, dep.severity, "package.json", 0,
            ACTION_COMMAND,
            command=_dep_command(dep.name, dep.ecosystem, dep.fixed_version),
            nota="; ".join(dep.cve_ids or []),
        )

    for finding in report.llm_findings:
        file = (finding.related_files or [""])[0]
        line = 0
        if finding.evidence and ":" in finding.evidence:
            tail = finding.evidence.rsplit(":", 1)[-1].strip()
            if tail.isdigit():
                line = int(tail)
        add(
            "llm", finding.checklist_ref or "checklist", finding.severity,
            file, line,
            ACTION_MANUAL,
            nota=finding.title,
        )

    for vuln in report.vulnerabilities:
        add(
            "sast", vuln.rule, vuln.severity, vuln.file, vuln.line,
            ACTION_MANUAL,
            nota="Revisión manual: aplicar la corrección según la regla.",
        )
    for issue in report.iac_issues:
        add(
            "iac", issue.rule, issue.severity, issue.file, issue.line,
            ACTION_MANUAL,
            nota="Revisión manual de la configuración de infraestructura.",
        )
    for issue in report.cicd_issues:
        add(
            "cicd", issue.rule, issue.severity, issue.file, issue.line,
            ACTION_MANUAL,
            nota="Revisión manual del pipeline.",
        )
    return proposals


def proposals_patch(proposals: List[Dict]) -> str:
    """Patch unificado con todos los diffs propuestos."""
    diffs = [p["diff"] for p in proposals if p["diff"]]
    if not diffs:
        return "# Sin diffs propuestos (revisar comandos y notas).\n"
    return "\n".join(diffs) + "\n"


def proposals_json(proposals: List[Dict]) -> str:
    return json.dumps(proposals, ensure_ascii=False, indent=2)


def proposals_markdown(proposals: List[Dict]) -> str:
    """Informe Markdown con diffs propuestos, comandos y notas."""
    fecha = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    by_action = {
        ACTION_DIFF: "con diff propuesto",
        ACTION_COMMAND: "solo comando",
        ACTION_MANUAL: "revisión manual",
    }
    rows = []
    for p in proposals:
        sev = p["severity"].upper()
        line = f":{p['line']}" if p["line"] else ""
        rows.append(
            f"### {p['id']}. [{sev}] {p['rule']} — `{p['file']}{line}` "
            f"({by_action.get(p['action'], p['action'])})\n"
        )
        if p["nota"]:
            rows.append(f"- Nota: {p['nota']}\n")
        if p["command"]:
            rows.append(f"- Comando: `{p['command']}`\n")
        if p["diff"]:
            rows.append(f"```diff\n{p['diff']}\n```\n")
        rows.append("")
    counts = {a: sum(1 for p in proposals if p["action"] == a)
              for a in (ACTION_DIFF, ACTION_COMMAND, ACTION_MANUAL)}
    return (
        "# Informe de remediación (diffs propuestos)\n\n"
        f"_Generado por VibeAudit {fecha}. Solo informativo: nada se aplica "
        "automáticamente._\n\n"
        f"Total: {len(proposals)} propuestas — "
        f"{counts[ACTION_DIFF]} con diff, {counts[ACTION_COMMAND]} solo comando, "
        f"{counts[ACTION_MANUAL]} revisión manual.\n\n"
        + "\n".join(rows)
    )

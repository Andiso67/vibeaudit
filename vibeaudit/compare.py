"""Comparativa entre el auditor LLM y SonarQube (SAST estático).

Un hallazgo LLM puede ser:

- **coincide** con uno o más issues de SonarQube en los mismos archivos:
  el problema ya lo detecta el análisis estático tradicional.
- **único (LLM-only)**: lo ve el LLM pero no SonarQube. Estos son el valor
  incremental del motor narrativo.
- **sonar-only**: issues de SonarQube que el LLM no citó en sus archivos
  (luces del SAST tradicional).

La comparación cruza por archivos relativos (los hallazgos LLM citan
``related_files`` y las issues de SonarQube tienen ``primaryLocation.filePath``).
"""

import json
from pathlib import Path
from typing import List, Optional, TypedDict


class LLMSummary(TypedDict):
    total: int
    covered_by_sonar: int
    unique_llm: int


class ComparisonResult(TypedDict):
    summary: LLMSummary
    sonar_imported: int
    sonar_engines: dict
    details: list


def load_report(path: Path) -> dict:
    """Carga un report de vibeaudit desde disco."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_sonar_issues(path: Path) -> List[dict]:
    """Carga las issues del import (sonar-issues.json) o del scan de SonarQube."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "issues" in data:
        return data["issues"]
    return data


def _relative_file(issue: dict) -> str:
    return (issue.get("primaryLocation") or {}).get("filePath", "")


def compare(
    report: dict,
    sonar_issues: List[dict],
) -> ComparisonResult:
    """Cruza hallazgos LLM del reporte contra los issues importados/analizados."""
    llm_findings = report.get("llmFindings") or []

    sonar_by_file: dict = {}
    for issue in sonar_issues:
        sonar_by_file.setdefault(_relative_file(issue), []).append(issue)

    details = []
    covered = 0
    for finding in llm_findings:
        related = finding.get("relatedFiles") or []
        matching_files = [f for f in related if f in sonar_by_file]
        matching_rules = sorted(
            {
                issue.get("ruleId", "")
                for f in matching_files
                for issue in sonar_by_file.get(f, [])
            }
        )
        is_covered = bool(matching_files)
        if is_covered:
            covered += 1
        details.append(
            {
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "checklistRef": finding.get("checklistRef"),
                "relatedFiles": related,
                "coveredBySonar": is_covered,
                "matchingSonarRules": matching_rules,
            }
        )

    engines: dict = {}
    for issue in sonar_issues:
        rule = issue.get("ruleId", "")
        prefix = rule.split("-", 1)[0] if "-" in rule else "otro"
        engines[prefix] = engines.get(prefix, 0) + 1

    return {
        "summary": {
            "total": len(llm_findings),
            "covered_by_sonar": covered,
            "unique_llm": len(llm_findings) - covered,
        },
        "sonar_imported": len(sonar_issues),
        "sonar_engines": engines,
        "details": details,
    }


def to_text(result: ComparisonResult) -> str:
    """Renderiza la comparativa como texto legible para consola/docs."""
    s = result["summary"]
    lines = [
        "Comparativa LLM vs SonarQube",
        "=" * 40,
        f"Hallazgos del auditor LLM : {s['total']}",
        f"  coinciden con SonarQube : {s['covered_by_sonar']}",
        f"  únicos del LLM          : {s['unique_llm']} (valor incremental)",
        f"Issues de SonarQube       : {result['sonar_imported']}",
        f"Por motor                 : {result['sonar_engines']}",
    ]
    for detail in result["details"]:
        marca = "(" + ("coincide" if detail["coveredBySonar"] else "ÚNICO") + ")"
        lines.append(
            f"- {marca} [{detail['severity']}] {detail['title']}: "
            f"{', '.join(detail['relatedFiles'])} "
            f"{'→ ' + ', '.join(detail['matchingSonarRules']) if detail['matchingSonarRules'] else ''}"
        )
    return "\n".join(lines)
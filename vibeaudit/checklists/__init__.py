"""Carga y validación de los bundles de checklists YAML (datos del ítem 2).

Los checklists son datos: se definen en YAML dentro de este paquete
(12-factor, OWASP Top 10, AWS Well-Architected) y se cargan en modelos
`ChecklistItem`. Cada ítem puede declarar reglas de mapeo hallazgo→checklist
(secciones del reporte, patrones de id de regla y severidad mínima).
"""

from fnmatch import fnmatchcase
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml
from pydantic import ValidationError

from vibeaudit.models import (
    AppliedChecklist,
    AuditReport,
    ChecklistItem,
    ChecklistMatch,
    Severity,
)

# Orden de severidad: mayor índice = más grave
_SEVERITY_ORDER = [s.value for s in [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]]

# Secciones del reporte → ruta del atributo en AuditReport
REPORT_SECTIONS = {
    "sast": ("vulnerabilities",),
    "secrets": ("secrets",),
    "iac": ("iac_issues",),
    "cicd": ("cicd_issues",),
    "custom": ("custom_issues",),
    "deps": ("metrics", "dependency_vulnerabilities"),
}

BUNDLE_DIR = Path(__file__).resolve().parent


class ChecklistBundleError(ValueError):
    """El bundle YAML es inválido (estructura, ids duplicados, campos obligatorios)."""


def _load_yaml(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except OSError as exc:
        raise ChecklistBundleError(f"No se pudo leer {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ChecklistBundleError(f"YAML inválido en {path}: {exc}") from exc


def load_checklist_file(path: Path) -> List[ChecklistItem]:
    """Carga un único archivo YAML de checklist y devuelve sus items."""
    data = _load_yaml(path)
    items = data.get("items")
    if not isinstance(items, list):
        raise ChecklistBundleError(f"{path}: falta la lista 'items'")
    parsed: List[ChecklistItem] = []
    for raw in items:
        if not isinstance(raw, dict):
            raise ChecklistBundleError(f"{path}: un ítem de checklist no es un diccionario")
        try:
            parsed.append(ChecklistItem(**raw))
        except ValidationError as exc:
            raise ChecklistBundleError(
                f"{path}: ítem inválido {raw.get('id')!r}: {exc}"
            ) from exc
    _check_unique_ids(path, parsed)
    return parsed


def load_checklists(bundle_dir: Optional[Path] = None) -> List[ChecklistItem]:
    """Carga el bundle completo (todos los YAML del directorio indicado)."""
    directory = bundle_dir or BUNDLE_DIR
    items: List[ChecklistItem] = []
    for path in sorted(directory.glob("*.yaml")):
        items.extend(load_checklist_file(path))
    return items


def _check_unique_ids(path: Path, items: List[ChecklistItem]) -> None:
    ids = [item.id for item in items]
    duplicates = {id for id in ids if ids.count(id) > 1}
    if duplicates:
        raise ChecklistBundleError(f"{path}: ids duplicados: {sorted(duplicates)}")


def match_finding(
    item: ChecklistItem,
    section: str,
    rule: Optional[str] = None,
    severity: Optional[Severity] = None,
) -> bool:
    """¿Aplica este item al hallazgo según su regla de mapeo?"""
    if item.match is None:
        return False
    match: ChecklistMatch = item.match
    if section not in match.sections:
        return False
    if match.min_severity is not None and severity is not None:
        if _severity_rank(severity) < _severity_rank(match.min_severity):
            return False
    if match.rules:
        if not rule or not any(fnmatchcase(rule, pattern) for pattern in match.rules):
            return False
    return True


def _severity_rank(severity: Severity) -> int:
    return _SEVERITY_ORDER.index(severity.value)


def _section_items(report: AuditReport, section: str) -> Iterable:
    """Devuelve los hallazgos de una sección del report (rule, severity)."""
    path = REPORT_SECTIONS.get(section)
    if path is None:
        return []
    obj: object = report
    for part in path:
        obj = getattr(obj, part)
    return obj or []


def match_report(items: List[ChecklistItem], report: AuditReport) -> Dict[str, int]:
    """Mapa {item_id: nº de hallazgos mapeados} en el report completo."""
    matched: Dict[str, int] = {}
    for item in items:
        count = 0
        for section in (item.match.sections if item.match else []):
            for finding_item in _section_items(report, section):
                rule = getattr(finding_item, "rule", None)
                severity = getattr(finding_item, "severity", None)
                if match_finding(item, section, rule, severity):
                    count += 1
        if count:
            matched[item.id] = count
    return matched


def applied_checklists(
    items: List[ChecklistItem], report: AuditReport
) -> List[AppliedChecklist]:
    """Resumen de checklists aplicados (por framework) para el report maestro."""
    matched = match_report(items, report)
    grouped: Dict[str, List[ChecklistItem]] = {}
    for item in items:
        grouped.setdefault(item.framework or "General", []).append(item)
    result: List[AppliedChecklist] = []
    for name, group_items in sorted(grouped.items()):
        item_count = len(group_items)
        matched_findings = sum(matched.get(item.id, 0) for item in group_items)
        result.append(
            AppliedChecklist(
                name=name,
                item_count=item_count,
                matched_findings=matched_findings,
            )
        )
    return result
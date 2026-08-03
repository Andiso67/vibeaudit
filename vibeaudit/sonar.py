"""Integración con SonarQube (ítem 7 del Sprint 3).

Pieza 1 — Generic Issue Import: exporta los hallazgos del JSON maestro al
formato `sonar-issues.json` de SonarQube (Generic Issue Import). Sirve para
subir resultados de VibeAudit a un SonarQube existente: los hallazgos
aparecen en sus dashboards y Quality Gate. Solo entran los hallazgos con
archivo (SAST, secretos, IaC, CI/CD y custom); los sin archivo (nube, LLM,
deps) no se pueden localizar en el repo y se descartan del import.

Pieza 2 — sonar-scanner: passthrough al escáner oficial de SonarQube sobre
el repo si el binario y la configuración del servidor existen. Requiere
`sonar-scanner` instalado y proyecto configurado (sonar-project.properties).
"""

import json
import subprocess
from pathlib import Path
from typing import List

from rich.console import Console

from vibeaudit.models import Severity

console = Console()

# Mapeo de severidad de VibeAudit a SonarQube
SONARQUBE_SEVERITY = {
    Severity.CRITICAL: "BLOCKER",
    Severity.HIGH: "CRITICAL",
    Severity.MEDIUM: "MAJOR",
    Severity.LOW: "MINOR",
    Severity.INFO: "INFO",
}

# Tipo SonarQube para hallazgos de seguridad
SONARQUBE_TYPE = "VULNERABILITY"

# EngineId propio para que SonarQube sepa que los hallazgos vienen de VibeAudit
ENGINE_ID = "vibeaudit"

# SonarQube limita las issues importables por reporte
ISSUE_LIMIT = 1000

SONAR_SCANNER_BIN = "sonar-scanner"
SONAR_SCANNER_TIMEOUT = 600


def _severity_of(severity) -> str:
    """Traduce un Severity de VibeAudit a la escala de SonarQube."""
    value = severity.value if hasattr(severity, "value") else str(severity)
    try:
        return SONARQUBE_SEVERITY[Severity(str(value).upper())]
    except (KeyError, ValueError):
        return "MAJOR"


def to_sonar_issues(report) -> dict:
    """Convierte un AuditReport al formato Generic Issue Import de SonarQube."""
    issues: List[dict] = []

    # (prefijo de ruleId, items, atributo del id de regla, título del hallazgo)
    groups = [
        ("sast", report.vulnerabilities, "rule", "Vulnerabilidad SAST"),
        ("secret", report.secrets, "type", "Secreto filtrado"),
        ("iac", report.iac_issues, "rule", "Problema de IaC"),
        ("cicd", report.cicd_issues, "rule", "Riesgo en CI/CD"),
        ("custom", report.custom_issues, "rule", "Regla custom"),
    ]
    for engine, items, rule_attr, title in groups:
        for item in items:
            rule_id = getattr(item, rule_attr, "") or "unknown"
            message = f"[{title}] {rule_id}"
            snippet = getattr(item, "snippet", None) or ""
            if snippet:
                message += f" — {snippet}"
            issues.append(
                {
                    "engineId": ENGINE_ID,
                    "ruleId": f"{engine}-{rule_id}",
                    "severity": _severity_of(item.severity),
                    "type": SONARQUBE_TYPE,
                    "primaryLocation": {
                        "message": message,
                        "filePath": item.file,
                        "textRange": {
                            "startLine": item.line,
                            "endLine": item.line,
                            "startOffset": 0,
                            "endOffset": len(snippet),
                        },
                    },
                    "effortMinutes": 15,
                }
            )
    return {"issues": issues[:ISSUE_LIMIT]}


def save_sonar_json(report, path: Path) -> None:
    """Escribe el fichero sonar-issues.json en el formato de import."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(to_sonar_issues(report), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


class SonarRunner:
    """Invoca sonar-scanner (análisis real de SonarQube) sobre un repo.

    Es un passthrough: la configuración del servidor (URL, token, organización)
    se lee de sonar-project.properties / sonar-scanner.properties del proyecto.
    """

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    @staticmethod
    def is_installed() -> bool:
        """Verifica si el binario sonar-scanner está disponible."""
        try:
            result = subprocess.run(
                [SONAR_SCANNER_BIN, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    def scan(self) -> int:
        """Ejecuta sonar-scanner sobre el repo; devuelve su returncode."""
        if not self.is_installed():
            raise RuntimeError(
                "sonar-scanner no está instalado. Instálalo y configura el "
                "proyecto (sonar-project.properties con URL y token del "
                "servidor SonarQube) antes de usarlo."
            )
        result = subprocess.run(
            [
                SONAR_SCANNER_BIN,
                f"-Dsonar.projectBaseDir={self.repo_path}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=SONAR_SCANNER_TIMEOUT,
        )
        return result.returncode
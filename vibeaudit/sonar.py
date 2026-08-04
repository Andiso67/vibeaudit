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
from typing import List, Optional

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

# Severidad SonarQube: las más graves se importan primero si hay límite
SONARQUBE_SEVERITY_RANK = {
    "BLOCKER": 4,
    "CRITICAL": 3,
    "MAJOR": 2,
    "MINOR": 1,
    "INFO": 0,
}

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
    for cloud in report.cloud_issues:
        file_path = _cloud_file_path(report, cloud)
        if not file_path:
            console.print(
                f"[bold yellow]Advertencia:[/] issue de nube "
                f"[cyan]{cloud.rule}[/] sin archivo IaC al que asociar en "
                f"SonarQube; se omite del import."
            )
            continue
        issues.append(
            {
                "engineId": ENGINE_ID,
                "ruleId": f"cloud-{cloud.rule}",
                "severity": _severity_of(cloud.severity),
                "type": SONARQUBE_TYPE,
                "primaryLocation": {
                    "message": (
                        f"[Config insegura en la nube] {cloud.rule} — "
                        f"{cloud.description} Recomendación: "
                        f"{cloud.recommendation}"
                    ),
                    "filePath": file_path,
                    "textRange": {
                        "startLine": 1,
                        "endLine": 1,
                        "startOffset": 0,
                        "endOffset": 0,
                    },
                },
                "effortMinutes": 15,
            }
        )
    issues.sort(
        key=lambda issue: SONARQUBE_SEVERITY_RANK.get(issue["severity"], 0),
        reverse=True,
    )
    return {"issues": issues[:ISSUE_LIMIT]}


def _cloud_file_path(report, cloud) -> Optional[str]:
    """Asocia una issue de nube (sin archivo) al primer archivo IaC del repo.

    SonarQube exige que toda issue externa tenga una localización en un
    archivo del proyecto analizado; las issues de nube no nacen de un archivo,
    así que se anclan al primer archivo IaC (Dockerfile, docker-compose.yml,
    Terraform...) como proxy de la infraestructura que gobierna el recurso.
    """
    candidate = None
    for path in report.project.iac_files or []:
        candidate = path
        break
    if candidate is None:
        candidate = getattr(report, "_iac_files_default", None)
    return candidate


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
    Si se pasa `issues_path` (sonar-issues.json), se lo entrega al escáner vía
    `-Dsonar.externalIssuesReportPaths`, que es como SonarQube importa los
    hallazgos externos (Generic Issue Import) durante el análisis.
    """

    def __init__(self, repo_path: Path, issues_path: Optional[Path] = None):
        self.repo_path = repo_path
        self.issues_path = issues_path

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
        cmd = [
            SONAR_SCANNER_BIN,
            f"-Dsonar.projectBaseDir={self.repo_path}",
        ]
        if self.issues_path is not None:
            cmd.append(f"-Dsonar.externalIssuesReportPaths={self.issues_path}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=SONAR_SCANNER_TIMEOUT,
        )
        return result.returncode
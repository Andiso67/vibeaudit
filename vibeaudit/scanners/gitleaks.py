"""Scanner de secretos basado en Gitleaks."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from rich.console import Console

from vibeaudit.models import Secret, Severity

console = Console()

# Patrones de reglas que se consideran críticas
CRITICAL_RULES = (
    "aws-access-token",
    "aws-secret-access-key",
    "github",
    "gitlab",
    "slack",
    "stripe",
    "google-api-key",
    "twilio",
    "private-key",
    "ssh",
    "gcp",
    "azure",
)


class GitleaksScanner:
    """Ejecuta Gitleaks sobre un repositorio y convierte los hallazgos en Secret."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    @staticmethod
    def is_installed() -> bool:
        """Verifica si gitleaks está disponible en el sistema."""
        try:
            result = subprocess.run(
                ["gitleaks", "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    def scan(self) -> List[Secret]:
        """Ejecuta gitleaks detect y devuelve la lista de Secret encontrados."""
        if not self.is_installed():
            raise RuntimeError(
                "Gitleaks no está instalado. Instálalo con: "
                "brew install gitleaks"
            )

        result = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                str(self.repo_path),
                "--report-format",
                "json",
                "--report-path",
                "/dev/stdout",
                "--no-banner",
                "--redact",
                "0",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )

        # Exit codes de gitleaks:
        #   0 = sin hallazgos
        #   1 = hallazgos encontrados (no es un error)
        #   126 = error de ejecución
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"Gitleaks falló con código {result.returncode}: "
                f"{result.stderr.strip()}"
            )

        if not result.stdout.strip():
            return []

        return self._parse_output(result.stdout)

    def _parse_output(self, raw_output: str) -> List[Secret]:
        """Convierte el JSON de gitleaks en objetos Secret."""
        try:
            findings = json.loads(raw_output)
        except json.JSONDecodeError:
            console.print("[bold yellow]Advertencia:[/] salida de gitleaks no es JSON")
            return []

        if not isinstance(findings, list):
            return []

        secrets: List[Secret] = []
        for finding in findings:
            rule = finding.get("RuleID", "unknown-rule")
            severity = (
                Severity.CRITICAL
                if any(token in rule.lower() for token in CRITICAL_RULES)
                else Severity.HIGH
            )
            secrets.append(
                Secret(
                    type=rule,
                    file=finding.get("File", ""),
                    line=finding.get("StartLine", 0),
                    severity=severity,
                )
            )
        return secrets

"""Scanner de secretos basado en Gitleaks."""

import json
import os
import shutil
import subprocess
import tempfile
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

        # El reporte va a un tempfile: /dev/stdout no es fiable en macOS
        # (permission denied con pipes) y sin --report-path no se emite JSON
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "gitleaks.json")
            result = subprocess.run(
                [
                    "gitleaks",
                    "detect",
                    "--source",
                    str(self.repo_path),
                    "--report-format",
                    "json",
                    "--report-path",
                    report_path,
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

            # Exit 1 con FTL en stderr es un error de gitleaks disfrazado de
            # "hallazgos" (p. ej. report path no escribible)
            if result.returncode == 1 and "FTL" in result.stderr:
                raise RuntimeError(
                    f"Gitleaks falló: {result.stderr.strip()}"
                )

            try:
                with open(report_path, "r", encoding="utf-8") as report:
                    raw_output = report.read()
            except OSError:
                return []

        if not raw_output.strip():
            return []

        return self._parse_output(raw_output)

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
            # Hallazgos malformados se ignoran: un crash aquí rompería el
            # reporte completo, no solo este hallazgo
            if not isinstance(finding, dict):
                continue
            rule = finding.get("RuleID") or "unknown-rule"
            file_path = finding.get("File") or ""
            if not file_path:
                continue
            severity = (
                Severity.CRITICAL
                if any(token in rule.lower() for token in CRITICAL_RULES)
                else Severity.HIGH
            )
            secrets.append(
                Secret(
                    type=rule,
                    file=file_path,
                    # gitleaks siempre da línea >= 1; proteger el modelo por si
                    # un hallazgo raro devuelve 0 o sin StartLine
                    line=finding.get("StartLine") or 1,
                    severity=severity,
                )
            )
        return secrets

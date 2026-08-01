"""Scanner de reglas custom "Vibe Coding" basado en Semgrep."""

import json
import os
import subprocess
from pathlib import Path
from typing import List

from rich.console import Console

from vibeaudit.models import Severity, Vulnerability

console = Console()


class CustomRulesScanner:
    """Ejecuta semgrep con un bundle de reglas YAML propio del usuario.

    A diferencia de SemgrepScanner (que solo reporta HIGH/CRITICAL de la
    config auto), este scanner conserva todas las severidades: las reglas
    custom de estilo (SELECT *, `any`, logging sin logger) suelen ser
    WARNING/INFO.
    """

    def __init__(self, repo_path: Path, rules_dir: Path):
        self.repo_path = repo_path
        self.rules_dir = rules_dir

    @staticmethod
    def is_installed() -> bool:
        """Verifica si semgrep está disponible en el sistema."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    def scan(self) -> List[Vulnerability]:
        """Ejecuta semgrep con las reglas custom y devuelve los hallazgos."""
        if not self.is_installed():
            raise RuntimeError(
                "Semgrep no está instalado. Instálalo con: "
                "brew install semgrep"
            )
        if not self.rules_dir.is_dir():
            raise ValueError(
                f"El directorio de reglas no existe o no es un directorio: "
                f"{self.rules_dir}"
            )

        result = subprocess.run(
            [
                "semgrep",
                "scan",
                "--config",
                str(self.rules_dir),
                "--json",
                "--quiet",
                str(self.repo_path),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )

        # Exit codes de semgrep:
        #   0 = sin hallazgos, 1 = hallazgos, 2 = error
        if result.returncode == 2:
            raise RuntimeError(
                f"Semgrep falló con código 2: {result.stderr.strip()}"
            )

        if not result.stdout.strip():
            return []

        return self._parse_output(result.stdout, str(self.rules_dir))

    def _parse_output(
        self, raw_output: str, rules_dir: str = ""
    ) -> List[Vulnerability]:
        """Convierte el JSON de semgrep en objetos Vulnerability (todas las severidades)."""
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            console.print("[bold yellow]Advertencia:[/] salida de semgrep no es JSON")
            return []

        if data.get("errors"):
            console.print(
                f"[bold yellow]Advertencia:[/] semgrep reportó {len(data['errors'])} "
                f"errores de escaneo (archivos no analizados)"
            )

        # semgrep antepone el path del directorio como namespace al check_id
        namespace = ".".join(part for part in rules_dir.split(os.sep) if part)
        namespace_prefix = f"{namespace}." if namespace else ""

        vulnerabilities: List[Vulnerability] = []
        for finding in data.get("results", []):
            severity = self._map_severity(finding.get("extra", {}).get("severity"))
            start = finding.get("start", {})
            check_id = finding.get("check_id", "unknown-rule")
            if check_id.startswith(namespace_prefix):
                check_id = check_id[len(namespace_prefix):]
            vulnerabilities.append(
                Vulnerability(
                    rule=check_id,
                    file=self._relative_path(finding.get("path", "")),
                    line=start.get("line", 0),
                    severity=severity,
                    snippet=finding.get("extra", {}).get("lines"),
                )
            )
        return vulnerabilities

    def _relative_path(self, file_path: str) -> str:
        """Convierte paths absolutos del repo en paths relativos."""
        if not self.repo_path or not file_path:
            return file_path
        try:
            return str(Path(file_path).relative_to(self.repo_path))
        except ValueError:
            return file_path

    @staticmethod
    def _map_severity(semgrep_severity: str) -> Severity:
        """Mapea la severidad de semgrep (ERROR/WARNING/INFO) al enum Severity."""
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return mapping.get(semgrep_severity.upper(), Severity.INFO)

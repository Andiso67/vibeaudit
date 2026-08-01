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
        yaml_files = (
            list(self.rules_dir.glob("*.yml"))
            + list(self.rules_dir.glob("*.yaml"))
            + list(self.rules_dir.rglob("*.yml"))
            + list(self.rules_dir.rglob("*.yaml"))
        )
        if not yaml_files:
            console.print(
                "[bold yellow]Advertencia:[/] el directorio de reglas no tiene "
                "archivos .yml/.yaml, no se ejecutan reglas custom"
            )
            return []

        # Path absoluto: semgrep usa el path del config como namespace del
        # check_id y con paths relativos lo normaliza de forma impredecible
        rules_dir = str(self.rules_dir.resolve())

        result = subprocess.run(
            [
                "semgrep",
                "scan",
                "--config",
                rules_dir,
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

        return self._parse_output(result.stdout, rules_dir)

    def _namespaces(self, rules_dir: str) -> List[str]:
        """Prefijos que semgrep antepone al check_id (dir + subdirectorios).

        semgrep usa el path del config (con `/` → `.`) como namespace y añade
        los subdirectorios relativos de cada archivo de reglas anidado.
        """
        namespace = ".".join(
            part for part in rules_dir.split(os.sep) if part
        )
        prefixes = [f"{namespace}."] if namespace else []
        yaml_files = (
            list(Path(rules_dir).glob("*.yml"))
            + list(Path(rules_dir).glob("*.yaml"))
            + list(Path(rules_dir).rglob("*.yml"))
            + list(Path(rules_dir).rglob("*.yaml"))
        )
        for yaml_file in sorted(yaml_files):
            rel_parts = yaml_file.relative_to(rules_dir).parts[:-1]
            if rel_parts:
                prefixes.append(f"{namespace}.{'.'.join(rel_parts)}.")
        return prefixes

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
            config_errors = [
                error
                for error in data["errors"]
                if "invalid configuration" in str(error.get("message", ""))
                or "Invalid YAML" in str(error.get("message", ""))
            ]
            if config_errors:
                console.print(
                    f"[bold red]Error:[/] el bundle de reglas custom tiene "
                    f"{len(config_errors)} archivo(s) YAML inválido(s). "
                    f"Corrige las reglas para analizarlas."
                )
            else:
                console.print(
                    f"[bold yellow]Advertencia:[/] semgrep reportó "
                    f"{len(data['errors'])} errores de escaneo "
                    f"(archivos no analizados)"
                )

        # semgrep antepone el path del directorio (resuelto a absoluto) como
        # namespace al check_id, incluyendo los subdirectorios de reglas.
        # Probar los prefijos más largos primero: el namespace base también
        # matchea los check_ids de subdirectorios (y los dejaría sin limpiar)
        prefixes = sorted(
            self._namespaces(rules_dir), key=len, reverse=True
        )

        vulnerabilities: List[Vulnerability] = []
        for finding in data.get("results", []):
            severity = self._map_severity(finding.get("extra", {}).get("severity"))
            start = finding.get("start", {})
            check_id = finding.get("check_id", "unknown-rule")
            for prefix in prefixes:
                if check_id.startswith(prefix):
                    check_id = check_id[len(prefix):]
                    break
            vulnerabilities.append(
                Vulnerability(
                    rule=check_id,
                    file=self._relative_path(finding.get("path", "")),
                    # semgrep siempre da línea >= 1; proteger el modelo por si
                    # una regla rara devuelve 0 o sin start
                    line=start.get("line") or 1,
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
        return mapping.get(
            (semgrep_severity or "").upper(), Severity.INFO
        )

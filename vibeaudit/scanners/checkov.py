"""Scanner de infraestructura (IaC) basado en Checkov."""

import json
import os
import subprocess
from pathlib import Path
from typing import List, Optional

from rich.console import Console

from vibeaudit.ingester import IAC_FILES
from vibeaudit.models import Severity, Vulnerability

console = Console()

# Marcadores de Kubernetes / CloudFormation dentro de archivos YAML
K8S_MARKERS = ("kind: Deployment", "kind: Service", "apiVersion: apps/", "kind: Pod")
CLOUDFORMATION_MARKER = "AWSTemplateFormatVersion"
IAC_YAML_EXTENSIONS = (".yml", ".yaml")


class CheckovScanner:
    """Ejecuta Checkov sobre un repositorio y convierte los hallazgos en Vulnerability."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    @staticmethod
    def is_installed() -> bool:
        """Verifica si checkov está disponible en el sistema."""
        try:
            result = subprocess.run(
                ["checkov", "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    def _find_iac_files(self) -> List[str]:
        """Busca archivos de infraestructura en el repositorio."""
        if not self.repo_path.exists():
            return []

        iac_files: List[str] = []
        for root, _dirs, files in os.walk(self.repo_path):
            if ".git" in root:
                continue
            for filename in files:
                rel_path = os.path.relpath(
                    os.path.join(root, filename), self.repo_path
                )
                if self._is_iac_file(os.path.join(root, filename), filename):
                    iac_files.append(rel_path)
        return iac_files

    def _is_iac_file(self, full_path: str, filename: str) -> bool:
        """Clasifica un archivo como IaC (Terraform, CloudFormation, K8s, Docker)."""
        # Mapeo del ingester (Terraform, Serverless, Docker Compose, Dockerfile)
        if IAC_FILES.get(filename) or any(
            pattern == f"*{os.path.splitext(filename)[1]}"
            for pattern in ("*.tf",)
        ):
            return True

        # Terraform con cualquier nombre
        if filename.endswith(".tf") or filename.endswith(".tfvars"):
            return True

        # YAML: Kubernetes o CloudFormation por contenido
        if filename.endswith(IAC_YAML_EXTENSIONS):
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    head = f.read(4096)
            except OSError:
                return False
            if CLOUDFORMATION_MARKER in head or any(
                marker in head for marker in K8S_MARKERS
            ):
                return True

        return False

    def _find_unsupported_cfn_files(self) -> List[str]:
        """Detecta templates CloudFormation cuyo resource tiene Type no-string.

        Checkov 3.3.x crashea (unhashable type: 'dict') cuando un recurso usa
        Fn::Rain::Module u otras funciones intrínsecas como Type. Estos archivos
        se excluyen del escaneo vía --skip-path para no romper la ejecución.
        """
        try:
            from checkov.cloudformation.parser import parse as parse_cfn
        except ImportError:
            return []

        unsupported: List[str] = []
        for root, _dirs, files in os.walk(self.repo_path):
            if ".git" in root:
                continue
            for filename in files:
                if not (
                    filename.endswith(IAC_YAML_EXTENSIONS)
                    or filename.endswith(".json")
                ):
                    continue
                full_path = os.path.join(root, filename)
                try:
                    parsed, _ = parse_cfn(full_path)
                except Exception:
                    continue
                resources = (parsed or {}).get("Resources", {}) if isinstance(parsed, dict) else {}
                for _name, resource in resources.items():
                    if isinstance(resource, dict) and not isinstance(resource.get("Type"), str):
                        unsupported.append(os.path.relpath(full_path, self.repo_path))
                        break
        return unsupported

    def scan(self) -> List[Vulnerability]:
        """Ejecuta checkov si hay IaC y devuelve los problemas como Vulnerability."""
        if not self.is_installed():
            raise RuntimeError(
                "Checkov no está instalado. Instálalo con: "
                "pip install checkov"
            )

        iac_files = self._find_iac_files()
        if not iac_files:
            return []

        command = [
            "checkov",
            "-d",
            str(self.repo_path),
            "--output",
            "json",
            "--quiet",
            "--download-external-modules",
            "false",
        ]
        for skip in self._find_unsupported_cfn_files():
            command.extend(["--skip-path", skip])

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )

        # Exit codes de checkov:
        #   0 = sin hallazgos, 1 = hallazgos o warnings de parseo (válido)
        if result.returncode not in (0, 1):
            stderr_tail = "\n".join(result.stderr.strip().splitlines()[-5:])
            raise RuntimeError(
                f"Checkov falló con código {result.returncode}: {stderr_tail}"
            )

        if not result.stdout.strip():
            return []

        return self._parse_output(result.stdout)

    def _parse_output(self, raw_output: str) -> List[Vulnerability]:
        """Convierte el JSON de checkov en objetos Vulnerability."""
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            console.print("[bold yellow]Advertencia:[/] salida de checkov no es JSON")
            return []

        # Checkov 3.x devuelve una lista de check_types; versiones viejas un dict
        check_types = data if isinstance(data, list) else [data]
        if not isinstance(data, list) and not data.get("results"):
            return []

        failed_checks = []
        for check_type in check_types:
            if not isinstance(check_type, dict):
                continue
            results = check_type.get("results", {})
            failed_checks.extend(results.get("failed_checks", []))

        vulnerabilities: List[Vulnerability] = []
        for check in failed_checks:
            file_path = check.get("repo_file_path") or check.get("file", "")
            line_range = check.get("file_line_range") or [0, 0]
            vulnerabilities.append(
                Vulnerability(
                    rule=check.get("check_id", "unknown-check"),
                    file=self._relative_path(file_path),
                    line=line_range[0] if line_range else 0,
                    severity=self._map_severity(check.get("severity")),
                    snippet=check.get("check_name"),
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
    def _map_severity(checkov_severity: Optional[str]) -> Severity:
        """Mapea la severidad de checkov (CRITICAL/HIGH/MEDIUM/LOW) al enum Severity."""
        try:
            return Severity(checkov_severity.upper()) if checkov_severity else Severity.HIGH
        except ValueError:
            return Severity.HIGH

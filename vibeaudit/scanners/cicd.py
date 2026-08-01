"""Análisis de pipelines CI/CD (GitHub Actions y GitLab CI)."""

import os
import re
from pathlib import Path
from typing import List, Optional

from vibeaudit.models import Severity, Vulnerability

# Rutas de pipelines soportadas
GITHUB_WORKFLOW_DIR = ".github/workflows"
GITHUB_WORKFLOW_EXTENSIONS = (".yml", ".yaml")
GITLAB_CI_FILE = ".gitlab-ci.yml"

# Owners de acciones de confianza (no requieren pin a SHA)
TRUSTED_ACTION_OWNERS = ("actions", "github", "docker", "azure", "aws-actions")

# SHA de commit válido para pin de acciones
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")

# Patrones de secretos dentro de bloques run/script
SECRET_IN_RUN_RE = re.compile(r"\$\{\{\s*secrets\.[\w.-]+\s*\}\}")
GITLAB_TOKEN_RE = re.compile(r"\$CI_(JOB_TOKEN|REGISTRY_PASSWORD|DEPLOY_PASSWORD)")

# Patrones de pull_request_target dentro del bloque "on:"
PR_TARGET_RE = re.compile(r"pull_request_target")


class CICDScanner:
    """Detecta riesgos de seguridad en pipelines de CI/CD (parser propio).

    No depende de herramientas externas: analiza los archivos de workflow
    directamente. Los hallazgos se reportan como Vulnerability con la misma
    estructura que el resto de scanners.
    """

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    @staticmethod
    def is_installed() -> bool:
        """Parser propio: siempre disponible (no requiere herramienta externa)."""
        return True

    def scan(self) -> List[Vulnerability]:
        """Analiza los pipelines del repositorio y devuelve los riesgos."""
        findings: List[Vulnerability] = []
        for file_path in self._find_ci_files():
            rel_path = os.path.relpath(file_path, self.repo_path)
            try:
                lines = Path(file_path).read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
            except OSError:
                continue
            if rel_path == GITLAB_CI_FILE:
                findings.extend(self._scan_gitlab_ci(lines, rel_path))
            else:
                findings.extend(self._scan_github_workflow(lines, rel_path))
        return findings

    def _find_ci_files(self) -> List[str]:
        """Localiza los archivos de pipeline en el repositorio."""
        files: List[str] = []
        workflows_dir = self.repo_path / GITHUB_WORKFLOW_DIR
        if workflows_dir.is_dir():
            for filename in sorted(os.listdir(workflows_dir)):
                if filename.endswith(GITHUB_WORKFLOW_EXTENSIONS):
                    files.append(str(workflows_dir / filename))
        gitlab_ci = self.repo_path / GITLAB_CI_FILE
        if gitlab_ci.is_file():
            files.append(str(gitlab_ci))
        return files

    def _scan_github_workflow(
        self, lines: List[str], rel_path: str
    ) -> List[Vulnerability]:
        """Checks de seguridad para un workflow de GitHub Actions."""
        findings: List[Vulnerability] = []

        # 1. pull_request_target sin bloque permissions explícito
        on_line = self._find_pull_request_target(lines)
        if on_line is not None and not self._has_permissions(lines):
            findings.append(
                Vulnerability(
                    rule="cicd-github-pr-target-no-permissions",
                    file=rel_path,
                    line=on_line,
                    severity=Severity.HIGH,
                    snippet=(
                        "pull_request_target sin permissions explícitas: el "
                        "workflow puede ejecutar código del PR con el token "
                        "del repositorio base. Definir permissions mínimo "
                        "(contenidos: read, issues: read)."
                    ),
                )
            )

        # 2. Acciones de terceros sin pin a SHA de commit
        for index, line in enumerate(lines, start=1):
            stripped = line.strip().lstrip("- ").strip()
            if not stripped.startswith("uses:"):
                continue
            ref = stripped.split("uses:", 1)[1].strip().strip('"').strip("'")
            if "@" not in ref:
                continue
            owner = ref.split("/", 1)[0]
            version = ref.rsplit("@", 1)[1].split("#", 1)[0].strip()
            if owner in TRUSTED_ACTION_OWNERS:
                continue
            if not SHA40_RE.match(version):
                findings.append(
                    Vulnerability(
                        rule="cicd-github-action-not-pinned",
                        file=rel_path,
                        line=index,
                        severity=Severity.MEDIUM,
                        snippet=f"La acción {ref} se referencia por tag/rama en lugar de SHA: pinear a un SHA de commit.",
                    )
                )

        # 3. Secretos interpolados dentro de bloques run:
        for index, line in enumerate(lines, start=1):
            stripped = line.strip().lstrip("- ").strip()
            if not stripped.startswith("run:"):
                continue
            block_lines = [line]
            for next_line in lines[index:]:
                if next_line.strip() and not next_line.startswith((" ", "\t")):
                    break
                block_lines.append(next_line)
            if SECRET_IN_RUN_RE.search("\n".join(block_lines)):
                findings.append(
                    Vulnerability(
                        rule="cicd-github-secret-in-run",
                        file=rel_path,
                        line=index,
                        severity=Severity.HIGH,
                        snippet=(
                            "Secreto interpolado en run: el valor puede "
                            "aparecer en logs o exponerse a código del PR. "
                            "Pasarlo vía env/inputs del job."
                        ),
                    )
                )

        return findings

    def _scan_gitlab_ci(self, lines: List[str], rel_path: str) -> List[Vulnerability]:
        """Checks de seguridad para un .gitlab-ci.yml."""
        findings: List[Vulnerability] = []
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped.startswith("script:"):
                continue
            block = [stripped] + [
                l.strip() for l in lines[index:] if l.strip().startswith("- ")
            ]
            for block_line in block:
                if GITLAB_TOKEN_RE.search(block_line):
                    findings.append(
                        Vulnerability(
                            rule="cicd-gitlab-token-in-script",
                            file=rel_path,
                            line=index,
                            severity=Severity.MEDIUM,
                            snippet=(
                                f"Token de CI ({GITLAB_TOKEN_RE.search(block_line).group(0)}) "
                                "usado en script: puede filtrarse en logs. Usar "
                                "variables protegidas o passed-job artifacts."
                            ),
                        )
                    )
                    break
        return findings

    @staticmethod
    def _find_pull_request_target(lines: List[str]) -> Optional[int]:
        """Devuelve el número de línea del pull_request_target si existe."""
        in_on_block = False
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped == "on:" or stripped.startswith("on: "):
                in_on_block = True
                if PR_TARGET_RE.search(line):
                    return index
                continue
            if in_on_block:
                if not stripped or not line.startswith((" ", "\t")):
                    return None
                if PR_TARGET_RE.search(stripped):
                    return index
        return None

    @staticmethod
    def _has_permissions(lines: List[str]) -> bool:
        """True si el workflow define permissions (nivel workflow o de job)."""
        return any(
            line.strip() == "permissions:" or line.strip().startswith("permissions: ")
            for line in lines
        )

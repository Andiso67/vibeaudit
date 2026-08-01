"""Clonación y lectura de repositorios para la auditoría."""

import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from git import InvalidGitRepositoryError, NoSuchPathError, Repo
from git.exc import GitCommandError
from rich.console import Console

from vibeaudit.models import ProjectMetadata

console = Console()

# Mapeo de archivos de dependencias por lenguaje
DEPENDENCY_FILES: Dict[str, str] = {
    "package.json": "JavaScript",
    "package-lock.json": "JavaScript",
    "yarn.lock": "JavaScript",
    "pnpm-lock.yaml": "JavaScript",
    "requirements.txt": "Python",
    "Pipfile": "Python",
    "pyproject.toml": "Python",
    "poetry.lock": "Python",
    "pom.xml": "Java",
    "build.gradle": "Java",
    "build.gradle.kts": "Java",
    "Cargo.toml": "Rust",
    "Cargo.lock": "Rust",
    "go.mod": "Go",
    "go.sum": "Go",
    "Gemfile": "Ruby",
    "composer.json": "PHP",
    "*.csproj": ".NET",
}

# Archivos de infraestructura (IaC)
IAC_FILES: Dict[str, str] = {
    "main.tf": "Terraform",
    "*.tf": "Terraform",
    "serverless.yml": "Serverless",
    "serverless.yaml": "Serverless",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
    "Dockerfile": "Docker",
}

# Extensiones de archivos que determinan el lenguaje
EXTENSION_MAP: Dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".html": "HTML",
    ".css": "CSS",
    ".sh": "Shell",
}

# Frameworks detectados por archivos conocidos
FRAMEWORK_FILES: Dict[str, str] = {
    "next.config.js": "Next.js",
    "next.config.mjs": "Next.js",
    "next.config.ts": "Next.js",
    "nuxt.config.ts": "Nuxt",
    "vue.config.js": "Vue",
    "angular.json": "Angular",
    "manage.py": "Django",
    "app.py": "Flask",
    "main.py": "Flask",
    "pom.xml": "Spring Boot",
    "build.gradle": "Spring Boot",
}

def sanitize_url(url: str) -> str:
    """Quita credenciales embebidas de una URL (https://token@host/...)."""
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    if "@" in rest.split("/", 1)[0]:
        rest = rest.split("@", 1)[1]
    return f"{scheme}://{rest}"


class RepoIngester:
    """Clona un repositorio Git o analiza un directorio local, y devuelve metadatos."""

    def __init__(
        self,
        repo_url: Optional[str] = None,
        local_path: Optional[Path] = None,
        token: Optional[str] = None,
        branch: Optional[str] = None,
        depth: Optional[int] = None,
    ):
        if (repo_url is None) == (local_path is None):
            raise ValueError(
                "Indica una URL de repositorio o un directorio local (exactamente uno)"
            )
        if local_path is not None and (
            token or branch or (depth is not None and depth != 1)
        ):
            raise ValueError(
                "token, branch y depth solo aplican al clonar (--repo-url)"
            )
        self.repo_url = repo_url
        self.local_path = Path(local_path) if local_path is not None else None
        self.token = token
        self.branch = branch
        self.depth = depth
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.repo_path: Optional[Path] = None

    def __enter__(self) -> "RepoIngester":
        """Permite usar el ingester como context manager (limpia al salir)."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._cleanup()

    def ingest(self) -> ProjectMetadata:
        """Clona o carga el directorio, detecta características y devuelve ProjectMetadata."""
        try:
            self.clone()
            metadata = self._analyze()
            return metadata
        finally:
            self._cleanup()

    def clone(self) -> None:
        """Clona el repositorio o carga el directorio local con manejo de errores."""
        if self.local_path is not None:
            self._load_local()
            return
        try:
            self._clone()
        except GitCommandError as exc:
            message = str(exc).lower()
            safe_url = sanitize_url(self.repo_url)
            console.print(f"[bold red]Error de Git:[/] {sanitize_url(str(exc))}")
            if (
                "not found" in message
                or "repository not found" in message
                or "does not exist" in message
                or "could not read username" in message
                or "authentication failed" in message
            ):
                raise ValueError(
                    f"El repositorio no existe o no es accesible: {safe_url}"
                ) from exc
            if "permission denied" in message:
                raise PermissionError(
                    f"Sin permisos para acceder al repositorio: {safe_url}"
                ) from exc
            raise
        except (NoSuchPathError, InvalidGitRepositoryError) as exc:
            raise ValueError(
                f"No se pudo leer el repositorio: {sanitize_url(self.repo_url)}"
            ) from exc

    def analyze(self) -> ProjectMetadata:
        """Analiza el repositorio clonado o el directorio local y devuelve sus metadatos."""
        return self._analyze()

    def _load_local(self) -> None:
        """Valida el directorio local y lo usa directamente como repo_path."""
        assert self.local_path is not None
        path = self.local_path.expanduser().resolve()
        if not path.exists():
            raise ValueError(f"El directorio local no existe: {self.local_path}")
        if not path.is_dir():
            raise ValueError(
                f"El path local no es un directorio: {self.local_path}"
            )
        self.repo_path = path

    def _clone(self) -> None:
        """Clona el repositorio en un directorio temporal (con token/branch/depth)."""
        self._temp_dir = tempfile.TemporaryDirectory(prefix="vibeaudit_")
        self.repo_path = Path(self._temp_dir.name)
        clone_url = self.repo_url
        if self.token:
            clone_url = self._inject_token(clone_url, self.token)
        kwargs: Dict[str, object] = {}
        if self.depth is not None:
            kwargs["depth"] = self.depth
        if self.branch is not None:
            kwargs["branch"] = self.branch
        # Sin prompt interactivo: git falla limpio en vez de pedir credenciales
        # por terminal (que imprimiría el token en la URL)
        kwargs["env"] = {"GIT_TERMINAL_PROMPT": "0"}
        repo = Repo.clone_from(clone_url, self.repo_path, **kwargs)
        if self.token:
            # No dejar el token en la config del repo temporal (origin)
            repo.remotes.origin.set_url(self.repo_url)

    @staticmethod
    def _inject_token(url: str, token: str) -> str:
        """Inyecta el token en la URL de clone (https://token@host/...)."""
        if not (url.startswith("https://") or url.startswith("http://")):
            return url
        scheme, rest = url.split("://", 1)
        if "@" in rest.split("/", 1)[0]:
            rest = rest.split("@", 1)[1]
        return f"{scheme}://{token}@{rest}"

    def _analyze(self) -> ProjectMetadata:
        """Analiza el repositorio clonado y construye los metadatos."""
        assert self.repo_path is not None
        if self.local_path is not None:
            name = self.local_path.name or "directorio-local"
        else:
            name = self.repo_url.rstrip("/").split("/")[-1].removesuffix(".git")

        languages: set = set()
        frameworks: set = set()
        iac_files: List[str] = []

        for root, _dirs, files in os.walk(self.repo_path):
            if ".git" in root:
                continue
            for filename in files:
                rel_path = os.path.relpath(os.path.join(root, filename), self.repo_path)
                self._detect_file(rel_path, filename, languages, frameworks, iac_files)

        repository_url = self._capture_repository_url()
        default_branch = self._capture_default_branch()
        commit_hash = self._capture_commit_hash()

        return ProjectMetadata(
            name=name,
            repository_url=repository_url,
            default_branch=default_branch,
            commit_hash=commit_hash,
            languages=sorted(languages),
            frameworks=sorted(frameworks),
            iac_files=iac_files,
        )

    def _capture_repository_url(self) -> Optional[str]:
        """Obtiene la URL remota real del repositorio clonado."""
        try:
            remote_url = Repo(self.repo_path).remotes.origin.url
        except Exception:
            return sanitize_url(self.repo_url) if self.repo_url else None
        # Los clones locales resuelven origin a la ruta absoluta; conservar la original
        if remote_url.startswith(("/", "file://")):
            return sanitize_url(self.repo_url) if self.repo_url else None
        return sanitize_url(remote_url)

    def _capture_default_branch(self) -> Optional[str]:
        """Obtiene la rama activa (HEAD) del repositorio clonado."""
        try:
            repo = Repo(self.repo_path)
            if repo.head.is_detached:
                return None
            return repo.active_branch.name
        except Exception:
            return None

    def _capture_commit_hash(self) -> Optional[str]:
        """Obtiene el hash del commit clonado (HEAD)."""
        try:
            return Repo(self.repo_path).head.commit.hexsha
        except Exception:
            return None

    def _detect_file(
        self,
        rel_path: str,
        filename: str,
        languages: set,
        frameworks: set,
        iac_files: List[str],
    ) -> None:
        """Clasifica un archivo individual dentro del repositorio."""
        # Lenguaje por extensión
        ext = os.path.splitext(filename)[1]
        language = EXTENSION_MAP.get(ext)
        if language:
            languages.add(language)

        # Lenguaje por archivo de dependencias (soporta patrones como *.csproj)
        dep_language = DEPENDENCY_FILES.get(filename)
        if not dep_language:
            dep_language = self._match_pattern(DEPENDENCY_FILES, filename)
        if dep_language:
            languages.add(dep_language)

        # Framework por archivo conocido
        framework = FRAMEWORK_FILES.get(filename)
        if framework:
            frameworks.add(framework)

        # Detección de React (usa imports)
        if framework is None and filename in ("App.jsx", "App.tsx", "index.jsx"):
            frameworks.add("React")

        # Archivos IaC
        iac_match = IAC_FILES.get(filename) or self._match_pattern(IAC_FILES, filename)
        if iac_match:
            iac_files.append(rel_path)

    @staticmethod
    def _match_pattern(mapping: Dict[str, str], filename: str) -> Optional[str]:
        """Busca un patrón glob (ej. *.tf) en el mapeo."""
        import fnmatch

        for pattern, value in mapping.items():
            if "*" in pattern and fnmatch.fnmatch(filename, pattern):
                return value
        return None

    def _cleanup(self) -> None:
        """Elimina el directorio temporal y sus contenidos."""
        if self._temp_dir is not None:
            try:
                self._temp_dir.cleanup()
            except OSError:
                pass
            finally:
                self._temp_dir = None
                self.repo_path = None

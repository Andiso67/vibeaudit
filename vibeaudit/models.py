"""Esquemas de datos Pydantic para el JSON maestro de auditoría."""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Niveles de severidad para hallazgos de seguridad."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ProjectMetadata(BaseModel):
    """Metadatos del proyecto auditado."""

    name: str = Field(..., min_length=1, description="Nombre del repositorio")
    repository_url: Optional[str] = Field(
        default=None,
        alias="repositoryUrl",
        description="URL del repositorio Git",
    )
    default_branch: Optional[str] = Field(
        default=None,
        alias="defaultBranch",
        description="Rama por defecto del repositorio",
    )
    commit_hash: Optional[str] = Field(
        default=None,
        alias="commitHash",
        description="Hash del commit auditado",
    )
    languages: List[str] = Field(
        default_factory=list, description="Lenguajes de programación detectados"
    )
    frameworks: List[str] = Field(
        default_factory=list, description="Frameworks detectados"
    )
    iac_files: List[str] = Field(
        default_factory=list,
        alias="iacFiles",
        description="Archivos IaC (Infrastructure as Code) detectados",
    )

    model_config = {"populate_by_name": True}


class Vulnerability(BaseModel):
    """Vulnerabilidad encontrada por un scanner de SAST (ej. Semgrep)."""

    rule: str = Field(..., min_length=1, description="Identificador de la regla")
    file: str = Field(..., min_length=1, description="Archivo afectado")
    line: int = Field(..., gt=0, description="Línea donde se detectó")
    severity: Severity = Field(..., description="Severidad del hallazgo")
    snippet: Optional[str] = Field(
        default=None, description="Fragmento del código vulnerable"
    )

    @field_validator("snippet")
    @classmethod
    def strip_snippet(cls, value: Optional[str]) -> Optional[str]:
        """Elimina espacios en blanco sobrantes del snippet."""
        if value is None:
            return None
        return value.strip()


class Secret(BaseModel):
    """Secreto o credencial filtrada detectada (ej. Gitleaks)."""

    type: str = Field(
        ..., min_length=1, description="Tipo de secreto (API key, token, etc.)"
    )
    file: str = Field(..., min_length=1, description="Archivo donde se filtró")
    line: int = Field(..., gt=0, description="Línea donde se encontró")
    severity: Severity = Field(..., description="Severidad del hallazgo")


class DependencyVulnerability(BaseModel):
    """Vulnerabilidad de una dependencia (datos de OSV)."""

    name: str = Field(..., min_length=1, description="Nombre del paquete")
    ecosystem: str = Field(..., min_length=1, description="Ecosistema (PyPI, npm, Go...)")
    version: str = Field(..., min_length=1, description="Versión declarada en el lockfile")
    direct: bool = Field(..., description="True si es dependencia directa del proyecto")
    dependency_type: str = Field(
        default="unknown",
        alias="dependencyType",
        description="production | dev | unknown",
    )
    purl: Optional[str] = Field(
        default=None, description="Package URL canónico (pkg:npm/axios@1.0.0)"
    )
    cve_ids: List[str] = Field(
        default_factory=list, alias="cveIds", description="Identificadores CVE"
    )
    aliases: List[str] = Field(
        default_factory=list, description="IDs alternativos (GHSA-xxxx, GMS-xxxx)"
    )
    cwe_ids: List[str] = Field(
        default_factory=list, alias="cweIds", description="Clasificación CWE del problema"
    )
    severity: Severity = Field(..., description="Severidad según CVSS de OSV")
    cvss_score: Optional[float] = Field(
        default=None, alias="cvssScore", description="Puntuación CVSS (ej. 9.8)"
    )
    summary: str = Field(default="", description="Descripción corta de la vulnerabilidad")
    details: Optional[str] = Field(
        default=None, description="Descripción completa"
    )
    fixed_version: Optional[str] = Field(
        default=None, alias="fixedVersion", description="Versión que corrige la vulnerabilidad"
    )
    affected_range: Optional[str] = Field(
        default=None, alias="affectedRange", description="Rango de versiones vulnerables (ej. <1.2.3)"
    )
    is_fix_available: bool = Field(
        default=False,
        alias="isFixAvailable",
        description="True si existe versión corregida",
    )
    exploited_in_wild: Optional[bool] = Field(
        default=None,
        alias="exploitedInWild",
        description="True si figura en CISA KEV (si se integra)",
    )
    epss_score: Optional[float] = Field(
        default=None, alias="epssScore", description="Score EPSS de probabilidad de explotación"
    )
    published: Optional[str] = Field(
        default=None, description="Fecha de publicación del advisory"
    )
    modified: Optional[str] = Field(
        default=None, description="Última actualización del advisory"
    )
    references: List[str] = Field(
        default_factory=list, description="URLs de advisories"
    )

    model_config = {"populate_by_name": True}


class Metrics(BaseModel):
    """Métricas del repositorio."""

    lines_of_code: int = Field(
        default=0, ge=0, alias="linesOfCode", description="Líneas de código totales"
    )
    test_files: int = Field(
        default=0, ge=0, alias="testFiles", description="Número de archivos de test"
    )
    dependencies_with_cves: List[str] = Field(
        default_factory=list,
        alias="dependenciesWithCves",
        description="Dependencias con CVEs conocidos",
    )
    dependency_vulnerabilities: List[DependencyVulnerability] = Field(
        default_factory=list,
        alias="dependencyVulnerabilities",
        description="Detalle completo de vulnerabilidades de dependencias",
    )
    vulnerabilities_by_severity: Dict[str, int] = Field(
        default_factory=dict,
        alias="vulnerabilitiesBySeverity",
        description="Conteo de vulnerabilidades agrupadas por severidad",
    )

    model_config = {"populate_by_name": True}


class AuditReport(BaseModel):
    """Esquema maestro que combina todos los resultados de la auditoría."""

    project: ProjectMetadata = Field(..., description="Metadatos del proyecto")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="Vulnerabilidades de SAST"
    )
    secrets: List[Secret] = Field(
        default_factory=list, description="Secretos filtrados"
    )
    iac_issues: List[Vulnerability] = Field(
        default_factory=list,
        alias="iacIssues",
        description="Problemas de IaC (ej. Checkov)",
    )
    metrics: Metrics = Field(..., description="Métricas del repositorio")

    model_config = {"populate_by_name": True}

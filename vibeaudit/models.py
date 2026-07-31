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

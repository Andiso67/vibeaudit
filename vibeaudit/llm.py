"""Motor LLM: auditoría por checklists sobre el JSON maestro.

Cliente httpx compatible con la API de OpenAI (chat/completions), pensado
para motores locales y gratuitos: por defecto apunta a Ollama
(http://localhost:11434/v1) y es configurable vía variables de entorno a
cualquier proveedor compatible (Groq, OpenRouter, LM Studio, ...).
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

import httpx
from pydantic import BaseModel, Field, ValidationError

from vibeaudit.models import AuditReport, LLMFinding, Severity

# Variables de entorno
ENV_BASE_URL = "VIBEAUDIT_LLM_BASE_URL"
ENV_MODEL = "VIBEAUDIT_LLM_MODEL"
ENV_API_KEY = "VIBEAUDIT_LLM_API_KEY"
ENV_TIMEOUT = "VIBEAUDIT_LLM_TIMEOUT"

DEFAULT_BASE_URL = "http://localhost:11434/v1"
DEFAULT_MODEL = "llama3.1"
DEFAULT_TIMEOUT = 600
MAX_FINDINGS_IN_PROMPT = 40


class LLMUnavailableError(RuntimeError):
    """El endpoint LLM no está disponible (sin red, sin servidor local, 401...)."""


class ChecklistItem(BaseModel):
    """Ítem de un checklist de buenas prácticas (12-Factor, OWASP, WAF...)."""

    id: str = Field(..., min_length=1, description="Identificador único (ej. 12-factor.config)")
    title: str = Field(..., min_length=1, description="Título corto")
    description: str = Field(..., min_length=1, description="Qué verificar y por qué")


STARTER_CHECKLIST: List[ChecklistItem] = [
    ChecklistItem(
        id="12-factor.config",
        title="Configuración en el entorno",
        description="Los secretos y la configuración no deben estar hardcodeados en el "
        "código (12-Factor III). Buscar credenciales en archivos fuente y plantillas.",
    ),
    ChecklistItem(
        id="owasp.sensitive-data",
        title="Protección de datos sensibles",
        description="Los secretos filtrados y los datos sensibles deben gestionarse con "
        "gestores de secretos (OWASP A02). Verificar hallazgos de gitleaks y su alcance.",
    ),
    ChecklistItem(
        id="owasp.injection",
        title="Prevención de inyección",
        description="Las consultas a bases de datos deben usar parámetros, nunca "
        "concatenación de strings (OWASP A03). Revisar hallazgos SAST de tipo injection/raw query.",
    ),
    ChecklistItem(
        id="owasp.code-eval",
        title="Sin evaluación dinámica de código",
        description="Evitar eval/exec sobre entrada del usuario (OWASP A03). Revisar "
        "hallazgos de evaluaciones dinámicas en el reporte SAST y reglas custom.",
    ),
    ChecklistItem(
        id="waf.iam-least-privilege",
        title="Mínimo privilegio en IAM",
        description="Las políticas IAM y los permisos de CI/CD deben seguir el principio "
        "de mínimo privilegio (AWS Well-Architected SEC01). Revisar hallazgos de IaC y CI/CD.",
    ),
    ChecklistItem(
        id="waf.dependencies",
        title="Dependencias actualizadas",
        description="Las dependencias con CVEs conocidos deben actualizarse a la versión "
        "corregida (AWS WAF / OWASP A06). Revisar el detalle de dependenciesWithCves.",
    ),
]


@dataclass
class LLMConfig:
    """Configuración del cliente LLM (env vars con defaults para Ollama local)."""

    base_url: str = field(default_factory=lambda: os.getenv(ENV_BASE_URL, DEFAULT_BASE_URL))
    model: str = field(default_factory=lambda: os.getenv(ENV_MODEL, DEFAULT_MODEL))
    api_key: str = field(default_factory=lambda: os.getenv(ENV_API_KEY, ""))
    timeout: float = field(
        default_factory=lambda: float(os.getenv(ENV_TIMEOUT, DEFAULT_TIMEOUT))
    )

    @classmethod
    def from_env(cls) -> "LLMConfig":
        return cls()


class LLMClient:
    """Cliente mínimo de chat/completions compatible con la API de OpenAI."""

    def __init__(self, config: Optional[LLMConfig] = None, transport=None):
        self.config = config or LLMConfig.from_env()
        self._client = httpx.Client(timeout=self.config.timeout, transport=transport)

    def chat(self, messages: List[dict]) -> str:
        """Envía un chat y devuelve el texto de la respuesta."""
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.2,
        }
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        try:
            response = self._client.post(
                f"{self.config.base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(
                f"No se pudo contactar el motor LLM ({self.config.base_url}): {exc}"
            ) from exc
        if response.status_code in (401, 403):
            raise LLMUnavailableError(
                f"El motor LLM rechazó la autenticación ({response.status_code})"
            )
        if response.status_code >= 400:
            raise LLMUnavailableError(
                f"El motor LLM respondió {response.status_code}: "
                f"{response.text[:200]}"
            )
        try:
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError) as exc:
            raise LLMUnavailableError(
                "Respuesta del motor LLM con formato inesperado"
            ) from exc


class LLMAuditor:
    """Audita el JSON maestro contra un checklist usando un modelo LLM."""

    def __init__(
        self,
        report: AuditReport,
        client: Optional[LLMClient] = None,
        checklist: Optional[List[ChecklistItem]] = None,
    ):
        self.report = report
        self.client = client or LLMClient()
        self.checklist = checklist if checklist is not None else STARTER_CHECKLIST

    def build_messages(self) -> List[dict]:
        """Construye el par system/user con el resumen del reporte y el checklist."""
        system = (
            "Eres un auditor senior de seguridad de aplicaciones y arquitectura. "
            "Recibes un resumen de una auditoría automática de un repositorio y un "
            "checklist de buenas prácticas. Emite SOLO JSON válido, sin markdown ni "
            "texto extra, con esta forma exacta: "
            '{"findings": [{"title": "...", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", '
            '"checklistRef": "...", "evidence": "...", "recommendation": "...", '
            '"relatedFiles": ["..."]}]}. '
            "Máximo 10 hallazgos, ordenados por severidad. No inventes hallazgos: usa "
            "únicamente la evidencia presente en el resumen."
        )
        user = self._build_user_prompt()
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

    def _build_user_prompt(self) -> str:
        """Resumen compacto del reporte: métricas, conteos y hallazgos top."""
        report = self.report
        lines = [
            f"Repositorio: {report.project.name}",
            f"Lenguajes: {', '.join(report.project.languages) or 'desconocidos'}",
            f"Frameworks: {', '.join(report.project.frameworks) or 'ninguno'}",
            f"LOC: {report.metrics.lines_of_code} | tests: {report.metrics.test_files}",
            f"Vulnerabilidades por severidad: {report.metrics.vulnerabilities_by_severity}",
        ]
        sections = [
            ("SAST", report.vulnerabilities),
            ("Secretos", report.secrets),
            ("IaC", report.iac_issues),
            ("CI/CD", report.cicd_issues),
            ("Custom", report.custom_issues),
        ]
        for name, items in sections:
            if not items:
                lines.append(f"{name}: sin hallazgos")
                continue
            lines.append(f"{name} ({len(items)}):")
            for item in items[:MAX_FINDINGS_IN_PROMPT]:
                snippet = getattr(item, "snippet", None)
                detail = f" [{snippet}]" if snippet else ""
                lines.append(
                    f"  - {item.rule} {item.severity.value} "
                    f"{item.file}:{item.line}{detail}"
                )
        deps = report.metrics.dependency_vulnerabilities
        if deps:
            lines.append(f"Dependencias con CVEs ({len(deps)}):")
            for dep in deps[:MAX_FINDINGS_IN_PROMPT]:
                lines.append(
                    f"  - {dep.name}@{dep.version} {dep.severity.value} "
                    f"{','.join(dep.cve_ids)} fix={dep.fixed_version or 'sin fix'}"
                )
        else:
            lines.append("Dependencias con CVEs: ninguna")
        lines.append("")
        lines.append("CHECKLIST:")
        for item in self.checklist:
            lines.append(f"- [{item.id}] {item.title}: {item.description}")
        return "\n".join(lines)

    def parse_response(self, text: str) -> List[LLMFinding]:
        """Parsea la respuesta del modelo a hallazgos, ignorando items inválidos."""
        block = self._extract_json(text)
        if block is None:
            return []
        try:
            data = json.loads(block)
        except json.JSONDecodeError:
            return []
        findings = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(findings, list):
            return []
        parsed = []
        for item in findings:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("checklistRef"), str):
                item["checklistRef"] = item["checklistRef"].strip("[]\"' ")
            try:
                parsed.append(LLMFinding(**item))
            except ValidationError:
                continue
        return parsed

    @staticmethod
    def _extract_json(text: str) -> Optional[str]:
        """Extrae el primer bloque JSON de la respuesta (tolera fences ```json)."""
        if not text:
            return None
        text = text.strip()
        fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if fenced:
            text = fenced.group(1).strip()
        try:
            json.loads(text)
            return text
        except json.JSONDecodeError:
            pass
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end <= start:
            return None
        return text[start : end + 1]

    def audit(self) -> List[LLMFinding]:
        """Ejecuta la auditoría LLM y devuelve los hallazgos."""
        messages = self.build_messages()
        response = self.client.chat(messages)
        return self.parse_response(response)

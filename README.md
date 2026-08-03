# VibeAudit

Auditoría automática de repositorios Git para detectar la deuda técnica típica
del **Vibe Coding**: secrets hardcodeados, vulnerabilidades SAST y configuraciones
de infraestructura inseguras. Clona el repo, ejecuta Gitleaks, Semgrep y Checkov,
y genera un JSON maestro con todos los hallazgos.

Primer paso hacia el servicio de "Pre-Auditoría Automatizada en 48 horas".
Ver `SPRINT.md` para el alcance del sprint 1 y `CONTEXT.md` para la visión completa.

## Requisitos

- Python 3.9+
- [gitleaks](https://github.com/gitleaks/gitleaks) (`brew install gitleaks`)
- [semgrep](https://semgrep.dev) (`brew install semgrep`)
- [checkov](https://www.checkov.io) (`pip install checkov`)

Los scanners se omiten con un mensaje claro si no están instalados.

## Instalación

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Como comando instalable

```bash
.venv/bin/pip install -e .
.venv/bin/vibeaudit --help
```

### Con Docker (todo incluido: Python + scanners)

```bash
docker build -t vibeaudit .
docker run --rm -v "$PWD:/reports" vibeaudit scan \
  --repo-url https://github.com/docker/compose.git \
  --output /reports/report.json
```

La imagen incluye gitleaks, semgrep y checkov — no hay que instalar nada en la máquina.

## Uso

```bash
.venv/bin/python -m vibeaudit.cli scan --repo-url <url> --output report.json
```

Ejemplo:

```bash
.venv/bin/python -m vibeaudit.cli scan \
  --repo-url https://github.com/docker/compose.git \
  --output /tmp/report.json
```

Auditar un directorio local sin clonar (metadatos parciales si no tiene `.git`):

```bash
.venv/bin/python -m vibeaudit.cli scan --path ./mi-repo --format md
```

### Opciones

| Opción | Descripción |
|---|---|
| `--repo-url`, `-u` | URL del repositorio Git a auditar (excluyente con `--path`) |
| `--path` | Directorio local a auditar sin clonar (excluyente con `--repo-url`) |
| `--token` | Token de acceso para clonar repositorios privados (solo con `--repo-url`) |
| `--branch` | Rama a auditar tras el clone (solo con `--repo-url`) |
| `--tag` | Tag a auditar tras el clone (excluyente con `--branch`) |
| `--depth` | Profundidad del clone (default: `1`) |
| `--output`, `-o` | Ruta del archivo de salida (default: `audit-report.<formato>`) |
| `--format`, `-f` | Formato de salida: `json` (default), `html` o `md` |
| `--dashboard` | Genera además un dashboard HTML interactivo junto al reporte (`<output>-dashboard.html`) |
| `--rules` | Directorio con reglas semgrep YAML custom "Vibe Coding" |
| `--llm` | Auditoría por checklists con un LLM local/remoto (ver sección "Auditoría LLM") |

El reporte HTML es autocontenido (CSS inline, sin JS externo) y se abre
directamente en el navegador. El Markdown es legible en cualquier visor/CI.
El dashboard (`--dashboard`) es HTML autocontenido que embebe el JSON maestro
en un `<script type="application/json">` y lo renderiza con JavaScript vanilla
(tarjetas de resumen, barras por severidad, tablas de hallazgos con filtro),
funciona abriendo el archivo con `file://` (sin servidor).

## Auditoría LLM

Con `--llm`, vibeaudit envía el resumen del reporte (hallazgos de SAST, IaC,
CI/CD, secretos y dependencias) a un LLM junto con un checklist de buenas
prácticas, y añade `llmFindings` al reporte con recomendaciones. Es una
segunda opinión gratuita: por defecto usa Ollama local (API compatible con
OpenAI), sin coste ni API key.

```bash
ollama pull llama3.1 && ollama serve
.venv/bin/python -m vibeaudit.cli scan --path ./mi-repo --output report.json --llm
```

| Variable de entorno | Descripción | Default |
|---|---|---|
| `VIBEAUDIT_LLM_BASE_URL` | Base URL del endpoint `/chat/completions` | `http://localhost:11434/v1` |
| `VIBEAUDIT_LLM_MODEL` | Modelo a usar | `llama3.1` |
| `VIBEAUDIT_LLM_API_KEY` | API key (opcional, proveedores remotos) | (vacía) |
| `VIBEAUDIT_LLM_TIMEOUT` | Timeout de la consulta en segundos | `600` |

Si el motor no está disponible, el scan no falla: muestra una advertencia y
genera el reporte sin análisis LLM.

### Checklists como datos

Los checklists son YAML en `vibeaudit/checklists/` (12-Factor, OWASP Top 10,
AWS Well-Architected) con ítems que declaran reglas de mapeo hallazgo→checklist
(secciones del reporte, patrones de id de regla como `CKV_AWS_*`, y severidad
mínima). El reporte maestro referencia los checklists aplicados en
`checklists` (`{name, itemCount, matchedFindings}`), contados a partir del
mapeo real de los hallazgos.

## Estructura del JSON maestro
```json
{
  "project": { "name", "languages", "frameworks", "iacFiles" },
  "vulnerabilities": [{ "rule", "file", "line", "severity", "snippet" }],
  "secrets": [{ "type", "file", "line", "severity" }],
  "iacIssues": [{ ... }],
  "metrics": { "linesOfCode", "testFiles", "dependenciesWithCves", "vulnerabilitiesBySeverity" }
}
```

Severidades: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Semgrep solo reporta
HIGH/CRITICAL; las reglas críticas de Gitleaks (AWS, GitHub, Stripe, SSH...)
se mapean a CRITICAL.

## Estructura del proyecto

```
vibeaudit/
  cli.py          # CLI Typer (comando scan)
  ingester.py     # RepoIngester: clona a temp dir, detecta lenguajes/iaC
  models.py       # Esquemas Pydantic (AuditReport, Secret, Vulnerability...)
  reporter.py     # AuditReporter: métricas, JSON y resumen Rich
  scanners/
    gitleaks.py   # Secretos
    semgrep.py    # SAST
    checkov.py    # IaC
tests/            # Suite pytest
```

## Testing

```bash
.venv/bin/python -m pytest
```

Los tests usan `monkeypatch` de `subprocess.run` — no requieren las herramientas
reales instaladas.

## Roadmap

Motor LLM auditor, memoria vectorial (pgvector/Qdrant), escaneo de nube,
dashboard de cliente y generador de entregables (diagramas C4, backlog).
Detalle en `CONTEXT.md`.

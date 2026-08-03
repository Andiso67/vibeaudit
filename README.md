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
| `--memory` | Directorio de memoria de hallazgos recurrentes (ver sección "Memoria") |
| `--cloud` | Escanea la nube del proveedor configurado (solo lectura; ver sección "Escaneo de nube") |
| `--deliverables` | Directorio para entregables de cliente (C4 Mermaid, roadmap, backlog) |
| `--sonar-json` | Exporta el reporte a `sonar-issues.json` (Generic Issue Import de SonarQube) |
| `--sonar-scan` | Ejecuta `sonar-scanner` real sobre el repo (requiere binario y servidor SonarQube) |

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

## Memoria de hallazgos recurrentes

Con `--memory <dir>`, el scan persiste en `<dir>/memory.json` una tienda local
(sin dependencias, ~5-20 MB RAM) con los hallazgos ya vistos y sus soluciones.
Los hallazgos que reaparecen en auditorías posteriores se marcan en el reporte
como `recurrentFindings` con su número de ocurrencias y, si existe, el fix
conocido:

```bash
.venv/bin/python -m vibeaudit.cli scan --path ./mi-repo --output report.json --memory ./memoria
```

Sin `--memory` el scan no registra nada. Además del guardado automático puedes
registrar fixes conocidos a mano:

```bash
.venv/bin/python -m vibeaudit.cli memory add ./memoria \
  --rule CKV_AWS_18 --fix "Restringir los grupos de seguridad a IPs específicas"
.venv/bin/python -m vibeaudit.cli memory list ./memoria
```

La deduplicación se hace por clase de hallazgo (regla o paquete+CVE) y la
similitud semántica entre hallazgos se computa localmente con embeddings
deterministas de n-gramas (coseno); el diseño permite migrar a una vector DB
(Qdrant) sin cambiar la interfaz.

### Escaneo de nube (solo lectura)

With `--cloud`, vibeaudit consulta las APIs de solo lectura del proveedor
configurado por entorno y reporta configs inseguras (`cloudIssues`): buckets
S3 con ACL público, security groups abiertos a `0.0.0.0/0`, etc. Nunca
modifica recursos.

```bash
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
  .venv/bin/python -m vibeaudit.cli scan --path ./mi-repo --output report.json --cloud
```

| Proveedor | Credenciales (env) | Dependencia |
|---|---|---|
| AWS | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (o `AWS_PROFILE`) | `boto3` |
| Azure | `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` | `azure-mgmt` (pendiente) |
| GCP | `GOOGLE_APPLICATION_CREDENTIALS` | `google-cloud-*` (pendiente) |

Sin credenciales configuradas el scan falla limpio con exit 1 indicando qué
variables fijar. AWS se escanea con reglas reales (S3 ACL/get-bucket-acl,
EC2 describe-security-groups); Azure/GCP muestran una advertencia hasta
incorporar sus SDK.

## Dashboard de cliente (Next.js)

En `dashboard/` hay un servidor Next.js (App Router + server components) que
carga el JSON maestro y muestra el **semáforo de riesgo** (rojo si hay
CRITICAL/HIGH, ámbar con MEDIUM, verde si no), tarjetas de resumen, conteos
por severidad, métricas y una tabla por sección del reporte (SAST, secretos,
IaC, CI/CD, custom, nube, LLM, recurrentes, dependencias).

```bash
cd dashboard
npm install
npm run build    # verifica compilación
npm start        # http://localhost:3000
```

El JSON se lee de `dashboard/public/audit-report.json` (o de la variable
`VIBEAUDIT_REPORT`). Un ejemplo real se incluye en
`dashboard/public/audit-report.json`; sin reporte la página indica cómo
señalarlo. Requiere Node >= 20.9.

## Entregables de cliente

Con `--deliverables <dir>` se generan, a partir del JSON maestro, los
entregables de la pre-auditoría en 48h:

- `c4-context.mmd` / `c4-container.mmd` — diagramas C4 (nivel 1 y 2) en
  Mermaid para docs/impresión.
- `roadmap.md` — plan de remediación por fases según severidad (fase 1
  CRITICAL/HIGH, fase 2 MEDIUM, fase 3 LOW/INFO) con los hallazgos agrupados.
- `backlog.csv` / `backlog.json` — backlog de remediación con id, sección,
  regla, archivo, línea, severidad, fase y recomendación por hallazgo.

```bash
.venv/bin/python -m vibeaudit.cli scan --path ./mi-repo --output report.json \
  --deliverables ./entregables
```

Todo se deriva de forma determinista del reporte (sin red, sin LLM).

## Integración SonarQube

SonarQube Community Edition es **gratuita** (open source). VibeAudit ofrece
dos modos:

- **`--sonar-json <archivo>`**: exporta los hallazgos con archivo (SAST,
  secretos, IaC, CI/CD, custom) al formato **Generic Issue Import**
  (`sonar-issues.json`, `engineId: vibeaudit`). Ese fichero se importa en un
  proyecto SonarQube desde *Administration → General Settings → Generic Issue
  Import*, y los hallazgos aparecen en sus dashboards y Quality Gate.

  ```bash
  .venv/bin/python -m vibeaudit.cli scan --path ./mi-repo --output report.json \
    --sonar-json /tmp/sonar-issues.json
  ```

- **`--sonar-scan`**: pasa el control a `sonar-scanner` (análisis real de
  SonarQube sobre el repo). Requiere el binario instalado y la configuración
  del servidor (URL/token en `sonar-project.properties`); si falta, muestra
  una advertencia y el scan continúa sin fallar.

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

Escaneo de nube (AWS/Azure/GCP), dashboard de cliente (Next.js), generador de
entregables (diagramas C4, backlog) y exportación a SonarQube.
Detalle en `CONTEXT.md`.

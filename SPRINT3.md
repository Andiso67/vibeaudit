# Sprint 3 — Motor LLM, memoria y entregables

> **ESTADO: EN CURSO** — Ítems 1-2 completados (motor LLM + checklists YAML); pendientes 3-7.

## Objetivo del Sprint

Elevar la auditoría de "scanner de señales" a "auditor con criterio": un motor
LLM (módulo 3) que revisa el JSON maestro contra checklists (12-Factor, OWASP
Top 10, AWS Well-Architected) y produce hallazgos narrativos con severidad.
Sentar la base de memoria (módulo 4) para deduplicar hallazgos recurrentes y
empezar los entregables de cliente (módulo 5) y el escaneo de nube (módulo 1).

## Contexto (visión completa del producto)

VibeAudit & Knowledge Engine: CLI que clona un repo, ejecuta scanners y genera
un JSON maestro (`AuditReport`). Los Sprints 1 y 2 cerraron la fundación
(ingester, Gitleaks/Semgrep/Checkov, deps OSV, CI/CD, reglas custom, reportes
HTML/MD/dashboard, imagen Docker). Este sprint amplía los módulos 1, 3, 4 y 5.

## Alcance del Sprint 3

### Ítems (backlog)

| # | Ítem | Módulo | Detalle |
|---|---|---|---|
| 1 | **Motor LLM: agentes auditor** | 3 | Nuevo `LLMAuditor`: revisa el `AuditReport` con checklists (12-Factor, OWASP, AWS WAF) y emite hallazgos narrativos (severidad, evidencia, recomendación). Flag `--llm`; default Ollama local sin API key; si el motor no está disponible → warning + skip. Sin red en tests (client fake). |
| 2 | **Checklists como datos** | 3 | Bundle de checklists en YAML (12-Factor, OWASP Top 10, AWS Well-Architected) + mapeo hallazgo→checklist. El motor los carga; el reporte referencia el checklist aplicado. |
| 3 | **Memoria: hallazgos recurrentes** | 4 | Vector DB (Qdrant o pgvector) con post-mortems/soluciones: "ya visto" en reportes anteriores, dedup y sugerencia de fix conocida. Flag `--memory <dir|url>`; sin memoria configurada → no-op. |
| 4 | **Escaneo de nube (solo lectura)** | 1 | Scanners AWS/Azure/GCP vía APIs de solo lectura (credenciales por env o `--profile`), mismos modelos de salida. Detección de configs inseguras (S3 público, SG abiertos, etc.). |
| 5 | **Dashboard de cliente (Next.js)** | 5 | Servidor web que carga el JSON maestro y muestra semáforo de riesgo + las secciones del dashboard HTML actual. |
| 6 | **Generador de entregables** | 5 | Diagramas C4 (Mermaid), roadmap por fases y backlog CSV/JSON. Flag `--deliverables <dir>`. |
| 7 | **Integración SonarQube** | 2 | Exportar el JSON maestro a SonarQube (Generic Issue Import) y/o escanear vía su API. |

### Fuera de alcance (sprints futuros)

- Autenticación de plataforma (solo token de git)
- Base graph DB completa de dependencias
- Interfaz SaaS multi-tenant

## Definition of Done

- [ ] Ítems 1-7 implementados con tests unitarios (monkeypatch, sin red)
- [x] `--llm` produce hallazgos narrativos verificados E2E (real con Ollama: 11 hallazgos sobre `/tmp/s2-e2e`)
- [x] Checklists YAML cargables y referenciados en el reporte
- [ ] Memoria: dedup y sugerencias verificadas E2E (backend local)
- [ ] Scanners de nube: fail limpio sin credenciales
- [ ] Dashboard Next.js arranca y renderiza el JSON maestro
- [ ] Entregables: C4/roadmap/backlog generados y verificados
- [ ] README + SPRINT3.md actualizados; suite completa en verde

## Criterios de Aceptación

- `scan --llm` sin motor disponible → warning y mismo reporte que sin `--llm` (con Ollama local no se necesita key)
- `scan --llm` con key → hallazgos con severidad, evidencia y recomendación
- Hallazgo repetido entre auditorías → sugerencia de fix desde la memoria
- `scan --memory <dir>` sin red → funciona con el backend local
- Escaneo de nube sin credenciales → error limpio + exit 1
- `dashboard` (Next.js) muestra semáforo de riesgo por repo
- `--deliverables` genera C4 Mermaid, roadmap y backlog en los formatos pedidos

## Notas de ejecución

### Ítem 1 — Motor LLM: agentes auditor (EN CURSO → COMPLETADO)

- **Decisión**: cliente `httpx` contra API compatible con OpenAI. Default
  Ollama local (`http://localhost:11434/v1`, modelo `llama3.1`): gratis, sin
  API key. Variables de entorno: `VIBEAUDIT_LLM_BASE_URL`, `VIBEAUDIT_LLM_MODEL`,
  `VIBEAUDIT_LLM_API_KEY` (opcional), `VIBEAUDIT_LLM_TIMEOUT` (default 600).
- **`vibeaudit/llm.py`**: `LLMConfig.from_env()`, `LLMClient.chat()` (errores →
  `LLMUnavailableError`), `ChecklistItem`, `STARTER_CHECKLIST` (6 ítems:
  12-factor.config, owasp.sensitive-data, owasp.injection, owasp.code-eval,
  waf.iam-least-privilege, waf.dependencies), `LLMAuditor` con
  `build_messages()` (system pide SOLO JSON `{"findings":[...]}`, máx. 10
  hallazgos), `_build_user_prompt()` (resumen + top 40 por sección + checklist),
  `parse_response()` (tolera fences ```json e JSON embebido; normaliza
  `checklistRef` con corchetes; items inválidos ignorados).
- **Modelos**: `LLMFinding` (title, severity, checklistRef, evidence,
  recommendation, relatedFiles) + `llmFindings` en `AuditReport`
  (camelCase en JSON).
- **CLI**: flag `--llm`; si el motor no está disponible → advertencia amarilla
  y reporte normal (exit 0, no crash).
- **Reporter**: fila "Hallazgos LLM" en `print_summary`, total incluyéndolos,
  sección "Auditoría LLM (checklists)" en HTML y Markdown, tarjeta LLM + tabla
  con filtro en el dashboard. `llm_findings` aceptado en el constructor de
  `AuditReporter`.
- **Tests**: 27 nuevos (218 total), sin red: `httpx.MockTransport` inyectado en
  `LLMClient`, `FakeLLMClient` en auditor/CLI, y reporter (json/html/md/dashboard/
  print_summary).
- **E2E real** (Ollama 0.32.5 + llama3.1, `/tmp/s2-e2e`): 11 hallazgos LLM
  mapeados a issues reales (p.ej. CKV_AWS_20 → waf.iam-least-privilege);
  dashboard con la sección LLM renderizada. Sin Ollama → advertencia + reporte.
- **Ajustes encontrados en el E2E real**: timeout default 120s → 600s (llama3.1
  local en CPU superaba los 120s); normalización de `checklistRef` con
  corchetes `[x]` que devuelve el modelo.
- **Fix de revisión**: la tabla "Vulnerabilidades por severidad" de
  `print_summary` no incluía los hallazgos LLM (mostraba menos que el total);
  ahora cuenta severidades sobre todos los tipos (SAST, secretos, IaC, CI/CD,
  custom, LLM, deps) igual que el dashboard, con test de regresión.

### Ítem 2 — Checklists como datos (COMPLETADO)

- **Bundle YAML** en `vibeaudit/checklists/` (3 archivos, 12 ítems):
  `12-factor.yaml` (config, dependencies, backing-services), `owasp-top10.yaml`
  (injection, sensitive-data, code-eval, broken-auth, vulnerable-deps) y
  `aws-well-architected.yaml` (iam-least-privilege, encryption, logging,
  network-security). `pyproject.toml` package-data incluye `checklists/*.yaml`.
- **Modelos** (`models.py`): `ChecklistMatch` (sections, rules glob, minSeverity),
  `ChecklistItem` ampliado (framework, severity, match), `AppliedChecklist`
  (name, itemCount, matchedFindings) y `AuditReport.checklists` (JSON
  `checklists`) que referencia los checklists aplicados.
- **`vibeaudit/checklists/__init__.py`** (loader): `load_checklist_file`,
  `load_checklists(bundle_dir)` (para tests con directorios custom),
  validación estricta (`ChecklistBundleError` para YAML inválido, falta de
  `items`, ítems inválidos e ids duplicados), `match_finding` (sección + glob
  de regla + severidad mínima), `match_report` y `applied_checklists`.
- **Integración LLM**: `STARTER_CHECKLIST = load_checklists()` (el bundle es el
  default); el prompt lista cada ítem con su framework y alcance de mapeo
  (`[aplica a iac,cicd >= HIGH]`); `audit()` rellena `report.checklists`.
- **Reporter**: fila "Checklists aplicados" en `print_summary` y tarjeta
  "Checklists" en el dashboard (el JSON maestro ya incluye el campo).
- **Tests**: 14 nuevos en `tests/test_checklists.py` (232 total), incluyendo
  validación de errores y mapeo CKV_AWS_20/18 → aws.iam-least-privilege.
- **E2E real** (`/tmp/s2-e2e`, Ollama + llama3.1): `checklists` en el JSON con
  los 3 frameworks y `matchedFindings` reales (AWS WAF: 6 hallazgos de los
  CKV_AWS del scan); 11 hallazgos LLM con checklistRef.

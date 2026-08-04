# Sprint 3 — Motor LLM, memoria y entregables

> **ESTADO: COMPLETADO** — Ítems 1-7 implementados (motor LLM, checklists YAML, memoria, escaneo nube, dashboard, entregables, SonarQube).

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

- [x] Ítems 1-7 implementados con tests unitarios (monkeypatch, sin red)
- [x] `--llm` produce hallazgos narrativos verificados E2E (real con Ollama: 11 hallazgos sobre `/tmp/s2-e2e`)
- [x] Checklists YAML cargables y referenciados en el reporte
- [x] Memoria: dedup y sugerencias verificadas E2E (backend local: 15 recurrentes en el 2º scan)
- [x] Scanners de nube: fail limpio sin credenciales
- [x] Dashboard Next.js arranca y renderiza el JSON maestro
- [x] Entregables: C4/roadmap/backlog generados y verificados
- [x] README + SPRINT3.md actualizados; suite completa en verde (277)

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

### Ítem 3 — Memoria: hallazgos recurrentes (COMPLETADO)

- **Decisión**: tienda 100 % local sin backend (`<dir>/memory.json`, ~5-20 MB
  RAM, 0 dependencias nuevas), validada contra el hardware real (Mac M1,
  16 GB). Por defecto Ollama comparte CPU/RAM con el scan; una vector DB (Qdrant)
  se dejaría para despliegue servido. La interfaz `MemoryStore` está preparada
  para migrar a Qdrant sin tocar `cli.py`/`reporter.py`.
- **`vibeaudit/memory.py`**: `LocalEmbedder` (256-d determinista: n-gramas 3-4
  + tokenización por palabras, similitud coseno), `MemoryStore` (carga/guarda
  `<dir>/memory.json`, `ingest_report`, `upsert` con `_identity_key` por regla o
  paquete+CVE, secciones sast/secrets/iac/cicd/custom/deps), umbral de
  recurrencia 0.5. Memoria corrupta o vacía → carga como nueva; en `__main__`
  no crea la tienda (no pisa la nada).
- **Modelos**: `RecurrentFinding` (rule, severity, file, occurrences,
  firstSeen, lastSeen, suggestion) + `AuditReport.recurrent_findings` (JSON
  `recurrentFindings`); `MemoryStore.upsert` lo rellena al inyectar el reporte.
- **CLI**: `--memory <dir>` en `scan` (no-op sin la flag); subcomando `memory add`
  (`--rule/--fix/--evidence/--framework`) y `memory list` (tabla Rich), como typer
  app en `cli.py`.
- **Reporter**: fila "Hallazgos recurrentes (memoria)" en `print_summary`,
  tarjeta "Recurrentes" en el dashboard, `Suggestion`/`occurrences` en el JSON.
- **Tests**: `tests/test_memory.py` (13) + 3 CLI (248 total): sin `--memory`
  no crea fichero, 2º scan rea CKV_AWS_20 → occurrences=2, `memory add/list`
  E2E CLI.
- **E2E real** (`/tmp/s2-e2e`, `--memory /tmp/mem-e2e`): 1º scan → 0 recurrentes
  y `memory.json` creado; 2º scan → **15 recurrentFindings** (CKV_AWS_18/20,
  sqlalchemy-execute-raw-query…) con occurrences=2 en `print_summary` y JSON.
- **README**: sección "Memoria de hallazgos recurrentes" con flag `--memory`,
  `memory add/list` y formato `memory.json`.

### Ítem 4 — Escaneo de nube (COMPLETADO)

- **Decisión**: primero el proveedor AWS funcionando con `boto3` (ya instalado) y
  detección de credenciales por env para AWS/Azure/GCP. En ningún caso se exige
  red en tests (clientes fake inyectados); el escaneo usa solo APIs de lectura
  (`list_buckets`, `get_bucket_acl`, `describe_security_groups`), nunca modifica
  recursos.
- **`vibeaudit/scanners/cloud.py`**: `CloudScanner(providers=None, clients=None)`;
  `configured_providers()` detecta credenciales: AWS vía `botocore.session` sin
  red (env, perfil, roles) y Azure/GCP por variables de entorno
  (`PROVIDER_ENV_VARS`). `scan()` → `RuntimeError` limpio "No hay credenciales de
  nube" si ninguno está configurado (el CLI lo traduce a exit 1 con sugerencia
  específica de nube).
- **Reglas AWS**: `aws-s3-bucket-public` (grants AllUsers/AuthenticatedUsers en
  el ACL del bucket) y `aws-ec2-security-group-open` (ingress abierto a
  `0.0.0.0/0` o `::/0`, incluso puertos `-1`). Azure/GCP: placeholder con
  advertencia y `NotImplementedError` hasta incorporar sus SDK.
- **Modelo** `CloudIssue` (provider, rule, resource, resourceType, region,
  severity, description, recommendation) + `AuditReport.cloud_issues` (JSON
  `cloudIssues`).
- **CLI**: flag `--cloud` (no-op sin ella); error de credenciales → mensaje
  específico de nube + exit 1. Reporter: fila "Seguridad en la nube" en
  `print_summary` y `_summary_rows`, sección con su tabla en HTML/Markdown, y
  tarjeta "Nube" + sección `sec-cloud` en el dashboard.
- **Tests**: `tests/test_cloud.py` (8, suite 256): fakes S3/EC2, ACL anónimo
  filtrado, puertos abiertos (incl. `-1`), sin credenciales → RuntimeError, y
  detección de proveedores por env.
- **E2E fail limpio**: `scan --path tests --cloud` sin credenciales →
  "No hay credenciales de nube configuradas" + exit 1. E2E con fakes: 2 issues
  (`aws-s3-bucket-public`, `aws-ec2-security-group-open`) presentes en JSON,
  Markdown, HTML y dashboard (`/tmp/cloud-e2e*`).

### Ítem 5 — Dashboard de cliente (COMPLETADO)

- **Decisión**: app Next.js en `dashboard/` (App Router, server components,
  JSX sin TS). Server component `app/page.jsx` lee el JSON maestro del disco
  en cada petición (`export const dynamic = "force-dynamic"`): primero
  `VIBEAUDIT_REPORT` (env) y luego `public/audit-report.json`.
- **Semáforo de riesgo**: rojo si hay CRITICAL/HIGH, ámbar si solo MEDIUM,
  verde si no hay nada de eso — calculado sobre todas las secciones
  (SAST, secretos, IaC, CI/CD, custom, nube, LLM, recurrentes, deps).
- **Contenido**: tarjetas de resumen por sección + total, lista por
  severidad, métricas (LOC, tests, deps con CVEs) y una tabla por sección
  (issue/cloud/deps/llm/recurrent, cada una con su renderizador).
- **Ejemplo real**: `dashboard/public/audit-report.json` (scan del propio
  repo con issues de nube fakes: 2 SAST, 2 IaC, 2 nube, 18 deps).
- **Verificación**: `npm install` (22 paquetes), `npm run build` compila,
  `next start` + curl → semáforo rojo "Riesgo alto" (1 CRITICAL, 20 HIGH),
  tarjetas y tablas renderizadas. Node v26.4.0/npm 11.17.0 verificados antes.
- **Nota**: `node_modules/` y `.next/` en `.gitignore` del dashboard.

### Ítem 6 — Generador de entregables (COMPLETADO)

- **Decisión**: entregables deterministas derivados del JSON maestro (sin red,
  sin LLM) con `--deliverables <dir>`: diagramas C4 en Mermaid, roadmap por
  fases y backlog CSV/JSON. `vibeaudit/deliverables.py`.
- **C4**: `c4-context.mmd` (nivel 1: usuario → VibeAudit → JSON → dashboard/
  entregables) y `c4-container.mmd` (nivel 2: CLI, ingester, scanners, LLM,
  memoria, reporter, entregables) en bloques Mermaid fenced.
- **Roadmap**: `roadmap.md` por fases según severidad — Fase 1 (CRITICAL/HIGH),
  Fase 2 (MEDIUM), Fase 3 (LOW/INFO) — con tabla de hallazgos por fase
  (id, tipo, regla, archivo, severidad).
- **Backlog**: `backlog.csv` (id, seccion, regla, archivo, linea, severidad,
  fase, recomendacion) y `backlog.json` (mismos datos + fases +
  resumen_por_seccion). Cada hallazgo lleva recomendación (del campo
  correspondiente o por defecto por tipo).
- **CLI**: flag `--deliverables <dir>`; crea el directorio y lista los archivos
  generados al terminar.
- **Tests**: `tests/test_deliverables.py` (8) + 1 CLI (265 total).
- **E2E real** (reporte de `/tmp/r6.json` y del dashboard con 18 deps): 5
  archivos en `/tmp/entregables-real`; roadmap con Fase 1 poblada
  (dockerfile.security.*, iac CKV_AWS, cloud) y backlog.json con resumen
  {sast: 2, iac: 2, cloud: 2, deps: 18}.

### Ítem 7 — Integración SonarQube (COMPLETADO)

- **Decisión**: dos vías complementarias. SonarQube Community es gratuito
  (open source); no hace falta licencia para importar hallazgos externos.
- **Pieza 1 — Generic Issue Import** (`vibeaudit/sonar.py`): `to_sonar_issues`
  convierte el reporte al formato `sonar-issues.json` de SonarQube
  (`engineId: vibeaudit`, `type: VULNERABILITY`, severidades mapeadas
  CRITICAL→BLOCKER, HIGH→CRITICAL, MEDIUM→MAJOR, LOW→MINOR, INFO→INFO, con
  `primaryLocation.filePath`/`textRange`). Solo entran hallazgos con archivo
  (SAST, secretos, IaC, CI/CD, custom); los sin archivo (nube, LLM, deps) se
  descartan. `save_sonar_json` lo escribe; flag CLI `--sonar-json <archivo>`.
  Límite de 1000 issues por import (el de SonarQube).
- **Pieza 2 — sonar-scanner**: `SonarRunner` (passthrough) con
  `is_installed()` y `scan()` que ejecuta `sonar-scanner -Dsonar.projectBaseDir`
  y, si hay `sonar-issues.json`, añade
  `-Dsonar.externalIssuesReportPaths=<path>` (la vía real de import en 9.9).
  Flag CLI `--sonar-scan`; sin binario → advertencia y el scan continúa
  (mismo patrón que `--llm` sin motor).
- **Tests**: `tests/test_sonar.py` (10) + 2 CLI (278 total): formato del
  import, mapeo de severidad, descarte de sin-archivo, fichero escrito,
  is_installed y scan con monkeypatch (sin red).
- **E2E real** (reporte del dashboard): `/tmp/sonar-issues.json` con 4 issues
  (2 SAST + 2 IaC, todos CRITICAL/HIGH → CRITICAL en SonarQube), engineId y
  tipo correctos.
- **Integración en vivo (SonarQube 9.9.8 Community en Docker, puerto 9000)**:
  `sonar-scanner` 8.1 (Homebrew, Java 21) analizó el repo contra el servidor
  real con `-Dsonar.login=<token> -Dsonar.externalIssuesReportPaths=…`:
  - **Issues de VibeAudit importadas** como `external_vibeaudit:*` (2 SAST
    Dockerfile CRITICAL visibles en la lista de VULNERABILITY del proyecto).
  - Las 2 IaC de checkov sobre `Dockerfile` se ignoraron por el servidor:
    `Dockerfile` no es archivo fuente analizado en 9.9 Community (limitación
    del servidor, el JSON estaba bien formado).
  - SonarQube añadió ~104 issues propias (code smells Python/JS + un AWS
    secret BLOCKER en `dashboard/public/audit-report.json`, el ejemplo).
  - **Aprendizaje clave**: en 9.9 el import NO es vía menú/UI ni API pública;
    es el análisis del scanner con `sonar.externalIssuesReportPaths`. Los
    tokens van por `-Dsonar.login` (no `sonar.token`).

## Estado del Sprint 3

**Completado 7/7 ítems** — suite 277 passed, E2Es reales en ítems 1-7.

**Verificación Docker (completada)** — `docker build -t vibeaudit:test` OK con
el ítem 7; `scan --help` muestra `--sonar-json`/`--sonar-scan` dentro del
contenedor; E2E real en imagen: repo con `GITHUB_TOKEN` → 1 issue
(`secret-…-generic-api-key`, CRITICAL, `t.env`) exportado a `sonar-issues.json`.
(Nota: las claves AWS de ejemplo `AKIAIOSFODNN7…` están en el allowlist de
gitleaks, por eso no se detectan.)

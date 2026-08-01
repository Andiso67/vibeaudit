# Sprint 2 — Cierre del ciclo de auditoría

> **ESTADO: EN CURSO** — Ítems 1, 2, 3 y 4 completados (ver notas de cierre al final).

## Objetivo del Sprint

Completar la foto de seguridad del repositorio auditado: dependencias con CVEs,
análisis de CI/CD y reglas custom de "Vibe Coding". Mejorar la usabilidad del
CLI (escaneo de directorio local, auth y selección de rama) y producir
entregables legibles para el cliente (HTML/Markdown y dashboard básico).

## Contexto (visión completa del producto)

VibeAudit & Knowledge Engine: herramienta CLI que clona un repo, ejecuta
scanners de seguridad y genera un JSON maestro (`AuditReport`). La herramienta
completa tendrá 5 módulos (ver SPRINT.md). El Sprint 1 cerró la fundación
(ingester, Gitleaks/Semgrep/Checkov, reporter, CLI, imagen Docker). Este sprint
amplía módulos 1, 2 y 5.

## Alcance del Sprint 2

### Ítems (backlog)

| # | Ítem | Módulo | Detalle |
|---|---|---|---|
| 1 | **Dependencias con CVEs** | 1 | Rellenar `dependenciesWithCves`: parsear lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, `requirements.txt`, `go.sum`) y consultar OSV API. Manejo sin red → lista vacía + warning. |
| 2 | **Análisis de CI/CD** | 2 | Nuevo `CICDScanner`: detectar `.github/workflows/*.yml` y `.gitlab-ci.yml`, escanearlos con semgrep (reglas de seguridad en pipelines) o parser propio con checks básicos (pinned actions, secrets en env). |
| 3 | **Reglas custom "Vibe Coding"** | 2 | Flag `--rules <dir>`: bundle de reglas semgrep YAML propias (ej. `SELECT *`, `any` en TypeScript, logging sin logger). Si no se pasa, comportamiento actual. |
| 4 | **Reporte HTML/Markdown** | 5 | Nuevos métodos en `AuditReporter`: `save_html()` y `save_markdown()` (misma data del JSON). Flag `--format json\|html\|md` en CLI. |
| 5 | **Escaneo de directorio local** | 1 | Flag `--path <dir>`: auditar un directorio sin clonar (formaliza el workaround `file://`; sin `.git` → metadatos parciales). Mutuamente excluyente con `--repo-url`. |
| 6 | **Auth y ramas** | 1 | Flags `--token` (usa el token en el clone), `--branch`/`--tag` (checkout después del clone depth=1) y `--depth` configurable (default 1). |
| 7 | **Dashboard básico** | 5 | `--dashboard`: genera HTML autocontenido que carga el JSON y muestra resumen (métricas, severidades, tablas de hallazgos). Sin servidor ni JS externo. |

### Fuera de alcance (sprints futuros)

- Motor de análisis LLM (módulo 3)
- Base de conocimiento vectorial/graph (módulo 4)
- Escaneo de nube vía APIs (requiere credenciales)
- SonarQube
- Dashboard con servidor/SaaS, diagramas C4, backlog Jira/Linear
- Autenticación de plataforma (solo token de git)

## Definition of Done

- [ ] Ítems 1-7 implementados con tests unitarios (monkeypatch, sin red)
- [ ] `dependenciesWithCves` poblado con datos reales verificados E2E
- [ ] Scanners: exit codes y ausencia de datos manejados sin crash
- [ ] CLI: flags nuevos con validación (mutua exclusión `--repo-url`/`--path`)
- [ ] Reportes HTML/MD/dashboard generados y abiertos localmente
- [ ] README + SPRINT2.md actualizados; suite completa en verde
- [ ] Imagen Docker reconstruida con los cambios

## Criterios de Aceptación

- `scan --path ./repo` funciona sin clonar y sin repo remoto
- `scan --repo-url X --token ... --branch main` clona y audita la rama indicada
- Lockfile con vuln conocida → aparece en `dependenciesWithCves`
- `.github/workflows` con `pull_request_target` sin `permissions` → hallazgo CI/CD
- `--rules` con regla custom → hallazgo de la regla en el reporte
- `--format html` → archivo abrible en navegador con los hallazgos

## Notas de cierre — Ítem 1 (Dependencias con CVEs) ✅

- **Modelo**: `DependencyVulnerability` (23 campos, incl. `cveIds`, `cweIds`,
  `cvssScore`, `fixedVersion`, `affectedRange`, `isFixAvailable`, `purl`,
  `exploitedInWild`/`epssScore` opcionales para futuras fuentes) + campo
  `dependencyVulnerabilities` en `Metrics`. Aliases camelCase con
  `populate_by_name = True`.
- **Scanner**: `vibeaudit/scanners/deps.py` — `DependencyScanner` parsa 9
  lockfiles (npm/yarn/pnpm, poetry/requirements/Pipfile, go.sum, Gemfile,
  Cargo.lock, composer, bundles). `direct`/`dependency_type` solo en npm y
  poetry; resto `unknown`.
- **OSV**: `POST /v1/querybatch` devuelve solo `id`+`modified` → segundo batch
  de `GET /v1/vulns/{id}` por advisory. CVSS v3.x calculado desde el vector
  (`_parse_cvss_vector`) o score directo. Dedup por CVE conservando el más
  severo (`_dedupe_vulnerabilities`). Sin red → warning + lista vacía.
- **Integración**: ejecutado en `cli.py scan`, incluido en el resumen Rich
  (fila "Dependencias con CVEs" y total) y en `metrics.dependencyVulnerabilities`
  del JSON (serializado con `by_alias=True`).
- **Validación**: 24 tests nuevos (72 total); E2E con repo npm (lodash 4.17.20 +
  axios 0.21.1) → 27 vulns únicas con CVSS y fixes correctos (ej. axios → 0.31.1).
- **Pendiente**: KEV/EPSS cuando exista la fuente (campos ya listos).

## Notas de cierre — Ítem 2 (Análisis de CI/CD) ✅

- **Scanner**: `vibeaudit/scanners/cicd.py` — `CICDScanner`, parser propio sin
  herramienta externa (`is_installed()` siempre True). Detecta
  `.github/workflows/*.{yml,yaml}` y `.gitlab-ci.yml`.
- **Checks GitHub Actions**:
  - `cicd-github-pr-target-no-permissions` (HIGH): `pull_request_target` sin
    bloque `permissions:` en el workflow.
  - `cicd-github-action-not-pinned` (MEDIUM): acciones de terceros (fuera de
    `actions|github|docker|azure|aws-actions`) referenciadas por tag/rama en vez
    de SHA de 40 hex.
  - `cicd-github-secret-in-run` (HIGH): `${{ secrets.* }}` interpolado en
    bloques `run:` (multilínea incluido).
- **Checks GitLab CI**: `cicd-gitlab-token-in-script` (MEDIUM): tokens
  (`$CI_JOB_TOKEN`, `$CI_REGISTRY_PASSWORD`, `$CI_DEPLOY_PASSWORD`) usados en
  scripts (posible fuga en logs).
- **Modelo**: campo `cicdIssues` (List[Vulnerability]) en `AuditReport`;
  incluido en el resumen Rich y el total de hallazgos.
- **Validación**: 17 tests nuevos (90 total); E2E con repo de prueba (2
  workflows + GitLab CI) → 4 hallazgos correctos (2 HIGH + 2 MEDIUM) y
  `actions/checkout@v4` correctamente ignorado por ser de confianza.
- **Verificaciones extra** (3 rondas, el usuario pidió revisar 2 veces más):
  - Ronda 1: bloque `script:` de GitLab absorbía líneas de otros jobs
    (ahora por indentación), `"on":` con comillas no se detectaba, y
    `# permissions:` comentado contaba como válida.
  - Ronda 2: scripts shell que *generan* texto `uses:` se marcaban como
    acciones sin pin (`_run_block_line_indexes`), secretos/tokens comentados
    (`#`) generaban hallazgos, y bloques `run:` consecutivos se duplicaban
    por comparación incorrecta de indentación.
  - Ronda 3 (con workflows reales de `actions/starter-workflows` y
    super-linter): `pull_request_target` en un comentario del bloque `on:`
    disparaba falso HIGH, líneas vacías dentro de `on:` ocultaban el
    trigger real, BOM UTF-8 rompía el análisis de la primera línea, y los
    tokens en `before_script:`/`after_script:` de GitLab no se detectaban.

## Notas de cierre — Ítem 3 (Reglas custom "Vibe Coding") ✅

- **Scanner**: `vibeaudit/scanners/custom.py` — `CustomRulesScanner`, ejecuta
  semgrep con `--config <rules_dir>` (en vez de `--config auto`). A diferencia
  de `SemgrepScanner`, conserva TODAS las severidades (las reglas custom de
  estilo suelen ser WARNING/INFO). Sin `--rules` el flujo no cambia.
- **Modelo**: campo `customIssues` (List[Vulnerability]) en `AuditReport`,
  incluido en el resumen Rich (fila "Reglas custom") y en el total.
- **CLI**: flag `--rules <dir>` opcional; si el directorio no existe o no es
  dir → `ValueError` limpio (sin traceback). El check_id de semgrep viene
  prefijado con el namespace del directorio → se limpia a `custom.<id>`.
- **Ejemplo de bundle**: `no-sql-select-star`, `no-any-ts`, `use-logger`
  (verificado E2E con repo Python/TS/JS → 3 hallazgos con severidades
  LOW/MEDIUM en el JSON final).
- **Validación**: 13 tests nuevos (121 total).

## Notas de cierre — Ítem 4 (Reporte HTML/Markdown) ✅

- **Reporter**: `AuditReporter.save_markdown()` y `AuditReporter.save_html()` usan
  la misma data del `AuditReport` (sin re-escanear). HTML autocontenido: CSS
  inline, sin JS externo, badges de severidad con colores y escape de HTML
  (`html.escape`) para reglas/snippets peligrosos.
- **Markdown**: secciones por tipo (SAST, secretos, IaC, CI/CD, custom, deps),
  resumen en tabla, metadatos (repo/rama/commit) y métricas. "No se encontraron
  hallazgos." en secciones vacías.
- **CLI**: flag `--format json|html|md` (default json, validado por typer/click
  con `OutputFormat` enum — `Literal` NO es soportado por typer 0.9, da
  "Type not yet supported"). `--output` ahora opcional: default
  `audit-report.<formato>`.
- **Validación**: 6 tests nuevos (156 total). E2E con `--format html|md|json`
  sobre repo con secretos/SAST/IaC → los 3 archivos generados y verificados
  (HTML abrible en navegador, Markdown con `aws-access-token — CRITICAL`).
- **Verificación extra** (revisión de robustez del ítem 4):
  - Bug encontrado: snippet con triple backtick (` ``` `) rompía el code fence
    del Markdown (fences impares → el resto del documento quedaba dentro del
    bloque de código). Fix: `_md_fence()` elige un fence más largo que la racha
    de backticks del snippet.
  - Verificado sin fallos: snippets gigantes (100 KB), snippets con HTML
    peligroso (escape en HTML, validado con parser de tags balanceados),
    deps sin fix/CVEs, summary multilínea, nombres con caracteres especiales,
    sin metadatos, severidades sin contador. E2E real con deps OSV → 27 badges
    y fixes correctos en HTML/MD; `--rules` + `--format html` → 3 hallazgos
    custom en el HTML. 157 tests en verde.

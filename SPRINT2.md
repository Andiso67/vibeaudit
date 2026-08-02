# Sprint 2 — Cierre del ciclo de auditoría

> **ESTADO: EN CURSO** — Ítems 1, 2, 3, 4, 5, 6 y 7 completados (ver notas de cierre al final).

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

- [x] Ítems 1-7 implementados con tests unitarios (monkeypatch, sin red)
- [x] `dependenciesWithCves` poblado con datos reales verificados E2E
- [x] Scanners: exit codes y ausencia de datos manejados sin crash
- [x] CLI: flags nuevos con validación (mutua exclusión `--repo-url`/`--path`)
- [x] Reportes HTML/MD/dashboard generados y abiertos localmente
- [x] README + SPRINT2.md actualizados; suite completa en verde
- [x] Imagen Docker reconstruida con los cambios

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
- **Verificación extra 2** (segunda pasada de robustez, `2af9f9e`):
  - Bug encontrado: regla con backticks (`rule\`with\`ticks`) — el escape con
    backslash NO es válido en code spans de CommonMark (`<code>r\</code>x`).
    Fix: `_md_code()` usa delimitador de code span dinámico (más backticks que
    la racha máxima del texto, como `_md_fence`).
  - Mejora defensiva: blank line entre la cabecera `###` y el fence del snippet
    (compatibilidad con renderers estrictos de Markdown).
  - Verificado con renderer real (python-markdown con `tables` + `fenced_code`,
    comportamiento GFM): tablas del resumen OK, snippets como `<pre><code>`
    (9 code blocks en el E2E), regla con backticks como `<code>r`x</code>`.
  - Verificado sin fallos: CRLF en snippets (se preserva `\r\n` intacto, no es
    bug), no-ASCII, `-o` apuntando a un directorio existente (error limpio
    "Is a directory" + exit 1), snippets de 4+ backticks (fence dinámico los
    absorbe). 159 tests en verde.

## Notas de cierre — Ítem 5 (Escaneo de directorio local) ✅

- **Ingester**: `RepoIngester(repo_url=..., local_path=...)` — exactamente uno
  de los dos (validado en `__init__` con ValueError). Modo local: valida que el
  path exista y sea directorio (`_load_local`), usa el directorio directamente
  sin copiar ni borrar nada (`_cleanup` solo limpia el temp de clones).
  Metadatos parciales sin `.git`: `repositoryUrl`/`defaultBranch`/`commitHash`
  quedan `null`; con `.git` se capturan rama y commit del working tree. El
  `name` del proyecto es el basename del directorio.
- **CLI**: flag `--path <dir>` mutuamente excluyente con `--repo-url` (error
  limpio + exit 1 si ambos o ninguno). El flag `-u` dejó de ser obligatorio.
  Progress muestra "Analizando directorio local..." en vez de "Clonando...".
- **Bug encontrado en E2E**: gitleaks escanea commits, no el filesystem — sin
  `.git` daba "0 commits scanned, ~0 bytes" y un falso negativo silencioso.
  Fix: `--no-git` en el comando `detect` cuando no existe `.git` en el
  repo_path (gitleaks >= 8.17). Además, con `--no-git` gitleaks reporta rutas
  absolutas → `_parse_output` las relativiza al repo_path (fuera del repo se
  conservan).
- **Validación**: 10 tests nuevos (169 total): metadatos parciales sin `.git`,
  rama/commit con `.git`, path inexistente/no-dir → ValueError, no borra el
  directorio local, exclusividad en `__init__`, validación de flags en el CLI
  (sin args, ambos args, scan completo con `--path`), rutas absolutas en
  gitleaks. E2E real: dir sin `.git` → secreto CRITICAL + 8 IaC con
  `app.py` relativo; dir con `.git` → rama/commit/1 secreto; `--path` inexistente
  y archivo → errores limpios + exit 1.
- **Verificación extra** (segunda pasada, `57d1f4d`):
  - Bug encontrado: repo con `.git` SIN commits (`git init` sin commit o `.git`
    roto) → gitleaks escaneaba "0 commits" y daba falso negativo silencioso con
    secretos en el working tree. Fix: `_has_git_history()` con
    `git rev-parse --verify HEAD` decide `--no-git` (no solo la existencia de
    `.git`). E2E: repo sin commits con AWS key → 1 secreto detectado.
  - Verificado sin fallos: dir vacío, nombres no-ASCII (escaneo y reporte),
    symlink circular, archivos sin permisos, `.git` roto, `--path` + `--rules`
    (regla custom), `--path` + `-f html`, worktree (`.git` como archivo, no
    dir), `~` expandido, reporte guardado dentro del dir auditado, deps OSV
    reales (27 vulns) vía `--path`. 173 tests en verde.

## Notas de cierre — Ítem 6 (Auth y ramas) ✅

- **Ingester**: `RepoIngester` acepta `token`, `branch` y `depth`. El clone
  inyecta el token en la URL (`https://token@host/...`, solo http/https),
  pasa `depth`/`branch` a `Repo.clone_from` y después limpia el origin del
  repo temporal con `set_url()` (el token nunca queda en `.git/config`).
  `GIT_TERMINAL_PROMPT=0` en el env del clone: git falla limpio sin pedir
  credenciales por terminal (que imprimiría el token en la URL).
- **Sanitización**: `sanitize_url()` a nivel módulo quita credenciales
  embebidas (`https://token@host/...` → `https://host/...`). Se aplica en los
  mensajes de error del ingester, en el mensaje "▶ Auditando" del CLI y en
  `repositoryUrl` del JSON (vía `_capture_repository_url`). El `--tag` deja el
  HEAD detached → `defaultBranch` null (correcto).
- **CLI**: flags `--token`, `--branch`, `--tag` y `--depth` (min=1, validado
  por typer). Validaciones: `--branch`+`--tag` → error; `--path` con cualquiera
  de los 4 → error (solo aplican con `--repo-url`).
- **Validación**: 15 tests nuevos (184 total): inyección del token en la URL,
  reemplazo de credenciales previas, kwargs depth/branch/env, origin limpio,
  modo local rechaza token, sanitize_url, validaciones del CLI (branch+tag,
  path+token, path+depth, depth inválido) y scan real con `--branch --depth`.
  E2E: `--branch feature` → rama y commit correctos (v3); `--tag v1.0` →
  detached + commit del tag (LOC 1, solo la versión taggeada); branch
  inexistente → error limpio; token inválido en URL pública → error sin filtrar
  el token ni en mensajes ni en stderr de git.
- **Verificación extra** (`f80f075`):
  - Bug encontrado: `sanitize_url` mutilaba URLs SSH legítimas
    (`ssh://git@github.com/...` → `ssh://github.com/...`): el `git@` es el
    usuario del transporte, no una credencial. Fix: solo saneo http/https
    (igual que `_inject_token`).
  - Verificado con servidor git HTTP real (git-http-backend + CGI + repo
    bare con push de main/feature): token inyectado en el clone, origin del
    repo temporal sin token (`.git/config` limpio), `repositoryUrl` sin token,
    0 fugas del token en output/JSON/stderr (GitPython redacta la cmdline como
    `http://*****@...`), `--branch feature --depth 1` remoto → rama/commit/LOC
    correctos (3 líneas: a.py v1+v2 + b.py v3). Repo 404 → error limpio
    saneado + exit 1. 184 tests en verde.

## Notas de cierre — Ítem 7 (Dashboard básico) ✅

- **Reporter**: `AuditReporter.save_dashboard()` — HTML autocontenido que
  embebe el JSON maestro (el mismo `to_json()` del reporte) en un
  `<script id="audit-data" type="application/json">`. Render con JavaScript
  vanilla (sin servidor, sin JS/CSS externo): funciona abriendo el archivo con
  `file://`.
- **Seguridad del embebido**: el JSON se escapa de las secuencias que romperían
  el bloque de datos — `</` → `<\/` y `<!--` → `<\u0021--` (ambas válidas en
  JSON, `JSON.parse` las resuelve). El render usa `textContent` (nunca
  `innerHTML`), así que reglas/snippets con HTML peligroso se muestran como
  texto plano.
- **Contenido**: tarjetas de resumen por tipo (SAST, secretos, IaC, CI/CD,
  custom, deps) + total, barras por severidad (colores por nivel CRITICAL→INFO),
  métricas (LOC, test files, deps con CVEs) y 6 tablas con detalle (snippet en
  `<pre>` para hallazgos, fix/CVEs/summary para deps). Campo de búsqueda que
  filtra filas y oculta secciones vacías.
- **CLI**: flag `--dashboard` (independiente de `--format`): además del reporte
  genera `<output>-dashboard.html` (ej. `audit-report.json` →
  `audit-report-dashboard.html`) e imprime "✔ Dashboard guardado en...".
- **Validación**: 5 tests nuevos (189 total): JSON embebido parseable y con
  datos reales (CVE, regla), dashboard vacío, escape de `</script>` y `<!--`
  dentro del JSON (el dato se conserva íntegro tras parsearlo), creación de
  directorios padre, y test CLI del flag `--dashboard`.
- **E2E real**: `scan --path /tmp/e2e-dashboard --format html --dashboard` →
  reporte HTML + dashboard generados; dashboard abierto en navegador con 8
  hallazgos IaC (CKV_AWS_20 HIGH), JSON embebido verificado (1 solo bloque de
  datos, sin `</script>` crudo dentro).
- **Verificación extra** (pasada de robustez tras el E2E):
  - Embebido: round-trip exacto `JSON parseado == to_json()` con payloads
    hostiles (`` </script>``, `<!--`, combinados, backslash literal, escapes
    unicode, emoji, 200 concatenaciones, bytes nulos); solo 2 bloques
    `<script>`; sin `innerHTML`/`eval`/`document.write`/recursos externos.
  - Render: el IIFE real ejecutado con DOM mock en node (dashboard con datos
    reales de awslabs) — tarjetas, barras de severidad, 6 tablas con 963 filas
    y métricas correctas; sintaxis JS válida (`node --check`).
  - CLI real: `--dashboard` solo, con `-f md`, con `-f html -o` sin extensión
    (nombres `<output>-dashboard.html` correctos), output=directorio → error
    limpio + exit 1, flag visible en `--help`.
  - E2E real con repo grande: `--path /tmp/awslabs-cfn` (7.5M, 316 archivos
    IaC) → 963 IaC + 8 secretos + 3 deps con CVEs. Requirió checkov 2.5.20
    (3.3.8 se cuelga en repos grandes; el pin en el .venv de dev valida el fix
    pendiente del Dockerfile).
  - Bug encontrado y corregido: el total de `print_summary` (consola)
    excluía los secretos (966 vs 974 de HTML/dashboard). Fix: `len(report.secrets)`
    en el total + test nuevo. 190 tests en verde.

## Notas de cierre — Imagen Docker (checkov 2.5.20) ✅

- **Dockerfile**: `pip install checkov==2.5.20 semgrep click==8.1.8` (3.3.8 se
  cuelga en repos grandes: 10+ min sin output). Comentario en el Dockerfile
  documentando el motivo.
- **Imagen**: reconstruida (`vibeaudit:latest`, 1.22GB). Verificada dentro del
  contenedor: CLI OK, checkov 2.5.20, gitleaks 8.30.1, semgrep 1.170.1.
- **E2E en contenedor**:
  - Repo chico (s3-public + secrets): 8 hallazgos IaC en segundos, dashboard +
    reporte generados (antes: cuelgue con 3.3.8).
  - Repo grande (`/tmp/awslabs-cfn`, 316 archivos IaC): scan completo en ~35s
    (antes colgado 10 min sin output) → 967 hallazgos + dashboard.
- **Diferencia dev vs Docker (967 vs 963, +4 CKV_AWS_110)**: variación interna
  de checkov 2.5.20 (graph checks según plataforma: dev py3.9/macOS vs
  contenedor py3.12/linux). Los 4 hallazgos extra son reales (políticas IAM en
  `Solutions/CloudFormationEndpointSignals`) y se renderizan correctamente en
  el dashboard. Verificado: run directo de checkov idéntico en ambos entornos
  (40=40), la diferencia solo aparece en el scan vía pipeline.
- **Suite**: 190 tests en verde.

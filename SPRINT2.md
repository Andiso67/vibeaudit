# Sprint 2 — Cierre del ciclo de auditoría

> **ESTADO: PLANIFICADO** (pendiente de inicio).

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

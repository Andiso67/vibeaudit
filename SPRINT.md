# Sprint 1 — Pre-Auditoría Automatizada (Fundación)

## Objetivo del Sprint

Construir la base del **VibeAudit & Knowledge Engine**: una herramienta CLI que
clona un repositorio Git, ejecuta scanners de seguridad y genera un **JSON
maestro** estructurado con todos los hallazgos. Es el primer paso hacia el
servicio de "Pre-Auditoría Automatizada en 48 horas".

## Contexto (visión completa del producto)

El Vibe Coding (desarrollo guiado por IA) genera deuda técnica: aplicaciones que
funcionan localmente pero carecen de estructura, seguridad y gobernanza. La
herramienta completa tendrá 5 módulos:

1. **Ingesta**: conectores Git, lectura de IaC, escaneo de nube (AWS/Azure/GCP)
2. **SAST/DAST**: Semgrep, Checkov, Gitleaks, SonarQube
3. **Motor LLM**: agentes auditor que comparan contra checklists (12-Factor, AWS WAF, OWASP)
4. **Memoria**: vector DB (hallazgos recurrentes) + graph DB (dependencias)
5. **Generador de entregables**: JSON → diagramas C4, roadmaps, backlogs

## Alcance del Sprint 1

### Dentro de alcance

| Módulo | Entregable |
|---|---|
| 1 (parcial) | `RepoIngester`: clonado a temp dir, detección de lenguajes, frameworks, dependencias e IaC |
| 2 (parcial) | `GitleaksScanner` (secretos), `SemgrepScanner` (SAST, solo HIGH/CRITICAL), `CheckovScanner` (IaC) |
| 5 (parcial) | `AuditReport` (JSON maestro): `ProjectMetadata`, `Vulnerability`, `Secret`, `Metrics` |
| CLI | `python -m vibeaudit.cli scan --repo-url <url> --output <file>` con progreso Rich y manejo de errores |

### Fuera de alcance (sprints futuros)

- Motor de análisis LLM (módulo 3)
- Base de conocimiento vectorial/graph (módulo 4)
- Escaneo de nube vía APIs (requiere credenciales)
- Análisis de CI/CD (GitHub Actions, GitLab CI)
- Dashboard para cliente, generación de diagramas C4, backlog Jira/Linear
- Reglas custom de "Vibe Coding" (ej. `SELECT *`, `any` en TypeScript)

## Definition of Done

- [x] Estructura de directorios del proyecto
- [x] `models.py` con enums, validaciones y aliases camelCase
- [x] `RepoIngester` con cleanup del directorio temporal (context manager)
- [x] 3 scanners con `is_installed()`, parseo JSON y mapeo de severidad
- [x] `AuditReporter` con métricas (LOC, tests, severidades), `save_to_file()`, `print_summary()`
- [x] CLI `scan` funcional de punta a punta
- [x] Tests unitarios (pytest)
- [x] README con instrucciones de uso

## Criterios de Aceptación

- `python -m vibeaudit.cli scan --repo-url <url> --output report.json` genera el
  JSON maestro sin errores
- Repo inexistente → mensaje claro + exit code 1
- Scanner no instalado → mensaje con instrucciones de instalación
- Sin archivos IaC → Checkov devuelve lista vacía sin fallar
- El directorio temporal se elimina siempre (éxito o error)

## Notas de cierre (evidencia de verificación)

- **Tests**: 48/48 pasando (models, ingester, scanners, reporter).
- **E2E `docker/compose`** (local y contenedor): 148 hallazgos (18 SAST,
  130 IaC, 0 secretos), 56.672 LOC, 108 archivos de test.
- **E2E `awslabs/aws-cloudformation-templates`** (réplica local, GitHub online
  y contenedor Docker): 947 problemas IaC, 0 secretos, 0 SAST.
- **Metadatos**: `repositoryUrl`, `defaultBranch` y `commitHash` capturados y
  verificados (p.ej. `main` / `a0f43bc6d208`).
- **Imagen Docker `vibeaudit:latest`** construida (python:3.12-slim, arm64,
  gitleaks multi-arch) y probada de punta a punta.
- **Bug encontrado y resuelto**: checkov 3.3.x crashea con templates CFN que
  usan `Fn::Rain::Module` (`Type` como dict → `unhashable type: 'dict'`).
  Fix: exclusión vía `--skip-path` (`_find_unsupported_cfn_files()`).
- Commits: `2fe7395` (sprint 1), `7b2a6b6` (Docker), `4776d65` (fix checkov),
  `f8aec64` (metadatos del repo).

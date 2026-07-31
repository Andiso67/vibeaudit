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

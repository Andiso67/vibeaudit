# Contexto del Proyecto — VibeAudit & Knowledge Engine

## Resumen
Herramienta CLI de auditoría automática para repositorios Git, diseñada para
detectar la deuda técnica típica del **Vibe Coding** (desarrollo guiado por IA):
secrets hardcodeados, vulnerabilidades SAST y configuraciones de infraestructura
inseguras. Sprint 1 = "Pre-Auditoría Automatizada": clonar → escanear → JSON maestro.

## Visión del producto (5 módulos)
1. **Ingesta**: conectores Git (GitHub/GitLab), lectura de IaC (Terraform, Pulumi, CloudFormation), escaneo de nube (AWS/Azure/GCP, solo lectura), configs (Dockerfiles, CI/CD, K8s).
2. **SAST/DAST**: Semgrep, Checkov, Gitleaks (integrables: SonarQube, Terrascan).
3. **Motor LLM**: agentes auditor (código e infra) contra checklists (12-Factor, AWS Well-Architected, OWASP).
4. **Memoria**: vector DB (hallazgos y soluciones recurrentes) + graph DB (dependencias).
5. **Generador de entregables**: JSON → diagramas C4, roadmap de fases, backlog Jira/Linear.

## Flujo de datos (sprint 1)
```
cli.py scan --repo-url <url> --output <file>
  → RepoIngester.clone() (temp dir) → analyze() → ProjectMetadata
  → GitleaksScanner.scan()  → List[Secret]
  → SemgrepScanner.scan()   → List[Vulnerability] (solo HIGH/CRITICAL)
  → CheckovScanner.scan()   → List[Vulnerability] (solo si hay IaC)
  → AuditReporter.build() (cachea) → save_to_file() → print_summary()
  → __exit__ del RepoIngester: cleanup del temp dir
```

## Esquema del JSON maestro (aliases camelCase)
```json
{
  "project":   { "name", "languages", "frameworks", "iacFiles" },
  "vulnerabilities": [{ "rule", "file", "line", "severity", "snippet" }],
  "secrets":        [{ "type", "file", "line", "severity" }],
  "iacIssues":      [{ ... Vulnerability ... }],
  "metrics":   { "linesOfCode", "testFiles", "dependenciesWithCves", "vulnerabilitiesBySeverity" }
}
```

## Mapeo de severidades
| Herramienta | Exit codes | Mapeo a Severity |
|---|---|---|
| Gitleaks | 0 = sin hallazgos, 1 = hallazgos | reglas críticas (AWS/GitHub/Stripe/SSH) → CRITICAL, resto → HIGH |
| Semgrep | 0/1 válidos, 2 = error | ERROR → HIGH, WARNING → MEDIUM, INFO → LOW (filtro solo HIGH/CRITICAL) |
| Checkov | 0 siempre (incluso con hallazgos) | texto directo CRITICAL/HIGH/MEDIUM/LOW, default HIGH |

## Decisiones clave
- `AuditReport.model_dump_json(by_alias=True, indent=2)` para exportar.
- `populate_by_name=True` en todos los modelos con alias (Pydantic 2.5 ignora kwargs silenciosamente sin él).
- `RepoIngester` es context manager: `with RepoIngester(url) as ing` → clonar/analizar/escanear dentro, cleanup garantizado.
- `AuditReporter.build()` cachea el reporte porque el repo temporal se elimina antes de `save_to_file()`.
- Detección de IaC por contenido para K8s/CloudFormation (marcadores `kind: Deployment`, `AWSTemplateFormatVersion`).

## Roadmap (sprints futuros)
- [ ] Motor LLM: agentes auditor + checklists (12-Factor, OWASP, AWS WAF)
- [ ] Memoria: pgvector/Qdrant con post-mortems y soluciones aplicadas
- [ ] Escaneo de nube vía APIs (solo lectura) y análisis de CI/CD
- [ ] Dashboard de cliente (Next.js) con semáforo de riesgo
- [ ] Generador de entregables: diagramas C4, roadmap por fases, backlog CSV/JSON
- [ ] Reglas custom de "Vibe Coding" en Semgrep (`SELECT *`, `any` en TS, etc.)
- [ ] Poblar `dependenciesWithCves` (ej. vía OSV API)

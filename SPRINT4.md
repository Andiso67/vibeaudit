# Sprint 4 — Profundizar el análisis: nube → SonarQube, CI/CD, Vibe Coding y dependencias

> **ESTADO: COMPLETADO** — Ítems 1-4 implementados y verificados E2E contra el
> repo real `Andiso67/golf-tracker` (Next.js/TypeScript, AWS us-east-1).

## Objetivo del Sprint

Cerrar los huecos detectados en el Sprint 3 con un repo real:

1. Las **issues de nube** (security groups, buckets) no llegaban a SonarQube.
2. No existía un **CI/CD** que automatizara scan + import a SonarQube.
3. Las **reglas custom "Vibe Coding"** no tenían bundle incluido (había que
   pasar `--rules` manualmente).
4. Los **lockfiles pnpm** no se parseaban (golf-tracker usa pnpm → 0 CVEs).

## Ítems (backlog)

| # | Ítem | Módulo | Detalle |
|---|---|---|---|
| 1 | **Issues de nube en SonarQube** | 2 | `to_sonar_issues()` ahora importa `cloud_issues`: se anclan al primer archivo IaC del repo (`iac_files[0]`, p. ej. `Dockerfile`) como proxy de la infraestructura que gobierna el recurso. Sin archivo IaC → warning + se omite. Además las issues se **ordenan por severidad** (BLOCKER→INFO) antes del límite de 1000, para que las graves nunca se pierdan. |
| 2 | **CI/CD completo** | 5 | Workflow `.github/workflows/vibeaudit.yml`: build de la imagen Docker, `vibeaudit scan` (con `--cloud` si hay credenciales), artefactos `audit-report.json` + `sonar-issues.json`, e import a SonarQube vía `sonarsource/sonar-scanner-cli@v4` con secretos `SONAR_HOST_URL`/`SONAR_TOKEN` (paso con `if` para no romper el CI si no están configurados). |
| 3 | **Reglas custom Vibe Coding** | 3 | Bundle de **10 reglas semgrep** incluido en `vibeaudit/rules/` (vibe-sql, vibe-typescript, vibe-javascript, vibe-python). `--rules` ahora **default al bundle** si no se pasa. Reglas: `SELECT *`, `any`, `!` no-null, `@ts-ignore`, `console.log`, `debugger`, `eval()`, `except` desnudo, excepción tragada con `pass`, TODO/FIXME. |
| 4 | **Dependencias pnpm** | 1 | Parser de `pnpm-lock.yaml` (v6 `/name@version` y v9 `name@version`, con/sin comillas y scoped) + consulta OSV. golf-tracker pasó de 0 a **28 deps con CVEs**. |

### Aprendizajes (reglas semgrep)

- `pattern: | except $E: ...` (bloque `except` suelto) **falla el parseo** en
  semgrep 1.172; hay que anclarlo a `try: ... except: ...` completo.
- Un patrón de comentario `// @ts-ignore` matchea **cualquier comentario**
  (4037 falsos positivos en golf-tracker); usar `pattern-regex: "@ts-ignore"`.
- `regex:` no existe en semgrep ≥1.x; es `pattern-regex:`.
- Lenguajes `sql` y `typescriptreact` no son válidos; usar `generic` +
  `pattern-regex` para strings (SQL) y `typescript` para TS.
- `sonar-issues.json` con >1000 issues truncaba antes de llegar a las de nube;
  el orden por severidad resuelve la pérdida.

## Definition of Done

- [x] Ítems 1-4 implementados con tests unitarios (monkeypatch, sin red)
- [x] Suite en verde: **284 passed**
- [x] E2E golf-tracker: scan con nube real (AWS `us-east-1`, solo lectura) →
      93 hallazgos (2 SAST, 2 IaC, 50 custom, 10 LLM, 28 deps, 1 nube)
- [x] SonarQube: **import de 55 issues en 9 archivos** (incl. la issue de nube
      `cloud-aws-ec2-security-group-open` → Dockerfile, CRITICAL); 341 issues totales
- [x] Dashboard actualizado (header de proyecto + "Recursos de nube analizados")

## Comandos útiles

```bash
# Scan completo con bundle de reglas incluido y nube
vibeaudit scan --path /tmp/golf-tracker --llm --cloud \
  --sonar-json sonar-issues.json --deliverables deliverables/

# Import a SonarQube (requiere token en /tmp/sonar-token.txt)
sonar-scanner -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login="$(cat /tmp/sonar-token.txt)" \
  -Dsonar.projectKey=golf-tracker -Dsonar.sources=. \
  -Dsonar.externalIssuesReportPaths=sonar-issues.json
```

# VibeAudit - OpenCode Rules

## Proyecto
Auditoría automatizada de repositorios Git ("Vibe Coding Audit"). CLI Python
que clona un repo, ejecuta Gitleaks (secretos), Semgrep (SAST) y Checkov (IaC),
y genera un JSON maestro (`AuditReport`). Ver `SPRINT.md` para el alcance.

## Entorno
- Python 3.9, venv en `.venv/`
- Dependencias fijadas en `requirements.txt` (pinned). Instalar con `.venv/bin/pip install -r requirements.txt`
- Tests: `.venv/bin/python -m pytest` (pytest en requirements.txt)
- No hay formatter/linter configurado todavía. Mantener el estilo del código existente.

## Arquitectura (flujo de datos)
```
CLI (cli.py) → RepoIngester (clone a temp dir)
             → GitleaksScanner / SemgrepScanner / CheckovScanner (repo_path)
             → AuditReporter (build + save_to_file + print_summary)
             → cleanup del temp dir vía context manager (with RepoIngester(...))
```

- `ingester.py`: clona con GitPython (`depth=1`) o carga un directorio local
  (`RepoIngester(repo_url=... | local_path=...)`, exactamente uno — validado en
  `__init__`), analiza, es context manager. `clone()` traduce errores de git a
  `ValueError`/`PermissionError`; en modo local valida existencia/directorio.
  La limpieza ocurre en `__exit__` o en `finally` de `ingest()` (el modo local
  nunca borra el directorio del usuario).
- `scanners/`: cada scanner tiene `is_installed()` estático, `scan()` y
  `_parse_output()`. Nunca fallan por "0 hallazgos" (exit codes 0/1 válidos).
  Levantan `RuntimeError` si la herramienta no está instalada o falla.
  `CICDScanner` es la excepción: parser propio de `.github/workflows/*.yml` y
  `.gitlab-ci.yml` (sin herramienta externa), `is_installed()` siempre True.
  `CustomRulesScanner` es semgrep con `--config <dir>` en vez de `auto` y NO
  filtra por severidad (las reglas custom suelen ser WARNING/INFO).
- `reporter.py`: `build()` cachea el reporte (el repo temporal se borra antes
  de `save_to_file()`). Usar `by_alias=True` al serializar.
- `cli.py`: Typer. El `@app.callback()` vacío es OBLIGATORIO: con un solo
  comando, Typer 0.9 lo convierte en comando directo y `scan` deja de existir.

## Gotchas conocidos (leer antes de tocar)
1. **Pydantic v2.5 ignora silenciosamente kwargs** si el campo tiene `alias` y el
   modelo no tiene `populate_by_name = True`. Todos los modelos con alias deben
   tenerlo (`ProjectMetadata`, `Metrics`, `AuditReport`, `DependencyVulnerability`).
2. **Aliases camelCase**: `iacFiles`, `linesOfCode`, `testFiles`,
   `dependenciesWithCves`, `vulnerabilitiesBySeverity`, `iacIssues`,
   `cicdIssues`, `customIssues`,
   `repositoryUrl`, `defaultBranch`, `commitHash`, `cveIds`, `cvssScore`,
   `fixedVersion`, `isFixAvailable`, `dependencyType`, `cweIds`,
   `affectedRange`, `epssScore`, `exploitedInWild`.
   Serializar SIEMPRE con `model_dump_json(by_alias=True)`.
3. **Rich 13.7.0**: `TaskProgressColumn(visible=...)` NO existe (da TypeError).
4. **Typer 0.9**: ver gotcha del callback arriba.
5. **Checkov**: exit code 0 = sin hallazgos, 1 = hallazgos/warnings (ambos
   válidos), 2 = error real. JSON 3.x = lista de check_types con
   `results.failed_checks`. Severidad por defecto HIGH si no viene.
   **Crashea con `unhashable type: 'dict'`** si un template CloudFormation
   tiene `Type` no-string (p.ej. `Fn::Rain::Module`): el scanner los detecta
   con `_find_unsupported_cfn_files()` y los excluye vía `--skip-path`.
6. **Semgrep**: exit 2 = error real; 0/1 válidos. Solo se reportan HIGH/CRITICAL
   (ERROR se mapea a HIGH).
7. **Gitleaks**: exit 1 = hay hallazgos (NO es error). Reglas críticas
   (AWS/GitHub/Stripe/SSH...) → CRITICAL, resto → HIGH.
   **Escanea commits, no el filesystem**: sin `.git` da "0 commits scanned"
   (falso negativo silencioso) → añadir `--no-git` al comando cuando no existe
   `.git` en el repo_path. OJO: `.git` presente pero SIN commits (git init sin
   commit, o `.git` roto) también escanea 0 bytes → decidir con
   `git rev-parse --verify HEAD` (`_has_git_history()`), no solo con la
   existencia de `.git`. Con `--no-git` reporta rutas absolutas → relativizar
   al repo_path en `_parse_output` (fuera del repo, conservar).
8. **OSV API**: `POST /v1/querybatch` devuelve SOLO `id` + `modified` por vuln;
   el detalle completo se trae con `GET /v1/vulns/{id}` por cada ID (deps.py
   hace batch de IDs → detalle por ID). El score CVSS viene como vector
   `CVSS:3.1/AV:...` (parseado por `_parse_cvss_vector`) o numérico.
   Hay advisories duplicados por CVE entre fuentes (GHSA vs NVD): se deduplican
   en `_dedupe_vulnerabilities` conservando el más severo.
9. **CICDScanner (parser propio de YAML)**: los bloques `run:` (GitHub) y
   `script:`/`before_script:`/`after_script:` (GitLab) se aíslan POR
   INDENTACIÓN (`indent <=` línea clave → fin de bloque). Nunca usar
   `".git" in root` en walks (matchea `.github`). En el bloque `on:` ignorar
   líneas comentadas y vacías (un blank cortaba la búsqueda). Limpiar BOM
   UTF-8 al leer (`lstrip("\ufeff")`). Validar con workflows reales, no solo
   casos inventados (cada verificación con reales encontró bugs).
10. **CustomRulesScanner**: semgrep antepone el path del directorio como
    namespace al `check_id` (con `/` → `.`) → limpiarlo en `_parse_output`
    para que el rule sea `custom.<id>`. NO filtra por severidad (reglas de
    estilo son WARNING/INFO). La validación del flag `--rules` debe ir DENTRO
    del `try` del CLI (si no, traceback en vez de error limpio).

## Convenciones
- Docstrings en español en todas las clases/métodos públicos.
- Sin comentarios inline salvo que se pidan.
- Enums: `Severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO) de `models.py`.
- Validaciones Pydantic: `line > 0`, nombres no vacíos, conteos `>= 0`.
- Mensajes de consola con Rich (no `print`).

## Testing
- pytest + monkeypatch de `subprocess.run` (no ejecutar herramientas reales en tests).
- `FakeResult(returncode, stdout, stderr)` imita el resultado de subprocess.
- El test de ingester crea un repo git real en `tmp_path` (git init + commit).
- Repos de prueba: `docker/compose` (Go), usar `git init` local para el resto.

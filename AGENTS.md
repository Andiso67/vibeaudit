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

- `ingester.py`: clona con GitPython (`depth=1`), analiza, es context manager.
  `clone()` traduce errores de git a `ValueError`/`PermissionError`. La limpieza
  ocurre en `__exit__` o en `finally` de `ingest()`.
- `scanners/`: cada scanner tiene `is_installed()` estático, `scan()` y
  `_parse_output()`. Nunca fallan por "0 hallazgos" (exit codes 0/1 válidos).
  Levantan `RuntimeError` si la herramienta no está instalada o falla.
- `reporter.py`: `build()` cachea el reporte (el repo temporal se borra antes
  de `save_to_file()`). Usar `by_alias=True` al serializar.
- `cli.py`: Typer. El `@app.callback()` vacío es OBLIGATORIO: con un solo
  comando, Typer 0.9 lo convierte en comando directo y `scan` deja de existir.

## Gotchas conocidos (leer antes de tocar)
1. **Pydantic v2.5 ignora silenciosamente kwargs** si el campo tiene `alias` y el
   modelo no tiene `populate_by_name = True`. Todos los modelos con alias deben
   tenerlo (`ProjectMetadata`, `Metrics`, `AuditReport`).
2. **Aliases camelCase**: `iacFiles`, `linesOfCode`, `testFiles`,
   `dependenciesWithCves`, `vulnerabilitiesBySeverity`, `iacIssues`,
   `repositoryUrl`, `defaultBranch`, `commitHash`.
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

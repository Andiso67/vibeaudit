# Sprint 5 — Memoria, evolución y comparativa

Objetivo: darle a `vibeaudit` una dimensión temporal: que recuerde hallazgos
previos (con una tienda vectorial real), que muestre cómo evoluciona el
proyecto entre escaneos, que alerte de problemas que nunca se arreglan, que
compare el valor del auditor LLM contra SonarQube y que escanee la nube en
todas las regiones.

## Ítem 1 — Memoria vectorial real (Qdrant)

`vibeaudit/memory.py` ahora expone una tienda vectorial real:

- **`QdrantMemoryStore`**: colección `vibeaudit_memory` con vectores de 256
  dimensiones y similitud de coseno. El cliente de `qdrant-client` se importa
  de forma perezosa y el flag `_fake` permite probar sin servidor.
- **`new_store(memory, embedder, client)`**: factory que decide el backend por
  el valor de `--memory`:
  - `http://host:port` → Qdrant (semántica real con embeddings locales).
  - un directorio → `MemoryStore` local (`memory.json`).
- El CLI acepta URLs de Qdrant en `--memory` y en `memory add/list`.

La capa de dedupe (`remember`, `ingest_report`, fix sugerido) es idéntica para
ambos backends; solo cambia el almacenamiento.

## Ítem 2 — Historial multi-scan y evolución en el dashboard

Nuevo módulo `vibeaudit/history.py` con `HistoryStore`:

- Guarda un **snapshot** por scan en `<dir>/snapshots/<id>.json` + `index.json`
  (commit, timestamp, resumen por módulo/severidad y reporte completo).
- `--history <dir>` en `scan` guarda el snapshot automáticamente.
- `delta(prev, curr)` clasifica cada hallazgo como **nuevo / resuelto /
  persistente** usando una clave estable (regla, archivo, CVE, título).
- `history list` y `history export` generan `audit-history.json` para el
  dashboard (sección **Evolución (historial)**: tabla de snapshots + lista de
  deltas entre escaneos).

Nuevo flujo de referencia:

```bash
vibeaudit scan --path REPO --history ./hist --memory ./mem --cloud \
  --sonar-json sonar-issues.json --output audit-report.json
vibeaudit history export ./hist --memory ./mem \
  --output dashboard/public/audit-history.json
```

## Ítem 3 — Alertas de recurrencia

`HistoryStore.recurrence_alerts()` combina dos señales:

1. **Persistencia entre escaneos**: cuántos snapshots contienen la misma clase
   de hallazgo (se repite pero nunca se arregla).
2. **Ocurrencias en memoria**: cuántas veces se ha visto en total
   (`occurrences` del `MemoryStore`/Qdrant).

Devuelve un ranking con `score = snapshots × 10 + ocurrencias`, nivel
`ALERTA` (ambas señales superan el umbral) o `ATENCION`, y la recomendación
guardada. El dashboard muestra la tabla de **Alertas de recurrencia** y el CLI
`history alerts --memory DIR` la imprime:

```bash
vibeaudit history alerts ./hist --memory ./mem --top 10
```

## Ítem 4 — Comparativa LLM vs SonarQube

`vibeaudit/compare.py` cruza los hallazgos del auditor LLM contra las issues
de SonarQube por archivo relativo (`relatedFiles` vs `primaryLocation.filePath`):

- **coincide con SonarQube**: el problema ya lo detecta el análisis estático.
- **único del LLM**: lo ve el LLM pero no el SAST (valor incremental).
- **sonar-only**: issues estáticos en archivos que el LLM no citó.

Añade además los hallazgos LLM al import de SonarQube (reglas
`external_vibeaudit:llm-*`, ancladas al primer archivo citado, o al primer
archivo IaC si no citan ninguno) para que la organización los pueda rastrear
en la misma herramienta.

```bash
vibeaudit compare audit-report.json sonar-issues.json [--output comparativa.json]
```

## Ítem 5 — Multi-región en la nube

`CloudScanner.scan_aws` ahora escanea por región:

1. Lista regiones con `ec2.describe_regions()` (solo lectura).
2. Por cada región consulta los security groups y etiqueta cada recurso e
   issue con su `region`.
3. Si `describe_regions` no está permitido (p. ej. IAM sin ese permiso), avisa
   y escanea solo la región de `AWS_DEFAULT_REGION` (default `us-east-1`), sin
   fallar.

> Para un escaneo multi-región completo, el rol IAM de solo lectura debe
> incluir también `ec2:DescribeRegions`.

## Resultados E2E (golf-tracker)

| Señal | Antes | Ahora |
| --- | --- | --- |
| Snapshots de historial | — | 3 (2 commits, 2 deltas) |
| Delta e0fb9cf → 762de69 | — | 28 nuevos / 0 resueltos / 42 persistentes |
| Alertas de recurrencia | — | 10 (top: `vibe-js-console-log`, ALERTA score 165) |
| Issues externas en SonarQube | 55 | 67 (vulnerabilidades totales) |
| Recursos de nube con región | 0 | 5 (4 con región us-east-1) |
| Suite de tests | 292 | 303 passed |
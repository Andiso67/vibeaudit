# Sprint 7 — Consola web de análisis (frontend contra Postgres)

Objetivo: el dashboard deja de ser solo un visor de resultados y pasa a ser
la consola de VibeAudit: pedir análisis de cualquier repo, seguirlos en vivo
y consultar todos los históricos guardados en Postgres (endpoints y esquema
del Sprint 6).

## Ítem 1 — API lista para el frontend

- **CORS** en la API (`VIBEAUDIT_CORS_ORIGINS`, default localhost:3000 y
  `andiso67lab.tail809b38.ts.net:3000`) para que el navegador del dashboard
  pueda llamar a `:8000` desde cualquier dispositivo.
- **`GET /api/analyses`**: `total` real (COUNT con los mismos filtros) y
  paginación estable con `limit`/`offset`; filtros por repo, estado y rango
  de fechas.
- **`GET /api/analyses/{id}`**: devuelve summary + reporte JSONB para la
  vista detalle (ya existe; se mantiene y se testea).
- Tests en `tests/test_db.py` para el shape de la respuesta y el paso de
  filtros.

## Ítem 2 — Formulario "Nuevo análisis"

- Sección/formulario en el dashboard que llama a `POST /api/scan` con: repo
  (URL git o ruta local), rama, profundidad, etiqueta, toggles LLM/nube y
  opciones avanzadas (entregables, SonarQube).
- Polling de `GET /api/scan/{id}` con progreso (paso actual del pipeline) y
  estado final; al terminar muestra un resumen de hallazgos y enlace al
  detalle.

## Ítem 3 — Listado de análisis con filtros

- Tabla: repo, rama, commit, fecha, duración, estado y contadores por
  severidad (desde el `summary` JSONB).
- Filtros: repo con autocompletado (`GET /api/repos`), estado, rango de
  fechas y paginación.
- Acciones por fila: ver detalle, re-escanear el mismo repo y descargar el
  reporte JSON.

## Ítem 4 — Vista de detalle de análisis

- Cabecera con metadatos (repo, commit, fechas, duración, estado).
- Resumen de hallazgos por módulo y severidad.
- Enlaces a los artefactos guardados (informe maestro/entregables si se
  generaron) y al reporte JSON completo.

## Ítem 5 — E2E y cierre

- Probar todo en el compose de dev: alta → progreso → listado → detalle →
  persistencia tras reinicio.
- `NEXT_PUBLIC_API_URL` apuntando a Tailscale para probar desde otro
  dispositivo.
- Build de producción del dashboard sin errores, suite pytest completa verde
  y commit final.

"""Persistencia de análisis en PostgreSQL (opcional).

La API funciona sin base de datos: solo se persiste si existe
``VIBEAUDIT_DATABASE_URL``. El esquema almacena metadatos del análisis,
un resumen (contadores) y el ``AuditReport`` completo en JSONB.

Tabla principal:
- analyses: id (job_id), repo, branch, commit_hash, status, fechas,
  duración, versiones de herramientas, summary JSONB, report JSONB,
  artifacts_dir y error.
"""

import json
import os
from typing import Any, Dict, List, Optional, Tuple

# psycopg es opcional: solo se importa si hay DATABASE_URL configurada.
_psycopg = None


def _import_psycopg():
    """Importa psycopg 3 solo cuando se usa (fallback limpio si no está)."""
    global _psycopg
    if _psycopg is None:
        import psycopg

        _psycopg = psycopg
    return _psycopg


def database_url() -> Optional[str]:
    """URL de conexión a Postgres (None si la persistencia está desactivada)."""
    return os.environ.get("VIBEAUDIT_DATABASE_URL")


def enabled() -> bool:
    """True si la persistencia en Postgres está configurada."""
    return bool(database_url())


def artifacts_dir() -> "os.PathLike[str]":
    """Directorio donde se guardan los artefactos de cada análisis."""
    return os.environ.get("VIBEAUDIT_ARTIFACTS", "./artifacts")


def connect():
    """Conexión a Postgres con timeout corto (solo lectura/escritura simple)."""
    psycopg = _import_psycopg()
    return psycopg.connect(database_url(), connect_timeout=5)


def init_db() -> None:
    """Crea el esquema (idempotente). Se ejecuta al arrancar la API si hay BD."""
    if not enabled():
        return
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id            TEXT PRIMARY KEY,
                    name          TEXT,
                    repo          TEXT NOT NULL,
                    branch        TEXT,
                    commit_hash   TEXT,
                    status        TEXT NOT NULL,
                    started_at    TIMESTAMPTZ,
                    finished_at   TIMESTAMPTZ,
                    duration_seconds REAL,
                    tool_versions JSONB,
                    summary       JSONB,
                    report        JSONB,
                    artifacts_dir TEXT,
                    request       JSONB,
                    error         TEXT
                )
                """
            )
            cur.execute(
                "ALTER TABLE analyses ADD COLUMN IF NOT EXISTS name TEXT"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_analyses_repo ON analyses (repo)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses (status)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_analyses_started ON analyses (started_at)"
            )


def save_analysis(analysis: Dict[str, Any]) -> None:
    """Inserta (o actualiza) un análisis completo."""
    if not enabled():
        return
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO analyses (
                    id, name, repo, branch, commit_hash, status, started_at,
                    finished_at, duration_seconds, tool_versions, summary,
                    report, artifacts_dir, request, error
                ) VALUES (
                    %(id)s, %(name)s, %(repo)s, %(branch)s, %(commit_hash)s,
                    %(status)s, %(started_at)s, %(finished_at)s,
                    %(duration_seconds)s, %(tool_versions)s, %(summary)s,
                    %(report)s, %(artifacts_dir)s, %(request)s, %(error)s
                )
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    repo = EXCLUDED.repo,
                    branch = EXCLUDED.branch,
                    commit_hash = EXCLUDED.commit_hash,
                    status = EXCLUDED.status,
                    started_at = EXCLUDED.started_at,
                    finished_at = EXCLUDED.finished_at,
                    duration_seconds = EXCLUDED.duration_seconds,
                    tool_versions = EXCLUDED.tool_versions,
                    summary = EXCLUDED.summary,
                    report = EXCLUDED.report,
                    artifacts_dir = EXCLUDED.artifacts_dir,
                    request = EXCLUDED.request,
                    error = EXCLUDED.error
                """,
                _pg_json(analysis),
            )


def update_status(
    job_id: str,
    status: str,
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
    error: Optional[str] = None,
    repo: Optional[str] = None,
    name: Optional[str] = None,
) -> None:
    """Actualiza el estado de un análisis en curso/fallido."""
    if not enabled():
        return
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO analyses (id, name, repo, status, started_at, finished_at, error)
                VALUES (%(id)s, %(name)s, %(repo)s, %(status)s, %(started_at)s, %(finished_at)s, %(error)s)
                ON CONFLICT (id) DO UPDATE SET
                    name = COALESCE(EXCLUDED.name, analyses.name),
                    repo = COALESCE(EXCLUDED.repo, analyses.repo),
                    status = EXCLUDED.status,
                    started_at = COALESCE(EXCLUDED.started_at, analyses.started_at),
                    finished_at = EXCLUDED.finished_at,
                    error = EXCLUDED.error
                """,
                {
                    "id": job_id,
                    "name": name,
                    "repo": repo or "",
                    "status": status,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "error": error,
                },
            )


def active_analysis_id(repo: str) -> Optional[str]:
    """Devuelve el id de un análisis en curso (queued/running) de un repo, o None."""
    if not enabled() or not repo:
        return None
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM analyses
                WHERE status IN ('queued', 'running') AND repo = %(repo)s
                LIMIT 1
                """,
                {"repo": repo},
            )
            row = cur.fetchone()
    return row[0] if row else None


def abort_stale_running() -> int:
    """Marca como error los análisis 'running' (jobs huérfanos tras un reinicio).

    Devuelve cuántos se marcaron.
    """
    if not enabled():
        return 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE analyses
                SET status = 'error',
                    error = 'Interrumpido por reinicio del servicio (job huérfano)',
                    finished_at = COALESCE(finished_at, now())
                WHERE status = 'running'
                """
            )
            return cur.rowcount


def list_analyses(
    repo: Optional[str] = None,
    status: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Lista los análisis sin el reporte completo.

    Devuelve ``{"total": int, "items": [...]}``; ``total`` es el recuento real
    con los mismos filtros (para paginar bien en el frontend).
    """
    if not enabled():
        return {"total": 0, "items": []}
    where, params = [], {}
    if repo:
        where.append("repo ILIKE %(repo)s")
        params["repo"] = f"%{repo}%"
    if status:
        where.append("status = %(status)s")
        params["status"] = status
    if since:
        where.append("started_at >= %(since)s")
        params["since"] = since
    if until:
        where.append("started_at <= %(until)s")
        params["until"] = until
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    params.update({"limit": limit, "offset": offset})
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT COUNT(*) FROM analyses {clause}",
                {k: v for k, v in params.items() if k not in ("limit", "offset")},
            )
            total = cur.fetchone()[0]
            cur.execute(
                f"""
                SELECT id, name, repo, branch, commit_hash, status, started_at,
                       finished_at, duration_seconds, tool_versions, summary,
                       artifacts_dir, request, error,
                       (report IS NOT NULL) AS has_report
                FROM analyses
                {clause}
                ORDER BY started_at DESC
                LIMIT %(limit)s OFFSET %(offset)s
                """,
                params,
            )
            rows = cur.fetchall()
            columns = [d.name for d in cur.description]
    return {
        "total": total,
        "items": [dict(zip(columns, row)) for row in rows],
    }


def get_analysis(analysis_id: str) -> Optional[Dict[str, Any]]:
    """Devuelve un análisis completo (incluye report JSONB), o None."""
    if not enabled():
        return None
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, repo, branch, commit_hash, status, started_at,
                       finished_at, duration_seconds, tool_versions, summary,
                       report, artifacts_dir, request, error
                FROM analyses
                WHERE id = %(id)s
                """,
                {"id": analysis_id},
            )
            row = cur.fetchone()
            if row is None:
                return None
            columns = [d.name for d in cur.description]
    return dict(zip(columns, row))


def delete_analyses(ids: List[str]) -> Tuple[int, List[str]]:
    """Borra los análisis indicados.

    Devuelve ``(borrados, artifacts_dir)``: cuántas filas se borraron y los
    directorios de artefactos de esas filas, para que el llamador los elimine
    (la BD y el sistema de ficheros se mantienen consistentes).
    """
    if not enabled() or not ids:
        return 0, []
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT artifacts_dir FROM analyses WHERE id = ANY(%s)",
                (list(ids),),
            )
            dirs = [row[0] for row in cur.fetchall() if row[0]]
            cur.execute(
                "DELETE FROM analyses WHERE id = ANY(%s)",
                (list(ids),),
            )
            deleted = cur.rowcount
    return deleted, dirs


def list_repos() -> List[str]:
    """Repos con análisis guardados, para el autocompletado del frontend."""
    if not enabled():
        return []
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT repo FROM analyses WHERE repo <> '' ORDER BY repo"
            )
            return [row[0] for row in cur.fetchall()]


def _pg_json(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convierte a JSONB las claves que Postgres necesita como JSON (json.dumps)."""
    out = dict(data)
    for key in ("tool_versions", "summary", "report", "request"):
        if out.get(key) is not None and not isinstance(out[key], str):
            out[key] = json.dumps(out[key], default=str)
    return out


# Listas de hallazgos por tipo en el reporte serializado (by_alias=True)
FINDING_LISTS: Dict[str, str] = {
    "secrets": "secrets",
    "sast": "vulnerabilities",
    "iac": "iacIssues",
    "cicd": "cicdIssues",
    "custom": "customIssues",
    "cloud": "cloudIssues",
    "llm": "llmFindings",
}


def build_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    """Contadores del reporte (by_alias) para el listado del frontend.

    Devuelve hallazgos por tipo y por severidad (y totales de dependencias).
    """
    by_type: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    total = 0
    for tool, key in FINDING_LISTS.items():
        items = report.get(key) or []
        by_type[tool] = len(items)
        total += len(items)
        for item in items:
            sev = (item.get("severity") or "INFO").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1

    metrics = report.get("metrics") or {}
    deps = metrics.get("dependenciesWithCves") or []
    by_type["deps"] = len(deps)
    total += len(deps)
    sev_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    return {
        "total": total,
        "by_type": by_type,
        "by_severity": {
            sev: by_severity.get(sev, 0)
            for sev in sev_order
            if by_severity.get(sev, 0)
        },
        "dependencies_total": (metrics.get("dependencies") or 0),
    }


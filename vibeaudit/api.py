"""Servicio HTTP (FastAPI) que expone el pipeline de vibeaudit.

Endpoints:
- GET  /api/health          estado del servicio
- POST /api/scan            lanza un scan en segundo plano (devuelve job_id)
- GET  /api/scan/{id}       estado/progreso y reporte del scan
- GET  /api/analyses        lista los análisis guardados (filtros + paginado)
- DELETE /api/analyses      borra varios análisis (cuerpo {"ids": [...]})
- GET  /api/analyses/{id}   análisis completo con su reporte
- DELETE /api/analyses/{id} borra un análisis y sus artefactos
- GET  /api/repos           repos con análisis guardados (autocompletado)
- GET  /api/history         lista los snapshots del historial configurado

Persistencia opcional: si existe ``VIBEAUDIT_DATABASE_URL`` los análisis se
guardan en Postgres (metadatos + JSONB) y los artefactos en
``VIBEAUDIT_ARTIFACTS`` (default ./artifacts). Sin la URL, todo queda en
memoria (dev local).
"""

import datetime as _dt
import json
import os
import shutil
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from vibeaudit import db as db_store
from vibeaudit.cli import ScanConfig, run_scan
from vibeaudit.history import HistoryStore

app = FastAPI(
    title="VibeAudit API",
    description="Servicio de auditoría de seguridad para repositorios Git",
    version="0.2.0",
)

# Orígenes permitidos para el dashboard (CORS). Configurable con
# VIBEAUDIT_CORS_ORIGINS (separados por comas).
_default_cors = (
    "http://localhost:3000,"
    "http://andiso67lab.tail809b38.ts.net:3000,"
    "http://andiso67lab.tail809b38.ts.net:8000"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.environ.get("VIBEAUDIT_CORS_ORIGINS", _default_cors).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


class ScanRequest(BaseModel):
    """Parámetros del scan.

    El repositorio se indica de una de estas formas (exactamente una):
    - ``repo``: valor único auto-detectado. Si parece una URL git
      (http/https/ssh/git/git@) se clona; en caso contrario se trata como
      directorio local o remoto con los ficheros (accesible por la API).
    - ``repo_url``: URL git explícita.
    - ``local_path``: directorio explícito (local o remoto montado).
    """

    repo: Optional[str] = Field(
        None,
        description="Repositorio: URL git o directorio local/remoto con los ficheros (auto-detecta)",
    )
    name: Optional[str] = Field(
        None,
        max_length=200,
        description="Nombre identificativo del análisis (opcional)",
    )
    repo_url: Optional[str] = Field(
        None, description="URL del repositorio Git a auditar"
    )
    local_path: Optional[str] = Field(
        None, description="Directorio local a auditar sin clonar"
    )
    token: Optional[str] = Field(
        None, description="Token de acceso para clonar repositorios privados"
    )
    branch: Optional[str] = Field(None, description="Rama a auditar")
    depth: int = Field(1, description="Profundidad del clone", ge=1)
    llm: bool = Field(False, description="Auditoría LLM por checklists")
    cloud: bool = Field(False, description="Escanea la nube del proveedor (solo lectura)")
    memory: Optional[str] = Field(
        None, description="Memoria de recurrentes: directorio local o URL Qdrant"
    )
    history: Optional[str] = Field(
        None, description="Directorio del historial (snapshots por scan)"
    )
    deliverables: Optional[str] = Field(
        None, description="Directorio donde generar entregables de cliente"
    )
    sonar_json: Optional[str] = Field(
        None, description="Exporta issues a sonar-issues.json"
    )
    output: Optional[str] = Field(
        None, description="Ruta del reporte JSON generado"
    )
    label: Optional[str] = Field(
        None, description="Etiqueta opcional para identificar el análisis"
    )


def _history_dir(req_history: Optional[str]) -> Optional[Path]:
    if req_history:
        return Path(req_history)
    env = os.environ.get("VIBEAUDIT_HISTORY")
    return Path(env) if env else None


def _persist_artifacts(job_id: str, report_dict: Dict[str, Any], config: ScanConfig) -> Path:
    """Guarda el reporte (y los entregables generados, si existen) en disco.

    Devuelve el directorio de artefactos del análisis.
    """
    base = Path(db_store.artifacts_dir()) / job_id
    base.mkdir(parents=True, exist_ok=True)
    (base / "audit-report.json").write_text(
        json.dumps(report_dict, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    if config.deliverables and config.deliverables.exists():
        for src in config.deliverables.iterdir():
            dest = base / "deliverables" / src.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dest)
    return base


def _run_job(job_id: str, req: ScanRequest) -> None:
    def log(msg: str) -> None:
        with JOBS_LOCK:
            JOBS[job_id]["step"] = msg

    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["step"] = "Iniciando..."
    started = _dt.datetime.now(_dt.timezone.utc)
    repo = req.repo_url or req.local_path or "local"
    if db_store.enabled():
        db_store.update_status(
            job_id,
            status="running",
            started_at=started.isoformat(),
            repo=repo,
            name=req.name,
        )
    try:
        if (req.repo_url is None) == (req.local_path is None):
            raise ValueError("Indica repo_url o local_path (exactamente uno)")
        output = Path(req.output) if req.output else Path(f"audit-report-{job_id}.json")
        config = ScanConfig(
            repo_url=req.repo_url,
            local_path=Path(req.local_path) if req.local_path else None,
            token=req.token,
            branch=req.branch,
            depth=req.depth,
            llm=req.llm,
            cloud=req.cloud,
            memory=req.memory,
            history=Path(req.history) if req.history else None,
            deliverables=Path(req.deliverables) if req.deliverables else None,
            sonar_json=Path(req.sonar_json) if req.sonar_json else None,
            output=output,
        )
        report, _ = run_scan(config, log=log, echo=lambda msg: None)
        report_dict = report.model_dump(by_alias=True, exclude_none=True)
        artifacts = _persist_artifacts(job_id, report_dict, config)
        finished = _dt.datetime.now(_dt.timezone.utc)
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["step"] = "Finalizado"
            JOBS[job_id]["output"] = str(output)
            JOBS[job_id]["report"] = report_dict
            JOBS[job_id]["artifacts_dir"] = str(artifacts)
        if db_store.enabled():
            project = report_dict.get("project") or {}
            db_store.save_analysis(
                {
                    "id": job_id,
                    "name": req.name,
                    "repo": repo,
                    "branch": req.branch,
                    "commit_hash": project.get("commitHash"),
                    "status": "done",
                    "started_at": started.isoformat(),
                    "finished_at": finished.isoformat(),
                    "duration_seconds": round(
                        (finished - started).total_seconds(), 2
                    ),
                    "tool_versions": report_dict.get("toolVersions"),
                    "summary": db_store.build_summary(report_dict),
                    "report": report_dict,
                    "artifacts_dir": str(artifacts),
                    "request": {
                        "name": req.name,
                        "repo_url": req.repo_url,
                        "local_path": req.local_path,
                        "branch": req.branch,
                        "depth": req.depth,
                        "llm": req.llm,
                        "cloud": req.cloud,
                        "label": req.label,
                    },
                    "error": None,
                }
            )
    except Exception as exc:  # noqa: BLE001 - el error queda en el job
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["step"] = str(exc)
            JOBS[job_id]["error"] = str(exc)
        if db_store.enabled():
            db_store.update_status(
                job_id,
                status="error",
                finished_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
                error=str(exc),
                name=req.name,
            )


@app.on_event("startup")
def _startup() -> None:
    """Crea el esquema de Postgres y aborta jobs huérfanos (reinicios)."""
    db_store.init_db()
    aborted = db_store.abort_stale_running()
    if aborted:
        print(f"VibeAudit API: {aborted} análisis 'running' marcados como "
              f"interrumpidos por reinicio.")


@app.get("/api/health")
def health() -> Dict[str, str]:
    """Estado del servicio."""
    return {"status": "ok", "service": "vibeaudit-api", "version": "0.1.0"}


def _repo_destino(repo: str) -> Tuple[Optional[str], Optional[str]]:
    """Clasifica un valor ``repo``: URL git (se clona) o directorio con ficheros.

    Devuelve ``(repo_url, local_path)``; ``local_path`` cubre también
    directorios remotos montados (NFS, SMB, SSHFS, volúmenes…).
    """
    if repo.startswith(("http://", "https://", "ssh://", "git://", "git@")):
        return repo, None
    return None, repo


@app.post("/api/scan", status_code=202)
def create_scan(req: ScanRequest) -> Dict[str, str]:
    """Lanza un scan en segundo plano; devuelve el job_id para consultar."""
    repo_url, local_path = req.repo_url, req.local_path
    if req.repo is not None:
        if repo_url is not None or local_path is not None:
            raise HTTPException(
                status_code=422,
                detail="Indica repo (auto-detectado) o repo_url/local_path, no ambos",
            )
        repo_url, local_path = _repo_destino(req.repo)
    if (repo_url is None) == (local_path is None):
        raise HTTPException(
            status_code=422,
            detail="Indica repo, repo_url o local_path (exactamente uno de los dos)",
        )
    repo = repo_url or local_path
    with JOBS_LOCK:
        for job_id, job in JOBS.items():
            if (
                job.get("status") in ("queued", "running")
                and job.get("repo") == repo
            ):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Ya hay un análisis en curso para este repositorio "
                        f"(job {job_id}). Espera a que termine o borra el "
                        "análisis previo."
                    ),
                )
    if db_store.enabled():
        activo = db_store.active_analysis_id(repo)
        if activo:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Ya hay un análisis en curso para este repositorio "
                    f"(id {activo}). Espera a que termine o borra el análisis "
                    "previo."
                ),
            )
    resolved = req.model_copy(
        update={"repo": None, "repo_url": repo_url, "local_path": local_path}
    )
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {"status": "queued", "step": "En cola", "repo": repo}
    threading.Thread(
        target=_run_job, args=(job_id, resolved), name=f"vibeaudit-{job_id}", daemon=True
    ).start()
    return {"job_id": job_id, "status": "queued"}


@app.get("/api/scan/{job_id}")
def get_scan(job_id: str) -> Dict[str, Any]:
    """Estado, progreso y reporte (si terminó) de un scan.

    Si el job no está en memoria (p. ej. reinicio del servicio), se lee de
    Postgres cuando la persistencia está activa.
    """
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None and db_store.enabled():
        row = db_store.get_analysis(job_id)
        if row is not None:
            job = {
                "status": row.get("status"),
                "step": "Recuperado de la base de datos",
                "report": row.get("report"),
                "error": row.get("error"),
            }
    if job is None:
        raise HTTPException(status_code=404, detail="job no encontrado")
    return {"job_id": job_id, **job}


@app.get("/api/analyses")
def analyses(
    repo: Optional[str] = Query(None, description="Filtro por repo (subcadena)"),
    status: Optional[str] = Query(None, description="Filtro por estado (queued/running/done/error)"),
    since: Optional[str] = Query(None, description="Fecha mínima (ISO 8601)"),
    until: Optional[str] = Query(None, description="Fecha máxima (ISO 8601)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Lista los análisis guardados en Postgres (metadatos + resumen).

    ``total`` es el recuento real con los filtros aplicados; los items NO
    incluyen el reporte completo (usar /api/analyses/{id} para el detalle).
    """
    if not db_store.enabled():
        raise HTTPException(
            status_code=503,
            detail="Persistencia no configurada: define VIBEAUDIT_DATABASE_URL",
        )
    return db_store.list_analyses(
        repo=repo, status=status, since=since, until=until,
        limit=limit, offset=offset,
    )


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: str) -> Dict[str, Any]:
    """Análisis completo guardado (incluye el reporte JSONB)."""
    if not db_store.enabled():
        raise HTTPException(
            status_code=503,
            detail="Persistencia no configurada: define VIBEAUDIT_DATABASE_URL",
        )
    row = db_store.get_analysis(analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="análisis no encontrado")
    return row


class DeleteAnalysesRequest(BaseModel):
    """Cuerpo del borrado en lote: lista de ids de análisis."""

    ids: List[str] = Field(default_factory=list, max_length=500)


def _purge_artifacts(artifacts_dirs: List[Optional[str]]) -> None:
    """Borra los directorios de artefactos, sin salirse del raíz de artefactos."""
    base = Path(db_store.artifacts_dir()).resolve()
    for d in artifacts_dirs or []:
        if not d:
            continue
        try:
            target = Path(d).resolve()
            if target.is_relative_to(base):
                shutil.rmtree(target, ignore_errors=True)
        except (OSError, ValueError):
            pass


@app.delete("/api/analyses/{analysis_id}")
def delete_analysis(analysis_id: str) -> Dict[str, Any]:
    """Borra un análisis guardado y sus artefactos."""
    if not db_store.enabled():
        raise HTTPException(
            status_code=503,
            detail="Persistencia no configurada: define VIBEAUDIT_DATABASE_URL",
        )
    if db_store.get_analysis(analysis_id) is None:
        raise HTTPException(status_code=404, detail="análisis no encontrado")
    deleted, dirs = db_store.delete_analyses([analysis_id])
    _purge_artifacts(dirs)
    return {"deleted": deleted, "analysis_id": analysis_id}


@app.delete("/api/analyses")
def delete_analyses(req: DeleteAnalysesRequest) -> Dict[str, Any]:
    """Borra varios análisis y sus artefactos (en lote)."""
    if not db_store.enabled():
        raise HTTPException(
            status_code=503,
            detail="Persistencia no configurada: define VIBEAUDIT_DATABASE_URL",
        )
    ids = [i for i in req.ids if i]
    deleted, dirs = db_store.delete_analyses(ids)
    _purge_artifacts(dirs)
    return {"deleted": deleted, "analysis_ids": ids}


@app.get("/api/analyses/{analysis_id}/artifacts")
def analysis_artifacts(analysis_id: str) -> Dict[str, Any]:
    """Lista los archivos de artefactos de un análisis (reporte + entregables)."""
    row = db_store.get_analysis(analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="análisis no encontrado")
    base = Path(row.get("artifacts_dir") or "")
    files = []
    if base.is_dir():
        for f in sorted(base.rglob("*")):
            if f.is_file():
                files.append(str(f.relative_to(base)))
    return {"analysis_id": analysis_id, "files": files}


@app.get("/api/analyses/{analysis_id}/artifacts/{filename:path}")
def analysis_artifact_file(analysis_id: str, filename: str) -> FileResponse:
    """Sirve un archivo concreto de los artefactos del análisis."""
    row = db_store.get_analysis(analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="análisis no encontrado")
    base = Path(row.get("artifacts_dir") or "")
    target = (base / filename).resolve()
    if not target.is_relative_to(base.resolve()) or not target.is_file():
        raise HTTPException(status_code=404, detail="artefacto no encontrado")
    return FileResponse(target, filename=Path(filename).name)


@app.get("/api/repos")
def repos() -> Dict[str, Any]:
    """Repos con análisis guardados (para autocompletado del frontend)."""
    if not db_store.enabled():
        raise HTTPException(
            status_code=503,
            detail="Persistencia no configurada: define VIBEAUDIT_DATABASE_URL",
        )
    return {"repos": db_store.list_repos()}


@app.get("/api/history")
def history(
    history: Optional[str] = Query(None, description="Directorio del historial"),
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """Lista los snapshots del historial (últimos `limit`)."""
    history_dir = _history_dir(history)
    if history_dir is None:
        raise HTTPException(
            status_code=422,
            detail="Indica history=<dir> o define VIBEAUDIT_HISTORY",
        )
    store = HistoryStore(history_dir)
    snapshots = store.list_snapshots()[-limit:]
    return {"directory": str(history_dir), "total": len(snapshots), "snapshots": snapshots}


@app.get("/api/history/{snapshot_id}")
def history_snapshot(snapshot_id: str, history: Optional[str] = None) -> Dict[str, Any]:
    """Carga un snapshot concreto del historial."""
    history_dir = _history_dir(history)
    if history_dir is None:
        raise HTTPException(
            status_code=422,
            detail="Indica history=<dir> o define VIBEAUDIT_HISTORY",
        )
    try:
        return HistoryStore(history_dir).load_snapshot(snapshot_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def main() -> None:
    """Entry point: uvicorn vibeaudit.api:app."""
    import uvicorn

    uvicorn.run(
        "vibeaudit.api:app",
        host=os.environ.get("VIBEAUDIT_API_HOST", "0.0.0.0"),
        port=int(os.environ.get("VIBEAUDIT_API_PORT", "8000")),
    )


if __name__ == "__main__":
    main()

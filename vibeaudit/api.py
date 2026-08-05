"""Servicio HTTP (FastAPI) que expone el pipeline de vibeaudit.

Endpoints:
- GET  /api/health      estado del servicio
- POST /api/scan        lanza un scan en segundo plano (devuelve job_id)
- GET  /api/scan/{id}   estado/progreso y reporte del scan
- GET  /api/history     lista los snapshots del historial configurado
"""

import os
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from vibeaudit.cli import ScanConfig, run_scan
from vibeaudit.history import HistoryStore

app = FastAPI(
    title="VibeAudit API",
    description="Servicio de auditoría de seguridad para repositorios Git",
    version="0.1.0",
)

JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


class ScanRequest(BaseModel):
    """Parámetros del scan. Exactamente uno de repo_url o local_path."""

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


def _history_dir(req_history: Optional[str]) -> Optional[Path]:
    if req_history:
        return Path(req_history)
    env = os.environ.get("VIBEAUDIT_HISTORY")
    return Path(env) if env else None


def _run_job(job_id: str, req: ScanRequest) -> None:
    def log(msg: str) -> None:
        with JOBS_LOCK:
            JOBS[job_id]["step"] = msg

    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["step"] = "Iniciando..."
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
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["step"] = "Finalizado"
            JOBS[job_id]["output"] = str(output)
            JOBS[job_id]["report"] = report.model_dump(
                by_alias=True, exclude_none=True
            )
    except Exception as exc:  # noqa: BLE001 - el error queda en el job
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["step"] = str(exc)
            JOBS[job_id]["error"] = str(exc)


@app.get("/api/health")
def health() -> Dict[str, str]:
    """Estado del servicio."""
    return {"status": "ok", "service": "vibeaudit-api", "version": "0.1.0"}


@app.post("/api/scan", status_code=202)
def create_scan(req: ScanRequest) -> Dict[str, str]:
    """Lanza un scan en segundo plano; devuelve el job_id para consultar."""
    if (req.repo_url is None) == (req.local_path is None):
        raise HTTPException(
            status_code=422,
            detail="Indica repo_url o local_path (exactamente uno de los dos)",
        )
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {"status": "queued", "step": "En cola"}
    threading.Thread(
        target=_run_job, args=(job_id, req), name=f"vibeaudit-{job_id}", daemon=True
    ).start()
    return {"job_id": job_id, "status": "queued"}


@app.get("/api/scan/{job_id}")
def get_scan(job_id: str) -> Dict[str, Any]:
    """Estado, progreso y reporte (si terminó) de un scan."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job no encontrado")
    return {"job_id": job_id, **job}


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

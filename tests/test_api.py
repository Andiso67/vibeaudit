"""Tests del servicio HTTP (FastAPI): salud, scan en segundo plano e historial."""

import time

import pytest
from fastapi.testclient import TestClient
from pathlib import Path

from vibeaudit import api as api_module
from vibeaudit.api import app

client = TestClient(app)


class FakePersistencia:
    """Sustituto de vibeaudit.db que captura las llamadas del job."""

    def __init__(self):
        self.updates = []
        self.saves = []

    def enabled(self):
        return True

    def update_status(self, *args, **kwargs):
        self.updates.append(kwargs)

    def save_analysis(self, analysis):
        self.saves.append(analysis)

    def artifacts_dir(self):
        return "./artifacts"

    def build_summary(self, report_dict):
        return {"total": 0}


class FakeReporte:
    def model_dump(self, by_alias=True, exclude_none=True):
        return {"project": {"name": "proyecto", "commitHash": "abc123"}}


class FakeScanner:
    def __init__(self, repo_path, *args, **kwargs):
        self.repo_path = repo_path

    def scan(self):
        return []


@pytest.fixture
def proyecto(tmp_path):
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / "main.py").write_text("print('hola')\n")
    return proyecto


def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_scan_sin_repo_url_ni_path_rechazado():
    resp = client.post("/api/scan", json={})
    assert resp.status_code == 422
    assert "exactamente uno" in resp.json()["detail"]


def test_scan_job_completo(monkeypatch, proyecto, tmp_path):
    for cls in (
        "GitleaksScanner",
        "SemgrepScanner",
        "CheckovScanner",
        "CICDScanner",
        "DependencyScanner",
        "CustomRulesScanner",
    ):
        monkeypatch.setattr("vibeaudit.cli." + cls, FakeScanner)

    salida = tmp_path / "reporte.json"
    resp = client.post(
        "/api/scan",
        json={
            "local_path": str(proyecto),
            "output": str(salida),
            "history": str(tmp_path / "historial"),
        },
    )
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    estado = None
    for _ in range(50):
        estado = client.get(f"/api/scan/{job_id}").json()
        if estado["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert estado["status"] == "done", estado.get("error")
    assert estado["report"]["project"]["name"] == "proyecto"
    assert salida.exists()

    guard = client.get("/api/scan/nonexist")
    assert guard.status_code == 404


def _captura_repo(monkeypatch):
    """Parchea run_scan para capturar cómo se resolvió el repo."""
    captured = {}

    def fake_run(config, log=None, echo=None):
        captured["repo_url"] = config.repo_url
        captured["local_path"] = config.local_path
        return FakeReporte(), None

    monkeypatch.setattr(api_module, "run_scan", fake_run)
    monkeypatch.setattr(
        api_module, "_persist_artifacts", lambda *a, **k: Path("artifacts/x")
    )
    return captured


def _espera_job(job_id, intentos=50):
    estado = None
    for _ in range(intentos):
        estado = client.get(f"/api/scan/{job_id}").json()
        if estado["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    return estado


def test_scan_repo_autodetecta_url(monkeypatch):
    captured = _captura_repo(monkeypatch)
    resp = client.post("/api/scan", json={"repo": "https://github.com/org/demo"})
    assert resp.status_code == 202
    estado = _espera_job(resp.json()["job_id"])
    assert estado["status"] == "done", estado.get("error")
    assert captured["repo_url"] == "https://github.com/org/demo"
    assert captured["local_path"] is None


def test_scan_repo_autodetecta_ssh(monkeypatch):
    captured = _captura_repo(monkeypatch)
    resp = client.post("/api/scan", json={"repo": "git@github.com:org/demo.git"})
    assert resp.status_code == 202
    estado = _espera_job(resp.json()["job_id"])
    assert estado["status"] == "done", estado.get("error")
    assert captured["repo_url"] == "git@github.com:org/demo.git"
    assert captured["local_path"] is None


def test_scan_repo_autodetecta_directorio(monkeypatch, proyecto):
    captured = _captura_repo(monkeypatch)
    resp = client.post("/api/scan", json={"repo": str(proyecto)})
    assert resp.status_code == 202
    estado = _espera_job(resp.json()["job_id"])
    assert estado["status"] == "done", estado.get("error")
    assert captured["local_path"] == Path(str(proyecto))
    assert captured["repo_url"] is None


def test_scan_repo_y_repo_url_juntos_rechazado():
    resp = client.post(
        "/api/scan",
        json={"repo": "/tmp/x", "repo_url": "https://github.com/a/b"},
    )
    assert resp.status_code == 422
    assert "no ambos" in resp.json()["detail"]


def test_scan_job_registra_repo_en_running_y_save(monkeypatch, proyecto):
    persistencia = FakePersistencia()
    monkeypatch.setattr(api_module, "db_store", persistencia)
    monkeypatch.setattr(
        api_module, "run_scan", lambda *a, **k: (FakeReporte(), None)
    )
    monkeypatch.setattr(
        api_module, "_persist_artifacts", lambda *a, **k: Path("artifacts/x")
    )

    resp = client.post("/api/scan", json={"local_path": str(proyecto)})
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    estado = None
    for _ in range(50):
        estado = client.get(f"/api/scan/{job_id}").json()
        if estado["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert estado["status"] == "done", estado.get("error")

    running = [u for u in persistencia.updates if u.get("status") == "running"]
    assert running, "no se registró el estado running"
    assert running[0]["repo"] == str(proyecto)
    assert persistencia.saves[0]["repo"] == str(proyecto)


def test_scan_job_falla_sin_path(monkeypatch):
    resp = client.post("/api/scan", json={"repo_url": "https://github.com/a/b"})
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    estado = None
    for _ in range(30):
        estado = client.get(f"/api/scan/{job_id}").json()
        if estado["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert estado["status"] == "error"
    assert estado["error"]


def test_history_sin_directorio_rechazado():
    resp = client.get("/api/history")
    assert resp.status_code == 422


def test_history_lista_snapshots(monkeypatch, proyecto, tmp_path):
    for cls in (
        "GitleaksScanner",
        "SemgrepScanner",
        "CheckovScanner",
        "CICDScanner",
        "DependencyScanner",
        "CustomRulesScanner",
    ):
        monkeypatch.setattr("vibeaudit.cli." + cls, FakeScanner)

    historial = tmp_path / "historial"
    resp = client.post(
        "/api/scan",
        json={"local_path": str(proyecto), "history": str(historial)},
    )
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    for _ in range(50):
        estado = client.get(f"/api/scan/{job_id}").json()
        if estado["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert estado["status"] == "done", estado.get("error")

    lista = client.get(f"/api/history?history={historial}").json()
    assert lista["total"] == 1
    snapshot_id = lista["snapshots"][0]["id"]

    detalle = client.get(f"/api/history/{snapshot_id}?history={historial}")
    assert detalle.status_code == 200
    assert detalle.json()["report"]["project"]["name"] == "proyecto"

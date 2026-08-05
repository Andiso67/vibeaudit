"""Tests del servicio HTTP (FastAPI): salud, scan en segundo plano e historial."""

import time

import pytest
from fastapi.testclient import TestClient

from vibeaudit.api import app

client = TestClient(app)


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

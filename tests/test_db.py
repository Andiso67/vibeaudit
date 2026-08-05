"""Tests de la capa de persistencia (Postgres opcional) y sus endpoints."""

from fastapi.testclient import TestClient

from vibeaudit import api as api_module
from vibeaudit import db as db_store

SAMPLE_REPORT = {
    "project": {"name": "demo", "commitHash": "abc123"},
    "secrets": [{"severity": "CRITICAL"}, {"severity": "HIGH"}],
    "vulnerabilities": [{"severity": "HIGH"}],
    "iacIssues": [],
    "cicdIssues": [{"severity": "LOW"}],
    "customIssues": [],
    "cloudIssues": [{"severity": "HIGH"}],
    "llmFindings": [],
    "metrics": {"dependenciesWithCves": [{"id": "x"}], "dependencies": 42},
}


class TestBuildSummary:
    def test_cuenta_por_tipo_y_severidad(self):
        summary = db_store.build_summary(SAMPLE_REPORT)
        assert summary["by_type"] == {
            "secrets": 2, "sast": 1, "iac": 0, "cicd": 1,
            "custom": 0, "cloud": 1, "llm": 0, "deps": 1,
        }
        assert summary["by_severity"] == {"CRITICAL": 1, "HIGH": 3, "LOW": 1}
        assert summary["total"] == 6
        assert summary["dependencies_total"] == 42

    def test_reporte_vacio(self):
        summary = db_store.build_summary({"metrics": {}})
        assert summary["total"] == 0
        assert summary["by_type"]["deps"] == 0
        assert summary["by_severity"] == {}


class TestEnabled:
    def test_sin_url_la_persistencia_es_noop(self, monkeypatch):
        monkeypatch.delenv("VIBEAUDIT_DATABASE_URL", raising=False)
        assert db_store.enabled() is False
        assert db_store.list_analyses() == []
        assert db_store.list_repos() == []
        assert db_store.get_analysis("x") is None
        db_store.save_analysis({"id": "x"})
        db_store.update_status("x", status="done")
        db_store.init_db()

    def test_con_url_activada(self, monkeypatch):
        monkeypatch.setenv(
            "VIBEAUDIT_DATABASE_URL", "postgresql://u:p@h:5432/db"
        )
        assert db_store.enabled() is True


class TestPgJson:
    def test_convierte_dicts_a_json_para_jsonb(self):
        data = {"report": {"a": 1}, "summary": {"b": 2}, "tool_versions": None}
        out = db_store._pg_json(data)
        assert out["report"] == '{"a": 1}'
        assert out["summary"] == '{"b": 2}'
        assert out["tool_versions"] is None

    def test_no_toca_strings_existentes(self):
        out = db_store._pg_json({"report": '{"a": 1}'})
        assert out["report"] == '{"a": 1}'


class FakeDB:
    """Sustituto de vibeaudit.db para los endpoints (sin Postgres real)."""

    def __init__(self):
        self.enabled_flag = False
        self.rows = [
            {
                "id": "job1",
                "repo": "https://github.com/org/demo",
                "branch": "main",
                "commit_hash": "abc123",
                "status": "done",
                "summary": {"total": 3},
                "artifacts_dir": "./artifacts/job1",
                "has_report": True,
            }
        ]

    def enabled(self):
        return self.enabled_flag

    def init_db(self):
        return None

    def list_analyses(self, **kwargs):
        return self.rows

    def get_analysis(self, analysis_id):
        if analysis_id == "job1":
            return {**self.rows[0], "report": SAMPLE_REPORT}
        return None

    def list_repos(self):
        return ["https://github.com/org/demo"]

    def update_status(self, *args, **kwargs):
        return None

    def save_analysis(self, analysis):
        return None


class TestAnalysesEndpoints:
    def _client(self, monkeypatch, fake):
        monkeypatch.setattr(api_module, "db_store", fake)
        return TestClient(api_module.app)

    def test_analyses_sin_bd_devuelve_503(self, monkeypatch):
        fake = FakeDB()
        client = self._client(monkeypatch, fake)
        assert client.get("/api/analyses").status_code == 503
        assert client.get("/api/analyses/job1").status_code == 503
        assert client.get("/api/repos").status_code == 503

    def test_analyses_con_bd_lista_y_filtra(self, monkeypatch):
        fake = FakeDB()
        fake.enabled_flag = True
        client = self._client(monkeypatch, fake)
        resp = client.get("/api/analyses?repo=demo&status=done&limit=10")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["repo"].endswith("demo")

    def test_analyses_por_id_devuelve_reporte(self, monkeypatch):
        fake = FakeDB()
        fake.enabled_flag = True
        client = self._client(monkeypatch, fake)
        resp = client.get("/api/analyses/job1")
        assert resp.status_code == 200
        assert resp.json()["report"]["secrets"][0]["severity"] == "CRITICAL"

    def test_analyses_por_id_no_encontrado_404(self, monkeypatch):
        fake = FakeDB()
        fake.enabled_flag = True
        client = self._client(monkeypatch, fake)
        assert client.get("/api/analyses/desconocido").status_code == 404

    def test_repos_autocompletado(self, monkeypatch):
        fake = FakeDB()
        fake.enabled_flag = True
        client = self._client(monkeypatch, fake)
        assert client.get("/api/repos").json() == {
            "repos": ["https://github.com/org/demo"]
        }

    def test_get_scan_fallback_a_bd_tras_reinicio(self, monkeypatch):
        fake = FakeDB()
        fake.enabled_flag = True
        with api_module.JOBS_LOCK:
            api_module.JOBS.clear()
        client = self._client(monkeypatch, fake)
        resp = client.get("/api/scan/job1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "done"
        assert body["report"]["project"]["name"] == "demo"

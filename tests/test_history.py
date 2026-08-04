"""Tests del historial de escaneos (snapshots, deltas y export para dashboard)."""

import json

from vibeaudit.history import HistoryStore
from vibeaudit.memory import MemoryEntry, MemoryStore
from vibeaudit.models import (
    AuditReport,
    Metrics,
    ProjectMetadata,
    Severity,
    Vulnerability,
)


def make_report(path, lines=100):
    return AuditReport(
        project=ProjectMetadata(name="demo", commit_hash="abc123def456"),
        vulnerabilities=[
            Vulnerability(
                rule="python.eval.usage",
                file="src/a.py",
                line=1,
                severity=Severity.CRITICAL,
            )
        ],
        metrics=Metrics(lines_of_code=lines),
    )


class TestHistoryStore:
    def test_save_y_list_snapshots(self, tmp_path):
        store = HistoryStore(tmp_path)
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-01T00:00:00Z")
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-02T00:00:00Z")

        snaps = store.list_snapshots()
        assert len(snaps) == 2
        assert snaps[0]["timestamp"] < snaps[1]["timestamp"]
        assert snaps[0]["summary"]["total"] == 1
        assert snaps[1]["summary"]["modules"]["sast"] == 1

    def test_delta_detecta_nuevos_y_resueltos(self, tmp_path):
        store = HistoryStore(tmp_path)
        first = make_report(tmp_path)
        store.save_snapshot(first, timestamp="2026-01-01T00:00:00Z")
        store.save_snapshot(first, timestamp="2026-01-02T00:00:00Z")

        prev_raw = store.load_snapshot(store.list_snapshots()[0]["id"])
        curr_raw = store.load_snapshot(store.list_snapshots()[1]["id"])
        delta = store.delta(prev_raw, curr_raw)
        assert delta["new"] == 0
        assert delta["resolved"] == 0
        assert delta["persistent"] == 1

    def test_delta_con_vulnerabilidad_nueva(self, tmp_path):
        store = HistoryStore(tmp_path)
        base = make_report(tmp_path)
        store.save_snapshot(base, timestamp="2026-01-01T00:00:00Z")

        evolved = make_report(tmp_path)
        evolved.vulnerabilities.append(
            Vulnerability(
                rule="javascript.eval.unsafe",
                file="src/b.js",
                line=3,
                severity=Severity.HIGH,
            )
        )
        store.save_snapshot(evolved, timestamp="2026-01-02T00:00:00Z")

        snaps = store.list_snapshots()
        delta = store.delta(
            store.load_snapshot(snaps[0]["id"]),
            store.load_snapshot(snaps[1]["id"]),
        )
        assert delta["new"] == 1
        assert delta["resolved"] == 0

    def test_export_dashboard(self, tmp_path):
        store = HistoryStore(tmp_path)
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-01T00:00:00Z")
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-02T00:00:00Z")

        payload = store.export_dashboard(tmp_path / "audit-history.json")
        assert len(payload["snapshots"]) == 2
        assert len(payload["deltas"]) == 1
        assert "new" in payload["deltas"][0]
        exported = json.loads((tmp_path / "audit-history.json").read_text())
        assert exported["latest"]["summary"]["total"] == 1

    def test_historial_vacio_exporta_json_vacio(self, tmp_path):
        payload = HistoryStore(tmp_path).export_dashboard(tmp_path / "empty.json")
        assert payload == {"snapshots": [], "deltas": [], "alerts": []}

    def test_recurrence_alerts_marca_persistentes(self, tmp_path):
        store = HistoryStore(tmp_path)
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-01T00:00:00Z")
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-02T00:00:00Z")
        alerts = store.recurrence_alerts()
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "python.eval.usage"
        assert alerts[0]["snapshots"] == 2
        assert alerts[0]["level"] == "ATENCION"

    def test_recurrence_alerts_integra_memoria(self, tmp_path, tmp_path_factory):
        store = HistoryStore(tmp_path)
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-01T00:00:00Z")
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-02T00:00:00Z")

        memory_dir = tmp_path_factory.mktemp("memory")
        memory = MemoryStore(memory_dir)
        for _ in range(4):
            memory.remember(
                Vulnerability(
                    rule="python.eval.usage",
                    file="src/a.py",
                    line=1,
                    severity=Severity.CRITICAL,
                ),
                suggestion="Usar un motor seguro para evaluar expresiones.",
            )
        alerts = store.recurrence_alerts(memory=memory)
        assert alerts[0]["occurrences"] >= 4
        assert "motor seguro" in alerts[0]["recommendation"]
        assert alerts[0]["level"] == "ALERTA"

    def test_export_dashboard_incluye_alertas(self, tmp_path):
        store = HistoryStore(tmp_path)
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-01T00:00:00Z")
        store.save_snapshot(make_report(tmp_path), timestamp="2026-01-02T00:00:00Z")
        payload = store.export_dashboard(tmp_path / "audit-history.json")
        assert len(payload["alerts"]) == 1
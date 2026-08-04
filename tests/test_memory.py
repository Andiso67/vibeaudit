"""Tests de la memoria de hallazgos recurrentes (ítem 3, tienda local)."""

import json

import pytest

from vibeaudit.memory import (
    LocalEmbedder,
    MemoryEntry,
    MemoryStore,
    QdrantMemoryStore,
    STORAGE_FILE,
    new_store,
)
from vibeaudit.models import (
    AuditReport,
    Metrics,
    ProjectMetadata,
    Severity,
    Vulnerability,
)


def make_report(rules=("CKV_AWS_20",)):
    return AuditReport(
        project=ProjectMetadata(name="demo"),
        vulnerabilities=[],
        iac_issues=[
            Vulnerability(rule=r, file="infra/main.tf", line=1, severity=Severity.HIGH)
            for r in rules
        ],
        metrics=Metrics(lines_of_code=10),
    )


class TestLocalEmbedder:
    def test_determinista(self):
        assert LocalEmbedder().embed("CKV_AWS_20") == LocalEmbedder().embed(
            "CKV_AWS_20"
        )

    def test_dimension_fija(self):
        vector = LocalEmbedder().embed("CKV_AWS_20 S3 bucket publico")
        assert len(vector) == 256

    def test_normalizado(self):
        import math

        vector = LocalEmbedder().embed("CKV_AWS_20 S3 bucket publico")
        norm = math.sqrt(sum(x * x for x in vector))
        assert norm == pytest.approx(1.0, abs=1e-6)

    def test_textos_similares_mas_cercanos(self):
        emb = LocalEmbedder()
        a = emb.embed("CKV_AWS_20 S3 bucket public access")
        b = emb.embed("CKV_AWS_20 S3 bucket public read")
        c = emb.embed("CKV_AWS_41 encryption enabled")
        assert emb.similarity(a, b) > emb.similarity(a, c)
        assert emb.similarity(a, b) > 0.5

    def test_vacio_no_tiene_similitud(self):
        emb = LocalEmbedder()
        assert emb.similarity(emb.embed(""), emb.embed("algo")) == 0.0


class TestMemoryStore:
    def test_ingest_primera_vez_no_es_recurrente(self, tmp_path):
        store = MemoryStore(tmp_path)
        recurrent = store.ingest_report(make_report(rules=["CKV_AWS_20"]))
        assert recurrent == []
        assert len(store.entries()) == 1
        assert store.path.exists()

    def test_ingest_segunda_vez_es_recurrente(self, tmp_path):
        store = MemoryStore(tmp_path)
        store.ingest_report(make_report(rules=["CKV_AWS_20"]))
        store2 = MemoryStore(tmp_path)  # se recarga desde JSON
        recurrent = store2.ingest_report(make_report(rules=["CKV_AWS_20"]))
        assert len(recurrent) == 1
        assert recurrent[0].rule == "CKV_AWS_20"
        assert recurrent[0].occurrences == 2
        assert recurrent[0].severity == Severity.HIGH

    def test_persistencia_json(self, tmp_path):
        store = MemoryStore(tmp_path)
        store.ingest_report(make_report(rules=["CKV_AWS_20"]))
        data = json.loads((tmp_path / STORAGE_FILE).read_text())
        assert data["version"] == 1
        assert data["entries"][0]["rule"] == "CKV_AWS_20"

    def test_suggestion_usada_en_recurrente(self, tmp_path):
        store = MemoryStore(tmp_path)
        store.upsert(
            MemoryEntry(
                id="ent1",
                rule="CKV_AWS_20",
                recommendation="Bloquear ACL públicos: aws_s3_bucket_public_access_block",
                occurrences=1,
                first_seen="2026-01-01T00:00:00+00:00",
                last_seen="2026-01-01T00:00:00+00:00",
            )
        )
        recurrent = store.ingest_report(make_report(rules=["CKV_AWS_20"]))
        assert len(recurrent) == 1
        assert "public_access_block" in recurrent[0].suggestion

    def test_upsert_reemplaza_y_guarda(self, tmp_path):
        store = MemoryStore(tmp_path)
        store.upsert(MemoryEntry(id="a", rule="R1", occurrences=1, first_seen="x", last_seen="x"))
        store.upsert(MemoryEntry(id="b", rule="R1", occurrences=2, first_seen="y", last_seen="y"))
        assert len(store.entries()) == 1
        assert store.entries()[0].id == "b"

    def test_marca_deps_por_paquete_cve(self, tmp_path):
        from vibeaudit.models import DependencyVulnerability

        report = make_report(rules=[])
        report.metrics.dependency_vulnerabilities = [
            DependencyVulnerability(
                name="axios", ecosystem="npm", version="1.0.0",
                direct=True, cve_ids=["CVE-2024-1"], severity=Severity.HIGH,
            )
        ]
        store = MemoryStore(tmp_path)
        store.ingest_report(report)
        store2 = MemoryStore(tmp_path)
        recurrent = store2.ingest_report(report)
        assert len(recurrent) == 1
        assert "axios" in recurrent[0].rule

    def test_ingest_empty_score(self, tmp_path):
        store = MemoryStore(tmp_path)
        report = AuditReport(
            project=ProjectMetadata(name="demo"),
            metrics=Metrics(lines_of_code=0),
        )
        assert store.ingest_report(report) == []
        assert store.entries() == []

    def test_corrupto_no_crash(self, tmp_path):
        (tmp_path / STORAGE_FILE).write_text("{ no es json")


class FakeQdrant:
    """Cliente Qdrant simplificado para tests (sin red)."""

    def __init__(self):
        self.points: dict = {}

    def upsert(self, collection, point_id, vector, payload):
        self.points[point_id] = {"vector": vector, "payload": dict(payload)}

    def set_payload(self, collection, point_id, payload):
        self.points[point_id]["payload"].update(payload)

    def scroll(self, collection):
        return [p["payload"] for p in self.points.values()]

    def find_by_rule(self, collection, rule):
        for payload in self.scroll(collection):
            if payload.get("rule") == rule:
                return payload
        return None

    def search_vectors(self, collection, vector, k):
        return [
            (p["payload"], 0.9)
            for p in sorted(
                self.points.values(),
                key=lambda p: sum(
                    x * y for x, y in zip(p["vector"], vector)
                ),
                reverse=True,
            )[:k]
        ]


class TestQdrantMemoryStore:
    def test_primera_vez_registra_segunda_es_recurrente(self):
        store = QdrantMemoryStore(
            url="http://qdrant:6333", client=FakeQdrant()
        )
        report = make_report(rules=("CKV_AWS_20",))
        assert store.ingest_report(report) == []
        assert len(store.entries()) == 1

        recurrent = store.ingest_report(report)
        assert len(recurrent) == 1
        assert recurrent[0].rule == "CKV_AWS_20"
        assert recurrent[0].occurrences == 2

    def test_upsert_y_semantic_similar(self):
        fake = FakeQdrant()
        store = QdrantMemoryStore(url="http://qdrant:6333", client=fake)
        store.upsert(
            MemoryEntry(
                id="a",
                rule="CKV_AWS_20",
                evidence="S3 bucket public access",
                recommendation="Block public access",
                occurrences=1,
                first_seen="2026-01-01",
                last_seen="2026-01-01",
            )
        )
        similar = store.semantic_similar("s3 bucket public access", k=1)
        assert len(similar) == 1
        assert similar[0][0].rule == "CKV_AWS_20"
        assert similar[0][1] > 0.5

    def test_new_store_selecciona_backend_segun_url(self):
        assert isinstance(
            new_store(
                "http://localhost:6333",
                embedder=LocalEmbedder(),
                client=FakeQdrant(),
            ),
            QdrantMemoryStore,
        )
        assert isinstance(
            new_store("/tmp/mem-local", embedder=LocalEmbedder()),
            MemoryStore,
        )
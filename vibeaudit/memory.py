"""Memoria de hallazgos recurrentes (ítem 3 del Sprint 3).

Tienda vectorial 100% local: embeddings deterministas por hash de n-gramos
(`LocalEmbedder`, sin red ni modelos) y búsqueda por similitud de coseno.
La persistencia es un único JSON en el directorio indicado con `--memory`.
La deduplicación y las sugerencias de fix se basan en la clase de hallazgo
(regla/paquete), que es la forma estable de reconocer un hallazgo repetido;
la similitud semántica queda disponible para escalar a un vector DB real
(Qdrant) sin tocar el resto de la app.
"""

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

from vibeaudit.models import AuditReport, RecurrentFinding, Severity

EMBED_DIM = 256
RECURRENCE_THRESHOLD = 0.5
STORAGE_FILE = "memory.json"

SECTIONS_ITEMS = {
    "sast": "vulnerabilities",
    "secrets": "secrets",
    "iac": "iac_issues",
    "cicd": "cicd_issues",
    "custom": "custom_issues",
    "deps": "metrics.dependency_vulnerabilities",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_feature(token: str) -> int:
    return int(hashlib.md5(token.encode("utf-8")).hexdigest()[:8], 16)


class LocalEmbedder:
    """Embedding determinista sin red: n-gramos de caracteres + palabras hash."""

    def __init__(self, dim: int = EMBED_DIM):
        self.dim = dim

    def _features(self, text: str) -> List[str]:
        text = text.lower()
        features = []
        for token in text.split():
            if len(token) >= 3:
                features.append("w:" + token)
        for n in (3, 4):
            for i in range(len(text) - n + 1):
                features.append(f"n{n}:" + text[i : i + n])
        return features

    def embed(self, text: str) -> List[float]:
        vector = [0.0] * self.dim
        for feature in self._features(text):
            index = _hash_feature(feature) % self.dim
            vector[index] += 1.0
        norm = math.sqrt(sum(x * x for x in vector))
        if norm == 0.0:
            return vector
        return [x / norm for x in vector]

    @staticmethod
    def similarity(a: List[float], b: List[float]) -> float:
        if not a or not b:
            return 0.0
        return sum(x * y for x, y in zip(a, b))


class MemoryEntry(BaseModel):
    """Entrada de memoria: una clase de hallazgo y el fix/solución conocida."""

    id: str = Field(..., min_length=1, description="Identificador de la entrada")
    rule: str = Field("", description="Regla/paquete asociado (clase del hallazgo)")
    evidence: str = Field("", description="Texto de evidencia que la identifica")
    recommendation: str = Field("", description="Solución/fix conocida (si se registró)")
    framework: str = Field("", description="Marco asociado (12-Factor, OWASP, AWS WAF...)")
    occurrences: int = Field(default=1, ge=1, description="Veces que se ha visto")
    first_seen: str = Field(..., description="Fecha ISO de la primera vez")
    last_seen: str = Field(..., description="Fecha ISO de la última vez")

    model_config = {"populate_by_name": True}


class MemoryStore:
    """Tienda persistente en `<dir>/memory.json`, sin red ni servicios."""

    def __init__(
        self,
        directory: Path,
        embedder: Optional[LocalEmbedder] = None,
        threshold: float = RECURRENCE_THRESHOLD,
    ):
        self.directory = Path(directory)
        self.embedder = embedder or LocalEmbedder()
        self.threshold = threshold
        self._entries: List[MemoryEntry] = []
        self._load()

    @property
    def path(self) -> Path:
        return self.directory / STORAGE_FILE

    # --- persistencia ---

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for raw in data.get("entries", []):
            try:
                self._entries.append(MemoryEntry(**raw))
            except Exception:
                continue

    def save(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "entries": [e.model_dump() for e in self._entries],
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        tmp.replace(self.path)

    def entries(self) -> List[MemoryEntry]:
        return list(self._entries)

    def upsert(self, entry: MemoryEntry) -> None:
        """Inserta o reemplaza una entrada (mismo rule) y guarda."""
        self._entries = [e for e in self._entries if e.rule != entry.rule] + [entry]
        self.save()

    # --- consultas ---

    def _identity_key(self, item) -> str:
        """Clave estable de un hallazgo: regla (o paquete+CVE en deps)."""
        rule = getattr(item, "rule", None)
        if rule:
            return str(rule)
        cves = getattr(item, "cve_ids", None)
        if cves:
            return f"{getattr(item, 'name', '')} {','.join(cves)}"
        return str(getattr(item, "type", "")) or str(getattr(item, "name", ""))

    def _find_exact(self, key: str) -> Optional[MemoryEntry]:
        for entry in self._entries:
            if entry.rule == key:
                return entry
        return None

    def semantic_similar(self, text: str, k: int = 5) -> List[Tuple[MemoryEntry, float]]:
        """Top-k entradas por similitud de coseno (para escalar a vector DB)."""
        vector = self.embedder.embed(text)
        scored = []
        for entry in self._entries:
            entry_vector = self.embedder.embed(entry.evidence or entry.rule)
            score = self.embedder.similarity(vector, entry_vector)
            scored.append((entry, score))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]

    def remember(self, item, suggestion: Optional[str] = None) -> Tuple[MemoryEntry, bool]:
        """Registra el hallazgo en memoria.

        Devuelve (entry, es_recurrente): si ya se había visto esta clase de
        hallazgo, incrementa `occurrences` y devuelve la entrada existente
        (recurrente=True); si no, crea una nueva (recurrente=False).
        """
        key = self._identity_key(item)
        if not key:
            return MemoryEntry(id="empty", first_seen="", last_seen=""), False
        now = _now_iso()
        existing = self._find_exact(key)
        if existing is not None:
            existing.occurrences += 1
            existing.last_seen = now
            return existing, True
        entry = MemoryEntry(
            id=hashlib.md5(key.encode()).hexdigest()[:12],
            rule=key,
            evidence=self._evidence_text(item),
            recommendation=suggestion or "",
            framework=getattr(item, "framework", ""),
            occurrences=1,
            first_seen=now,
            last_seen=now,
        )
        self._entries.append(entry)
        return entry, False

    def _evidence_text(self, item) -> str:
        snippet = getattr(item, "snippet", None) or ""
        file = getattr(item, "file", None) or ""
        parts = [getattr(item, "rule", "") or self._identity_key(item), file]
        if snippet:
            parts.append(str(snippet)[:200])
        return " ".join(p for p in parts if p)

    def mark_seen(self, item) -> Optional[MemoryEntry]:
        """Marca el hallazgo como visto (mismo comportamiento que remember=True)."""
        entry, recurrent = self.remember(item)
        if recurrent:
            return entry
        self.remember(item, suggestion=None)  # no-op: ya registrado
        return entry

    def ingest_report(self, report: AuditReport) -> List[RecurrentFinding]:
        """Recorre los hallazgos del report, registra en memoria y devuelve
        los recurrentes (con sugerencia de fix si está registrada)."""
        recurrent: List[RecurrentFinding] = []
        for section, attr in SECTIONS_ITEMS.items():
            obj: object = report
            for part in attr.split("."):
                obj = getattr(obj, part)
            for item in obj or []:
                entry, is_recurrent = self.remember(item)
                if not is_recurrent:
                    continue
                recurrent.append(
                    RecurrentFinding(
                        rule=self._identity_key(item),
                        file=getattr(item, "file", "") or "",
                        line=getattr(item, "line", 0) or 0,
                        severity=getattr(item, "severity", Severity.INFO),
                        occurrences=entry.occurrences,
                        memory_id=entry.id,
                        suggestion=entry.recommendation
                        or "Hallazgo recurrente: revisar en el repositorio y registrar un fix con 'memory add'.",
                        first_seen=entry.first_seen,
                    )
                )
        self.save()
        return recurrent


# Límite de resultados de búsqueda por defecto en el backend Qdrant
QDRANT_SEARCH_LIMIT = 10


def new_store(
    memory: str,
    embedder: Optional[LocalEmbedder] = None,
    client: object = None,
) -> "MemoryStore":
    """Crea la tienda de memoria según el valor de `--memory`.

    Si el valor es una URL (http://host:port) se usa un backend vectorial real
    sobre Qdrant; si no, un directorio local (persistencia JSON). Es el único
    punto de entrada que usa la CLI, para no acoplar la elección del backend.
    ``client`` se inyecta en tests (Qdrant sin red).
    """
    target = memory.strip()
    if target.startswith("http://") or target.startswith("https://"):
        return QdrantMemoryStore(url=target, embedder=embedder, client=client)
    return MemoryStore(directory=Path(target), embedder=embedder)


class QdrantMemoryStore:
    """Backend vectorial real sobre Qdrant (misma interfaz que MemoryStore).

    Usa Qdrant para la búsqueda por similitud de coseno mientras mantiene los
    embeddings de ``LocalEmbedder`` (deterministas y sin red). Los hallazgos se
    guardan como puntos con payload en una colección; ``remember`` consulta por
    regla exacta (igual que el backend local) y la similitud queda disponible
    vía ``semantic_similar`` con ``search`` nativo de Qdrant.

    ``client`` se inyecta en tests (sin red); en producción se usa el cliente
    oficial de Qdrant, que se importa de forma perezosa.
    """

    COLLECTION = "vibeaudit_memory"
    EMBED_DIM = EMBED_DIM

    def __init__(
        self,
        url: str,
        collection: str = COLLECTION,
        embedder: Optional[LocalEmbedder] = None,
        threshold: float = RECURRENCE_THRESHOLD,
        client: object = None,
    ):
        self.url = url
        self.collection = collection
        self.embedder = embedder or LocalEmbedder()
        self.threshold = threshold
        self._client = client
        self._fake = client is not None
        if client is None:
            self._init_client()

    @property
    def path(self) -> Path:
        return Path(self.url)

    def _models(self):
        """Modelos de Qdrant para construir payloads (solo cliente real)."""
        from qdrant_client.http import models

        return models

    def _init_client(self) -> None:
        """Conecta con Qdrant (import perezoso para no exigir el paquete)."""
        try:
            from qdrant_client import QdrantClient
        except ImportError as exc:
            raise RuntimeError(
                "Memoria Qdrant requiere 'pip install qdrant-client'. "
                "Instálalo o usa --memory <directorio> para el backend local."
            ) from exc
        self._client = QdrantClient(url=self.url, timeout=10)
        try:
            self._client.get_collection(self.collection)
        except Exception:
            from qdrant_client.http import models

            self._client.recreate_collection(
                collection_name=self.collection,
                vectors_config=models.VectorParams(
                    size=self.EMBED_DIM, distance=models.Distance.COSINE
                ),
            )

    @staticmethod
    def _filter_by_rule(rule: str) -> dict:
        return {"must": [{"key": "rule", "match": {"value": rule}}]}

    # --- persistencia / API de Qdrant ---

    def _upsert(self, point_id: str, vector: List[float], payload: dict) -> None:
        if self._fake:
            self._client.upsert(self.collection, point_id, vector, payload)
            return
        models = self._models()
        self._client.upsert(
            collection_name=self.collection,
            points=[models.PointStruct(id=point_id, vector=vector, payload=payload)],
            wait=True,
        )

    def _set_payload(self, point_id: str, payload: dict) -> None:
        if self._fake:
            self._client.set_payload(self.collection, point_id, payload)
            return
        self._client.set_payload(
            collection_name=self.collection,
            points=[point_id],
            payload=payload,
            wait=True,
        )

    def _scroll_all(self) -> List[dict]:
        if self._fake:
            payloads = self._client.scroll(self.collection)
        else:
            records = self._client.scroll(
                collection_name=self.collection, limit=10_000, with_payload=True
            )
            records = records[0] if isinstance(records, tuple) else records
            payloads = [rec.payload for rec in records]
        return [
            p
            for p in payloads
            if isinstance(p, dict) and p.get("rule") and p.get("id")
        ]

    def _find_by_rule(self, rule: str) -> Optional[dict]:
        if self._fake:
            payload = self._client.find_by_rule(self.collection, rule)
        else:
            models = self._models()
            records = self._client.search(
                collection_name=self.collection,
                query_vector=[0.0] * self.EMBED_DIM,
                query_filter=models.Filter(**self._filter_by_rule(rule)),
                limit=1,
                with_payload=True,
            )
            payload = records[0].payload if records else None
        return payload if isinstance(payload, dict) else None

    def save(self) -> None:
        """No-op: Qdrant persiste en cada operación."""

    def entries(self) -> List[MemoryEntry]:
        result = []
        for payload in self._scroll_all():
            try:
                result.append(MemoryEntry(**payload))
            except Exception:
                continue
        result.sort(key=lambda entry: entry.rule)
        return result

    def upsert(self, entry: MemoryEntry) -> None:
        self._upsert(
            entry.id,
            self.embedder.embed(entry.evidence or entry.rule),
            entry.model_dump(),
        )

    def _identity_key(self, item) -> str:
        rule = getattr(item, "rule", None)
        if rule:
            return str(rule)
        cves = getattr(item, "cve_ids", None)
        if cves:
            return f"{getattr(item, 'name', '')} {','.join(cves)}"
        return str(getattr(item, "type", "")) or str(getattr(item, "name", ""))

    def semantic_similar(self, text: str, k: int = QDRANT_SEARCH_LIMIT) -> List[Tuple[MemoryEntry, float]]:
        """Top-k entradas por similitud de coseno (search nativo de Qdrant)."""
        vector = self.embedder.embed(text)
        if self._fake:
            results = self._client.search_vectors(self.collection, vector, k)
            return [(MemoryEntry(**payload), score) for payload, score in results]
        hits = self._client.search(
            collection_name=self.collection,
            query_vector=vector,
            limit=k,
            with_payload=True,
        )
        scored = []
        for hit in hits:
            try:
                scored.append((MemoryEntry(**hit.payload), hit.score))
            except Exception:
                continue
        return scored

    def remember(self, item, suggestion: Optional[str] = None) -> Tuple[MemoryEntry, bool]:
        """Registra el hallazgo en Qdrant; devuelve (entry, es_recurrente)."""
        key = self._identity_key(item)
        if not key:
            return MemoryEntry(id="empty", first_seen="", last_seen=""), False
        now = _now_iso()
        entry_id = hashlib.md5(key.encode()).hexdigest()[:12]
        existing = self._find_by_rule(key)
        if existing is not None:
            existing["occurrences"] = int(existing.get("occurrences", 1)) + 1
            existing["last_seen"] = now
            self._set_payload(entry_id, existing)
            return MemoryEntry(**{**existing, "id": existing.get("id") or entry_id}), True
        entry = MemoryEntry(
            id=entry_id,
            rule=key,
            evidence=self._evidence_text(item),
            recommendation=suggestion or "",
            framework=getattr(item, "framework", ""),
            occurrences=1,
            first_seen=now,
            last_seen=now,
        )
        vector = self.embedder.embed(entry.evidence or entry.rule)
        self._upsert(entry.id, vector, entry.model_dump())
        return entry, False

    def _evidence_text(self, item) -> str:
        snippet = getattr(item, "snippet", None) or ""
        file = getattr(item, "file", None) or ""
        parts = [getattr(item, "rule", "") or self._identity_key(item), file]
        if snippet:
            parts.append(str(snippet)[:200])
        return " ".join(p for p in parts if p)

    def ingest_report(self, report: AuditReport) -> List[RecurrentFinding]:
        """Comportamiento idéntico a MemoryStore.ingest_report (sin guardar)."""
        recurrent: List[RecurrentFinding] = []
        for section, attr in SECTIONS_ITEMS.items():
            obj: object = report
            for part in attr.split("."):
                if hasattr(obj, part):
                    obj = getattr(obj, part)
                else:
                    obj = []
            for item in obj or []:
                entry, is_recurrent = self.remember(item)
                if not is_recurrent:
                    continue
                recurrent.append(
                    RecurrentFinding(
                        rule=self._identity_key(item),
                        file=getattr(item, "file", "") or "",
                        line=getattr(item, "line", 0) or 0,
                        severity=getattr(item, "severity", Severity.INFO),
                        occurrences=entry.occurrences,
                        memory_id=entry.id,
                        suggestion=entry.recommendation
                        or "Hallazgo recurrente: revisar en el repositorio y registrar un fix con 'memory add'.",
                        first_seen=entry.first_seen,
                    )
                )
        return recurrent
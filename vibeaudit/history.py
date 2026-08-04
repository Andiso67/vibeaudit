"""Historial de escaneos: snapshots por commit y delta de hallazgos.

Cada scan puede guardar un snapshot (reporte completo + metadatos) en un
directorio de historial. El dashboard usa un resumen exportado
(``audit-history.json``) para mostrar la evolución del proyecto entre
escaneos: hallazgos nuevos, resueltos y persistentes.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from vibeaudit.models import AuditReport, Severity

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class HistoryStore:
    """Guarda snapshots de escaneos en ``<dir>/snapshots/`` con un índice."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.snapshots_dir = self.directory / "snapshots"
        self.index_path = self.directory / "index.json"

    def save_snapshot(
        self,
        report: AuditReport,
        timestamp: Optional[str] = None,
        commit: Optional[str] = None,
    ) -> str:
        """Persiste un snapshot del reporte y registra su resumen en el índice."""
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        ts = timestamp or _now_iso()
        commit = commit or getattr(report.project, "commit_hash", None) or "unknown"
        snapshot_id = hashlib.md5(f"{commit}:{ts}".encode()).hexdigest()[:12]
        filename = f"{snapshot_id}.json"

        payload = {
            "id": snapshot_id,
            "timestamp": ts,
            "commit": commit,
            "summary": self._summary(report),
            "report": report.model_dump(
                by_alias=True, exclude_none=True
            ),
        }
        (self.snapshots_dir / filename).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        self._update_index(payload)
        return snapshot_id

    @staticmethod
    def _summary(report: AuditReport) -> dict:
        """Resumen compacto por módulo y severidades."""
        counts = {s: 0 for s in SEVERITIES}
        items = [
            report.vulnerabilities,
            report.secrets,
            report.iac_issues,
            report.cicd_issues,
            report.custom_issues,
            report.cloud_issues,
            report.llm_findings,
            report.recurrent_findings,
            report.metrics.dependency_vulnerabilities,
        ]
        for group in items:
            for item in group or []:
                sev = getattr(item, "severity", None)
                if isinstance(sev, Severity):
                    counts[sev.value] += 1
                elif sev and sev.value in counts:
                    counts[sev.value] += 1
        return {
            "total": sum(counts.values()),
            "perSeverity": counts,
            "modules": {
                "sast": len(report.vulnerabilities),
                "secrets": len(report.secrets),
                "iac": len(report.iac_issues),
                "cicd": len(report.cicd_issues),
                "custom": len(report.custom_issues),
                "cloud": len(report.cloud_issues),
                "llm": len(report.llm_findings),
                "deps": len(report.metrics.dependency_vulnerabilities),
            },
            "linesOfCode": report.metrics.lines_of_code,
        }

    def _update_index(self, snapshot: dict) -> None:
        index = {"version": 1, "snapshots": []}
        if self.index_path.exists():
            try:
                index = json.loads(self.index_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                index = {"version": 1, "snapshots": []}
        entry = {
            "id": snapshot["id"],
            "timestamp": snapshot["timestamp"],
            "commit": snapshot["commit"],
            "summary": snapshot["summary"],
        }
        index["snapshots"] = [
            s for s in index.get("snapshots", []) if s["id"] != entry["id"]
        ]
        index["snapshots"].append(entry)
        index["snapshots"].sort(key=lambda s: s["timestamp"])
        self.directory.mkdir(parents=True, exist_ok=True)
        tmp = self.index_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        tmp.replace(self.index_path)

    def list_snapshots(self) -> List[dict]:
        """Lista ordenada de snapshots (resúmenes, sin reportes completos)."""
        if not self.index_path.exists():
            return []
        try:
            index = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return sorted(index.get("snapshots", []), key=lambda s: s["timestamp"])

    def load_snapshot(self, snapshot_id: str) -> dict:
        """Carga un snapshot completo desde disco."""
        path = self.snapshots_dir / f"{snapshot_id}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    # --- comparativas ---

    def _finding_key(self, item: dict) -> str:
        """Clave estable de un hallazgo dentro del reporte exportado."""
        rule = item.get("rule") or item.get("type") or ""
        file = item.get("file") or ""
        name = item.get("name") or ""
        cve = ",".join(item.get("cveIds") or [])
        summary = item.get("summary") or item.get("title") or ""
        return "|".join([rule, file, name, cve, summary])

    def _finding_keys(self, report_export: dict) -> set:
        keys = set()
        groups = [
            report_export.get("vulnerabilities") or [],
            report_export.get("secrets") or [],
            report_export.get("iacIssues") or [],
            report_export.get("cicdIssues") or [],
            report_export.get("customIssues") or [],
            report_export.get("cloudIssues") or [],
            report_export.get("llmFindings") or [],
            report_export.get("recurrentFindings") or [],
            report_export.get("metrics", {}).get("dependencyVulnerabilities") or [],
        ]
        for group in groups:
            for item in group:
                keys.add(self._finding_key(item))
        return keys

    def delta(self, previous: dict, current: dict) -> dict:
        """Compara dos snapshots y devuelve nuevos / resueltos / persistentes."""
        prev_keys = self._finding_keys(previous.get("report", previous))
        curr_keys = self._finding_keys(current.get("report", current))
        resolved = sorted(prev_keys - curr_keys)
        new = sorted(curr_keys - prev_keys)
        persistent = sorted(prev_keys & curr_keys)
        return {
            "new": len(new),
            "resolved": len(resolved),
            "persistent": len(persistent),
            "newItems": new[:50],
            "resolvedItems": resolved[:50],
            "persistentItems": persistent[:50],
        }

    # --- alertas de recurrencia ---

    def recurrence_alerts(
        self,
        memory: Optional["MemoryStore"] = None,
        min_snapshots: int = 2,
        min_occurrences: int = 3,
        top: int = 10,
    ) -> List[dict]:
        """Ranking de hallazgos que persisten entre escaneos (nunca se arreglan).

        Combina cuántos snapshots contienen la clase de hallazgo con las
        ocurrencias acumuladas en memoria (si se pasa ``memory``). Devuelve la
        lista ordenada por severidad de recurrencia.
        """
        snapshots = self.list_snapshots()
        if len(snapshots) < 2:
            return []
        per_key: Dict[str, dict] = {}
        for snap in snapshots:
            full = self.load_snapshot(snap["id"])
            keys = self._finding_keys(full.get("report", full))
            for key in keys:
                info = per_key.setdefault(
                    key,
                    {"key": key, "snapshots": 0, "rule": "", "file": ""},
                )
                info["snapshots"] += 1
                info["commit"] = snap["commit"]
                parts = key.split("|")
                info["rule"] = parts[0]
                info["file"] = parts[1] if len(parts) > 1 else ""
        memory_lookup = {}
        if memory is not None:
            for entry in memory.entries():
                memory_lookup.setdefault(entry.rule, []).append(entry)
        alerts = []
        for info in per_key.values():
            sources = memory_lookup.get(info["rule"], [])
            occurrences = max((e.occurrences for e in sources), default=0)
            if (
                info["snapshots"] >= min_snapshots
                or occurrences >= min_occurrences
            ):
                start = sorted(e.first_seen for e in sources)[:1]
                alerts.append(
                    {
                        **info,
                        "occurrences": occurrences,
                        "firstSeen": start[0] if start else None,
                        "recommendation": next(
                            (e.recommendation for e in sources if e.recommendation),
                            "",
                        ),
                        "score": info["snapshots"] * 10 + occurrences,
                        "level": (
                            "ALERTA"
                            if info["snapshots"] >= min_snapshots
                            and occurrences >= min_occurrences
                            else "ATENCION"
                        ),
                    }
                )
        alerts.sort(key=lambda a: a["score"], reverse=True)
        return alerts[:top]

    def export_dashboard(
        self,
        out_path: Path,
        memory: Optional["MemoryStore"] = None,
    ) -> dict:
        """Escribe el resumen de evolución para el dashboard (JSON)."""
        snapshots = self.list_snapshots()
        if not snapshots:
            payload = {"snapshots": [], "deltas": [], "alerts": []}
        else:
            deltas = []
            for prev, curr in zip(snapshots[:-1], snapshots[1:]):
                prev_full = self.load_snapshot(prev["id"])
                curr_full = self.load_snapshot(curr["id"])
                d = self.delta(prev_full, curr_full)
                deltas.append(
                    {
                        "from": {"id": prev["id"], "timestamp": prev["timestamp"], "commit": prev["commit"]},
                        "to": {"id": curr["id"], "timestamp": curr["timestamp"], "commit": curr["commit"]},
                        **d,
                    }
                )
            payload = {
                "snapshots": snapshots,
                "deltas": deltas,
                "alerts": self.recurrence_alerts(memory),
                "latest": snapshots[-1],
            }
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return payload
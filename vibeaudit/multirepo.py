"""Comparativa multi-repo (item 4 del Sprint 6): ranking de riesgo normalizado.

Score por repo = suma ponderada de hallazgos por severidad
(CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0.5), con densidad por
miles de líneas para comparar proyectos de distinto tamaño.
"""

import csv
import html
import io
from datetime import datetime, timezone
from typing import Dict, List

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0.5}


def score_report(report) -> Dict:
    """Calcula el score de riesgo de un reporte y sus métricas base."""
    groups = [
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
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total = 0
    for group in groups:
        for item in group or []:
            severity = getattr(item, "severity", None)
            value = severity.value if hasattr(severity, "value") else str(severity or "")
            value = str(value).upper()
            if value in counts:
                counts[value] += 1
                total += 1
    weighted = sum(counts[s] * SEVERITY_WEIGHTS[s] for s in counts)
    loc = report.metrics.lines_of_code or 0
    density = round(weighted / max(1.0, loc / 1000.0), 2)
    return {
        "name": report.project.name,
        "repository_url": report.project.repository_url or "",
        "loc": loc,
        "total": total,
        "counts": counts,
        "score": weighted,
        "density": density,
    }


def ranking(results: List[Dict]) -> List[Dict]:
    """Ordena los resultados por score descendente con su posición."""
    ordered = sorted(results, key=lambda r: r["score"], reverse=True)
    for position, item in enumerate(ordered, start=1):
        item["position"] = position
    return ordered


def ranking_csv(results: List[Dict]) -> str:
    """CSV del ranking (posición, repo, score, densidad, total y por severidad)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["posicion", "repositorio", "score", "densidad_x_kloc", "total",
         "criticas", "altas", "medias", "bajas", "info", "loc"]
    )
    for item in ranking(results):
        writer.writerow(
            [
                item["position"], item["name"], item["score"], item["density"],
                item["total"], item["counts"]["CRITICAL"],
                item["counts"]["HIGH"], item["counts"]["MEDIUM"],
                item["counts"]["LOW"], item["counts"]["INFO"], item["loc"],
            ]
        )
    return buffer.getvalue()


def ranking_html(results: List[Dict]) -> str:
    """Tabla HTML del ranking, para el dashboard o informe."""
    rows = []
    colors = {"CRITICAL": "#d93025", "HIGH": "#ea8600", "MEDIUM": "#f2c300",
              "LOW": "#188038", "INFO": "#5f6368"}
    for item in ranking(results):
        badges = " ".join(
            f"<span style='background:{colors[s]};color:#fff;padding:1px 7px;"
            f"border-radius:9px;font-size:11px;'>{s}·{item['counts'][s]}</span>"
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            if item["counts"][s]
        )
        rows.append(
            f"<tr><td>{item['position']}</td><td><strong>{html.escape(item['name'])}</strong></td>"
            f"<td align='right'>{item['score']}</td>"
            f"<td align='right'>{item['density']}</td>"
            f"<td align='right'>{item['total']}</td><td>{badges}</td></tr>"
        )
    fecha = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Ranking de riesgo multi-repo — VibeAudit</title>
<style>
body {{ font-family: system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       max-width: 900px; margin: 0 auto; padding: 24px; color: #202124; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th {{ text-align: left; border-bottom: 1px solid #ccc; padding: 6px; }}
td {{ border-bottom: 1px solid #eee; padding: 6px; }}
</style>
</head>
<body>
<h1>Ranking de riesgo multi-repo</h1>
<p>Score ponderado por severidad (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0.5);
densidad = score por cada mil líneas. {fecha}</p>
<table>
<tr><th>#</th><th>Repositorio</th><th>Score</th><th>Densidad/KLOC</th>
<th>Total</th><th>Por severidad</th></tr>
{''.join(rows)}
</table>
<p><em>Generado por VibeAudit.</em></p>
</body>
</html>
"""

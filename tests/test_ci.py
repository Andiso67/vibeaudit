"""Tests del workflow de CI (GitHub Actions) que audita el repo por push."""

from pathlib import Path

import yaml

WORKFLOW = (
    Path(__file__).parent.parent / ".github" / "workflows" / "audit.yml"
)


def _load():
    """Carga el workflow normalizando 'on:' (PyYAML 1.1 lo convierte en True)."""
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return {("on" if key is True else key): value for key, value in data.items()}


def test_workflow_existe_y_es_yaml_valido():
    assert WORKFLOW.exists(), "falta .github/workflows/audit.yml"
    data = _load()
    assert data["name"] == "VibeAudit"
    assert "push" in data["on"]
    assert "pull_request" in data["on"]
    assert "workflow_dispatch" in data["on"]


def test_workflow_ejecuta_scan_solo_lectura():
    data = _load()
    job = data["jobs"]["audit"]
    assert job["runs-on"] == "ubuntu-latest"

    pasos = job["steps"]
    comandos = " ".join(
        paso.get("run", "") for paso in pasos if isinstance(paso, dict)
    )
    assert "actions/checkout" in str(pasos)
    assert "vibeaudit scan --path ." in comandos
    assert "--sonar-json sonar-issues.json" in comandos
    assert "--history .vibeaudit-history" in comandos
    assert "actions/upload-artifact" in str(pasos)


def test_workflow_no_escribe_en_el_repo_cliente():
    """El scan en CI usa --path (solo lectura); los reportes quedan en artefactos."""
    data = _load()
    pasos = data["jobs"]["audit"]["steps"]
    scan = [p for p in pasos if "vibeaudit scan" in p.get("run", "")]
    assert len(scan) == 1
    assert "--path ." in scan[0]["run"]
    assert "git push" not in scan[0]["run"]
    assert "git commit" not in scan[0]["run"]

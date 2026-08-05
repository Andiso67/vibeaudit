"""Tests del informe de remediación (solo diffs propuestos, nunca aplica)."""

import json

from typer.testing import CliRunner

from vibeaudit.cli import app
from vibeaudit.models import (
    AuditReport,
    DependencyVulnerability,
    Metrics,
    ProjectMetadata,
    Secret,
    Severity,
    Vulnerability,
)
from vibeaudit.remediate import (
    ACTION_COMMAND,
    ACTION_DIFF,
    ACTION_MANUAL,
    build_proposals,
    proposals_json,
    proposals_markdown,
    proposals_patch,
)

runner = CliRunner()


def _report() -> AuditReport:
    return AuditReport(
        project=ProjectMetadata(name="demo"),
        secrets=[
            Secret(type="aws-access-token", file=".env", line=2, severity=Severity.HIGH)
        ],
        vulnerabilities=[
            Vulnerability(
                rule="python.eval.usage", file="app.py", line=4,
                severity=Severity.CRITICAL, snippet="eval(x)",
            )
        ],
        metrics=Metrics(
            dependency_vulnerabilities=[
                DependencyVulnerability(
                    name="lodash",
                    version="4.17.20",
                    ecosystem="npm",
                    direct=False,
                    severity=Severity.HIGH,
                    cve_ids=["CVE-2021-23337"],
                    fixed_version="4.17.21",
                )
            ]
        ),
    )


def test_propuesta_secret_genera_diff(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = repo / ".env"
    env.write_text("HOST=localhost\nAWS_ACCESS_KEY_ID=AKIA1234567890ABCD\n")
    proposals = build_proposals(_report(), source_dir=repo)
    secret = next(p for p in proposals if p["kind"] == "secrets")
    assert secret["action"] == ACTION_DIFF
    assert secret["diff"] is not None
    assert "-AWS_ACCESS_KEY_ID=AKIA1234567890ABCD" in secret["diff"]
    assert "+AWS_ACCESS_KEY_ID" not in secret["diff"]


def test_propuesta_sin_source_no_genera_diff():
    proposals = build_proposals(_report(), source_dir=None)
    secret = next(p for p in proposals if p["kind"] == "secrets")
    assert secret["diff"] is None
    assert "no disponible" in secret["nota"]


def test_sast_es_revision_manual():
    proposals = build_proposals(_report(), source_dir=None)
    sast = next(p for p in proposals if p["kind"] == "sast")
    assert sast["action"] == ACTION_MANUAL
    assert sast["diff"] is None


def test_deps_proponen_comando():
    proposals = build_proposals(_report(), source_dir=None)
    dep = next(p for p in proposals if p["kind"] == "deps")
    assert dep["action"] == ACTION_COMMAND
    assert "npm install lodash@4.17.21" in dep["command"]
    assert dep["nota"] == "CVE-2021-23337"


def test_patch_json_md_consistentes():
    proposals = build_proposals(_report(), source_dir=None)
    patch = proposals_patch(proposals)
    assert patch == "# Sin diffs propuestos (revisar comandos y notas).\n"
    data = json.loads(proposals_json(proposals))
    assert len(data) == len(proposals)
    md = proposals_markdown(proposals)
    assert "Informe de remediación" in md
    assert "npm install lodash@4.17.21" in md
    assert "Solo informativo" in md or "automáticamente" in md


def test_cli_remediate_genera_informes(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("HOST=localhost\nAWS_ACCESS_KEY_ID=AKIA1234567890\n")
    reporte = tmp_path / "audit-report.json"
    reporte.write_text(
        json.dumps(_report().model_dump(by_alias=True, exclude_none=True)),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "remediate",
            str(reporte),
            "--source",
            str(repo),
            "--output",
            str(tmp_path / "remediaciones"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "remediaciones.patch").exists()
    assert (tmp_path / "remediaciones.json").exists()
    assert (tmp_path / "remediaciones.md").exists()
    patch = (tmp_path / "remediaciones.patch").read_text()
    assert "diff --git" in patch
    assert "-AWS_ACCESS_KEY_ID" in patch  # la línea se elimina (prefijo -)
    assert "+AWS_ACCESS_KEY_ID" not in patch  # nunca queda como línea añadida
    assert "revisa los diffs" in result.output

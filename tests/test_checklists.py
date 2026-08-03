"""Tests del paquete de checklists YAML (ítem 2): carga, validación y mapeo."""

import yaml
import pytest

from pathlib import Path

from vibeaudit.checklists import (
    BUNDLE_DIR,
    ChecklistBundleError,
    applied_checklists,
    load_checklist_file,
    load_checklists,
    match_finding,
    match_report,
)
from vibeaudit.llm import STARTER_CHECKLIST
from vibeaudit.models import (
    AuditReport,
    ChecklistItem,
    Metrics,
    ProjectMetadata,
    Severity,
    Vulnerability,
)


def make_report(iac_rules=()):
    iac = [
        Vulnerability(rule=rule_id, file="infra/main.tf", line=1, severity=Severity.HIGH)
        for rule_id in iac_rules
    ]
    return AuditReport(
        project=ProjectMetadata(name="demo"),
        vulnerabilities=[],
        iac_issues=iac,
        metrics=Metrics(lines_of_code=10),
    )


class TestLoader:
    def test_bundle_no_vacio_y_con_frameworks(self):
        items = load_checklists()
        assert len(items) > 0
        frameworks = {i.framework for i in items}
        assert "12-Factor" in frameworks
        assert "OWASP" in frameworks
        assert "AWS WAF" in frameworks

    def test_bundle_incluye_ids_esperados(self):
        ids = [i.id for i in load_checklists()]
        for expected in (
            "12-factor.config",
            "owasp.injection",
            "owasp.sensitive-data",
            "aws.iam-least-privilege",
        ):
            assert expected in ids

    def test_ids_unicos_en_cada_archivo(self):
        for path in BUNDLE_DIR.glob("*.yaml"):
            assert len(load_checklist_file(path)) > 0

    def test_checklist_file_sin_items_error(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("name: SinItems\n")
        with pytest.raises(ChecklistBundleError):
            load_checklist_file(f)

    def test_checklist_file_item_invalido_error(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(yaml.safe_dump({"name": "x", "items": [{"id": "", "title": "t"}]}))
        with pytest.raises(ChecklistBundleError):
            load_checklist_file(f)

    def test_checklist_file_yaml_invalido_error(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("items: [\n  - id: x\n")
        with pytest.raises(ChecklistBundleError):
            load_checklist_file(f)

    def test_load_checklists_desde_directorio_personalizado(self, tmp_path):
        (tmp_path / "custom.yaml").write_text(
            yaml.safe_dump(
                {
                    "name": "Custom",
                    "items": [{"id": "c.1", "title": "T", "description": "D"}],
                }
            )
        )
        items = load_checklists(bundle_dir=tmp_path)
        assert [i.id for i in items] == ["c.1"]

    def test_starter_checklist_es_el_bundle(self):
        assert STARTER_CHECKLIST == load_checklists()


class TestMapping:
    def test_match_por_section_sin_reglas(self):
        item = next(i for i in load_checklists() if i.id == "12-factor.dependencies")
        assert match_finding(item, "deps")
        assert not match_finding(item, "sast")

    def test_match_glob_de_regla(self):
        item = next(i for i in load_checklists() if i.id == "aws.iam-least-privilege")
        assert match_finding(item, "iac", "CKV_AWS_20", Severity.HIGH)
        assert not match_finding(item, "iac", "CKV_AWS_999", Severity.HIGH)
        assert not match_finding(item, "sast", "CKV_AWS_20", Severity.HIGH)

    def test_match_min_severity(self):
        item = next(i for i in load_checklists() if i.id == "owasp.vulnerable-deps")
        assert match_finding(item, "deps", None, Severity.HIGH)
        assert not match_finding(item, "deps", None, Severity.LOW)

    def test_item_sin_match_nunca_cuenta(self):
        item = ChecklistItem(id="x.1", title="T", description="D", framework="Custom")
        assert not match_finding(item, "sast", "r1", Severity.HIGH)

    def test_match_report_mapea_ckv_aws(self):
        items = load_checklists()
        report = make_report(iac_rules=["CKV_AWS_20", "CKV_AWS_18"])
        matched = match_report(items, report)
        assert matched.get("aws.iam-least-privilege") == 2
        assert "aws.encryption" not in matched

    def test_applied_checklists_agrupa_por_framework(self):
        report = make_report(iac_rules=["CKV_AWS_20"])
        applied = applied_checklists(load_checklists(), report)
        names = {a.name for a in applied}
        assert {"12-Factor", "OWASP", "AWS WAF"} <= names
        aws = next(a for a in applied if a.name == "AWS WAF")
        assert aws.item_count == 4
        assert aws.matched_findings >= 1
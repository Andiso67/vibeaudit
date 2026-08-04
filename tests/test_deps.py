"""Tests del DependencyScanner (parseo de lockfiles y consulta OSV)."""

import json

import pytest

from vibeaudit.models import Severity
from vibeaudit.scanners.deps import Dependency, DependencyScanner

NPM_LOCKFILE = {
    "name": "demo",
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"axios": "^1.0.0"}, "devDependencies": {"eslint": "^8.0.0"}},
        "node_modules/axios": {"version": "1.6.0"},
        "node_modules/eslint": {"version": "8.57.0"},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/@babel/core": {"version": "7.24.0"},
        "node_modules/axios/node_modules/follow-redirects": {"version": "1.15.4"},
    },
}

POETRY_LOCK = """[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP"
optional = false
python-versions = ">=3.7"

[package.dependencies]
certifi = ">=2017.4.17"

[[package]]
name = "certifi"
version = "2024.2.2"
description = "Certificates"
optional = false
python-versions = ">=3.6"

[package.dependencies]
"""

GO_SUM = """github.com/aws/aws-sdk-go v1.44.0 h1:abc123=
github.com/aws/aws-sdk-go v1.44.0/go.mod h1:xyz=
gopkg.in/yaml.v3 v3.0.1 h1:xyz=
"""

REQUIREMENTS = """requests==2.31.0
# comentario
flask>=2.0
Django==4.2.1
-e . 
"""


class TestParseLockfiles:
    def test_parse_npm_lockfile(self, tmp_path):
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps(NPM_LOCKFILE))
        deps = DependencyScanner(tmp_path)._parse_npm_lockfile(str(lockfile))

        by_name = {d.name: d for d in deps}
        assert by_name["axios"].version == "1.6.0"
        assert by_name["axios"].direct is True
        assert by_name["axios"].dependency_type == "production"
        assert by_name["eslint"].dependency_type == "dev"
        assert by_name["lodash"].direct is False
        assert by_name["@babel/core"].version == "7.24.0"
        assert by_name["follow-redirects"].version == "1.15.4"

    def test_parse_pnpm_lockfile(self, tmp_path):
        lockfile = tmp_path / "pnpm-lock.yaml"
        lockfile.write_text(
            "lockfileVersion: '9.0'\n"
            "packages:\n"
            "\n"
            "  '@alloc/quick-lru@5.2.0':\n"
            "    resolution: {integrity: sha512-x}\n"
            "\n"
            "  'next@14.2.5':\n"
            "    resolution: {integrity: sha512-y}\n"
            "    dependencies:\n"
            "      '@next/env': 14.2.5\n"
            "\n"
            "  '/legacy-dep@1.0.0':\n"
            "    resolution: {integrity: sha512-z}\n"
            "\n"
            "snapshots:\n"
            "  'next@14.2.5': {}\n"
        )
        deps = DependencyScanner(tmp_path)._parse_pnpm_lockfile(str(lockfile))

        assert len(deps) == 3
        assert deps[0].name == "@alloc/quick-lru"
        assert deps[0].version == "5.2.0"
        assert deps[1].name == "next"
        assert deps[1].version == "14.2.5"
        assert deps[2].name == "legacy-dep"
        assert deps[2].version == "1.0.0"

    def test_parse_poetry_lockfile(self, tmp_path):
        lockfile = tmp_path / "poetry.lock"
        lockfile.write_text(POETRY_LOCK)
        deps = DependencyScanner(tmp_path)._parse_poetry_lockfile(str(lockfile))

        assert len(deps) == 2
        assert {d.name for d in deps} == {"requests", "certifi"}
        assert deps[0].version == "2.31.0"

    def test_parse_requirements(self, tmp_path):
        lockfile = tmp_path / "requirements.txt"
        lockfile.write_text(REQUIREMENTS)
        deps = DependencyScanner(tmp_path)._parse_requirements(str(lockfile))

        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"
        assert deps[1].name == "Django"

    def test_parse_go_sum(self, tmp_path):
        lockfile = tmp_path / "go.sum"
        lockfile.write_text(GO_SUM)
        deps = DependencyScanner(tmp_path)._parse_go_sum(str(lockfile))

        assert len(deps) == 2
        assert deps[0].name == "github.com/aws/aws-sdk-go"
        assert deps[0].version == "v1.44.0"

    def test_find_dependencies_recolecta_lockfiles(self, tmp_path):
        (tmp_path / "package-lock.json").write_text(json.dumps(NPM_LOCKFILE))
        (tmp_path / "requirements.txt").write_text(REQUIREMENTS)
        scanner = DependencyScanner(tmp_path)
        deps = scanner._find_dependencies()

        assert len(deps) == 7
        assert {d.lockfile for d in deps} == {"package-lock.json", "requirements.txt"}

    def test_sin_lockfiles_devuelve_vacio(self, tmp_path):
        (tmp_path / "readme.md").write_text("hola")
        assert DependencyScanner(tmp_path)._find_dependencies() == []

    def test_escanea_github_pero_no_git(self, tmp_path):
        (tmp_path / ".github" / "actions" / "setup").mkdir(parents=True)
        (tmp_path / ".github" / "actions" / "setup" / "package-lock.json").write_text(
            json.dumps(NPM_LOCKFILE)
        )
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "package-lock.json").write_text(json.dumps(NPM_LOCKFILE))
        deps = DependencyScanner(tmp_path)._find_dependencies()

        lockfiles = {d.lockfile for d in deps}
        assert ".github/actions/setup/package-lock.json" in lockfiles
        assert ".git/package-lock.json" not in lockfiles

    def test_lockfile_roto_no_crashea(self, tmp_path, capsys):
        (tmp_path / "package-lock.json").write_text("{json invalido")
        (tmp_path / "requirements.txt").write_text(REQUIREMENTS)
        scanner = DependencyScanner(tmp_path)
        deps = scanner._find_dependencies()
        assert len(deps) == 2
        assert "no se pudo parsear" in capsys.readouterr().out


OSV_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "CVE-2023-40014",
                    "summary": "Prototype Pollution in axios",
                    "details": "axios before 1.6.0 is vulnerable...",
                    "aliases": ["GHSA-4x4g-32rx-1234"],
                    "published": "2023-08-14T00:00:00Z",
                    "modified": "2024-01-10T00:00:00Z",
                    "references": [
                        {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-4x4g-32rx-1234"}
                    ],
                    "database_specific": {
                        "severity": "HIGH",
                        "cwe_ids": ["CWE-1321"],
                    },
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": "axios",
                                "purl": "pkg:npm/axios@1.6.0",
                            },
                            "severity": [{"type": "CVSS_V3", "score": "8.8"}],
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "1.6.1"},
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        },
        None,
    ]
}


class TestOsvQuery:
    def test_build_vulnerability_completo(self):
        dep = Dependency(name="axios", version="1.6.0", ecosystem="npm", direct=True)
        vuln = OSV_RESPONSE["results"][0]["vulns"][0]
        result = DependencyScanner._build_vulnerability(dep, vuln)

        assert result.name == "axios"
        assert result.cve_ids == ["CVE-2023-40014"]
        assert result.aliases == ["GHSA-4x4g-32rx-1234"]
        assert result.cwe_ids == ["CWE-1321"]
        assert result.severity == Severity.HIGH
        assert result.cvss_score == 8.8
        assert result.fixed_version == "1.6.1"
        assert result.is_fix_available is True
        assert result.affected_range == ">=0,<1.6.1"
        assert result.purl == "pkg:npm/axios@1.6.0"
        assert result.references == ["https://github.com/advisories/GHSA-4x4g-32rx-1234"]
        assert result.published == "2023-08-14T00:00:00Z"

    def test_severidad_desde_cvss_sin_database_specific(self):
        dep = Dependency(name="pkg", version="1.0.0", ecosystem="npm")
        vuln = {
            "id": "CVE-2024-100",
            "affected": [
                {"package": {"ecosystem": "npm", "name": "pkg"},
                 "severity": [{"type": "CVSS_V3", "score": "9.8"}]}
            ],
        }
        result = DependencyScanner._build_vulnerability(dep, vuln)
        assert result.severity == Severity.CRITICAL
        assert result.cvss_score == 9.8

    def test_sin_fix_ni_severidad_default_high(self):
        dep = Dependency(name="pkg", version="1.0.0", ecosystem="npm")
        vuln = {"id": "CVE-2024-200", "affected": [{"package": {"name": "pkg"}}]}
        result = DependencyScanner._build_vulnerability(dep, vuln)
        assert result.is_fix_available is False
        assert result.severity == Severity.HIGH
        assert result.cve_ids == ["CVE-2024-200"]
        assert result.aliases == []

    def test_scan_consulta_osv_y_mapea_resultados(self, monkeypatch, tmp_path):
        (tmp_path / "package-lock.json").write_text(json.dumps(NPM_LOCKFILE))
        summary = OSV_RESPONSE["results"][0]["vulns"][0]
        detail = dict(OSV_RESPONSE["results"][0]["vulns"][0])

        monkeypatch.setattr(DependencyScanner, "_post_batch", lambda q: [{"vulns": [summary]}])
        monkeypatch.setattr(DependencyScanner, "_get_vuln_detail", lambda _: detail)
        results = DependencyScanner(tmp_path).scan()

        assert len(results) == 1
        assert results[0].name == "axios"

    def test_scan_dedup_por_id_y_mantiene_dep(self, monkeypatch, tmp_path):
        (tmp_path / "package-lock.json").write_text(json.dumps(NPM_LOCKFILE))
        summary = {"id": "GHSA-abc", "modified": "2023-01-01T00:00:00Z"}
        detail = {
            "id": "GHSA-abc",
            "aliases": ["CVE-2023-100"],
            "affected": [
                {"package": {"name": "axios", "ecosystem": "npm"}, "ranges": []}
            ],
        }

        def fake_post(queries):
            return [{"vulns": [summary]} for _ in queries]

        monkeypatch.setattr(DependencyScanner, "_post_batch", fake_post)
        monkeypatch.setattr(DependencyScanner, "_get_vuln_detail", lambda _: detail)
        results = DependencyScanner(tmp_path).scan()

        assert len(results) == 1
        assert results[0].cve_ids == ["CVE-2023-100"]

    def test_scan_sin_respuesta_osv_devuelve_vacio(self, monkeypatch, tmp_path):
        (tmp_path / "package-lock.json").write_text(json.dumps(NPM_LOCKFILE))
        monkeypatch.setattr(DependencyScanner, "_post_batch", lambda q: None)
        assert DependencyScanner(tmp_path).scan() == []

    def test_dedup_dependencias_repetidas(self):
        deps = [
            Dependency(name="a", version="1.0.0", ecosystem="npm", lockfile="x"),
            Dependency(name="a", version="1.0.0", ecosystem="npm", lockfile="x"),
            Dependency(name="a", version="1.0.0", ecosystem="npm", lockfile="y"),
            Dependency(name="b", version="1.0.0", ecosystem="npm", lockfile="x"),
        ]
        result = DependencyScanner._dedupe(deps)
        assert len(result) == 3


class TestCvssVector:
    def test_parse_vector_cvss_3_1(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
        assert DependencyScanner._parse_cvss_vector(vector) == pytest.approx(5.3)

    def test_parse_vector_critico(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert DependencyScanner._parse_cvss_vector(vector) == pytest.approx(9.8)

    def test_parse_vector_scope_changed(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
        assert DependencyScanner._parse_cvss_vector(vector) == pytest.approx(9.9)

    def test_parse_vector_invalido_devuelve_none(self):
        assert DependencyScanner._parse_cvss_vector("CVSS:3.1/AV:Z/AC:L") is None

    def test_extract_score_numerico_directo(self):
        items = [{"type": "CVSS_V3", "score": "8.8"}]
        assert DependencyScanner._extract_cvss_score(items) == 8.8

    def test_extract_score_desde_vector(self):
        items = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        assert DependencyScanner._extract_cvss_score(items) == pytest.approx(9.8)


class TestSelectAffected:
    def test_selecciona_rango_que_contiene_la_version(self):
        vuln = {
            "affected": [
                {"package": {"name": "pkg"}, "ranges": [
                    {"type": "SEMVER", "events": [
                        {"introduced": "0"}, {"fixed": "1.5.0"}]}
                ]},
                {"package": {"name": "pkg"}, "ranges": [
                    {"type": "SEMVER", "events": [
                        {"introduced": "1.5.0"}, {"fixed": "2.0.0"}]}
                ]},
            ]
        }
        result = DependencyScanner._select_affected(vuln, "1.8.0")
        assert result["ranges"][0]["events"][0]["introduced"] == "1.5.0"

    def test_sin_match_usa_el_primero(self):
        vuln = {"affected": [{"package": {"name": "pkg"}}]}
        assert DependencyScanner._select_affected(vuln, "1.0.0") == vuln["affected"][0]

    def test_semver_lt(self):
        assert DependencyScanner._semver_lt("1.0.0", "1.0.1") is True
        assert DependencyScanner._semver_lt("1.0.1", "1.0.1") is False
        assert DependencyScanner._semver_lt("1.9.0", "1.10.0") is True

    def test_dedupe_conserva_el_mas_severo(self):
        from vibeaudit.models import DependencyVulnerability

        low = DependencyVulnerability(
            name="lodash", ecosystem="npm", version="4.17.20",
            cve_ids=["CVE-2021-23337"], severity=Severity.MEDIUM,
            cvss_score=5.3, fixed_version="4.17.21", direct=False,
        )
        high = DependencyVulnerability(
            name="lodash", ecosystem="npm", version="4.17.20",
            cve_ids=["CVE-2021-23337"], severity=Severity.HIGH,
            cvss_score=8.1, fixed_version="4.17.21", direct=False,
        )
        other = DependencyVulnerability(
            name="axios", ecosystem="npm", version="0.21.1",
            cve_ids=["CVE-2020-100"], severity=Severity.CRITICAL, direct=False,
        )
        result = DependencyScanner._dedupe_vulnerabilities([low, high, other])
        assert len(result) == 2
        by_name = {v.name: v for v in result}
        assert by_name["lodash"].severity == Severity.HIGH
        assert by_name["axios"].severity == Severity.CRITICAL

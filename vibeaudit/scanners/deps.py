"""Análisis de dependencias: parseo de lockfiles y consulta de vulnerabilidades (OSV)."""

import json
import math
import os
import re
import subprocess
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.console import Console

from vibeaudit.models import DependencyVulnerability, Severity

console = Console()

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_TIMEOUT_SECONDS = 15

# Mapeo de ecosistema OSV por tipo de lockfile (solo formatos con parser)
LOCKFILE_ECOSYSTEMS: Dict[str, str] = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "poetry.lock": "PyPI",
    "requirements.txt": "PyPI",
    "Pipfile.lock": "PyPI",
    "go.sum": "Go",
    "Gemfile.lock": "RubyGems",
    "composer.lock": "Packagist",
    "Cargo.lock": "crates.io",
}

# Extensiones/frameworks que marcan dependencias de desarrollo por lockfile
DEV_SECTIONS = {
    "package-lock.json": ("devDependencies",),
    "yarn.lock": (),
    "poetry.lock": ("dev",),
    "Pipfile.lock": ("develop",),
}

# Paquetes en sección raíz (npm) que se consideran directos
NPM_ROOT_DEPS_SECTIONS = ("dependencies", "devDependencies")


@dataclass
class Dependency:
    """Dependencia detectada en un lockfile."""

    name: str
    version: str
    ecosystem: str
    direct: bool = False
    dependency_type: str = "unknown"
    lockfile: str = ""
    extra: dict = field(default_factory=dict)


class DependencyScanner:
    """Detecta dependencias en lockfiles y consulta OSV por CVEs."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    def scan(self) -> List[DependencyVulnerability]:
        """Devuelve las vulnerabilidades de dependencias detectadas."""
        dependencies = self._find_dependencies()
        if not dependencies:
            return []
        return self._query_osv(dependencies)

    def _find_dependencies(self) -> List[Dependency]:
        """Localiza y parsea los lockfiles del repositorio."""
        dependencies: List[Dependency] = []
        for root, _dirs, files in os.walk(self.repo_path):
            if ".git" in Path(root).parts:
                continue
            for filename in files:
                if filename in LOCKFILE_ECOSYSTEMS:
                    full_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(full_path, self.repo_path)
                    try:
                        found = self._parse_lockfile(full_path, filename)
                        for dep in found:
                            dep.lockfile = rel_path
                        dependencies.extend(found)
                    except (OSError, ValueError, json.JSONDecodeError):
                        console.print(
                            f"[bold yellow]Advertencia:[/] no se pudo parsear "
                            f"[cyan]{rel_path}[/]"
                        )
        return self._dedupe(dependencies)

    @staticmethod
    def _dedupe(dependencies: List[Dependency]) -> List[Dependency]:
        """Elimina dependencias repetidas (mismo lockfile, nombre y versión)."""
        seen = set()
        result = []
        for dep in dependencies:
            key = (dep.lockfile, dep.name, dep.version)
            if key not in seen:
                seen.add(key)
                result.append(dep)
        return result

    def _parse_lockfile(self, full_path: str, filename: str) -> List[Dependency]:
        """Delega el parseo según el tipo de lockfile."""
        if filename == "package-lock.json":
            return self._parse_npm_lockfile(full_path)
        if filename == "yarn.lock":
            return self._parse_yarn_lockfile(full_path)
        if filename == "poetry.lock":
            return self._parse_poetry_lockfile(full_path)
        if filename == "requirements.txt":
            return self._parse_requirements(full_path)
        if filename == "go.sum":
            return self._parse_go_sum(full_path)
        if filename == "Gemfile.lock":
            return self._parse_gemfile_lock(full_path)
        if filename == "Cargo.lock":
            return self._parse_cargo_lock(full_path)
        if filename == "composer.lock":
            return self._parse_composer_lock(full_path)
        if filename == "Pipfile.lock":
            return self._parse_pipfile_lock(full_path)
        return []

    def _parse_npm_lockfile(self, full_path: str) -> List[Dependency]:
        """Parsea package-lock.json (v2/v3)."""
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        # Dependencias directas declaradas en la sección raíz
        root = data.get("packages", {}).get("") or {}
        direct_names = set()
        dev_names = set()
        for section in NPM_ROOT_DEPS_SECTIONS:
            for name in (root.get(section) or {}).keys():
                if section == "devDependencies":
                    dev_names.add(name)
                else:
                    direct_names.add(name)

        dependencies: List[Dependency] = []
        packages = data.get("packages", {}) or {}
        for path, info in packages.items():
            if not path or not isinstance(info, dict):
                continue
            name = info.get("name")
            if not name:
                # El nombre se deriva del path (ej. node_modules/foo, node_modules/@scope/foo)
                name = path.split("node_modules/")[-1]
                if path.count("/") >= 2 and name.startswith("@"):
                    pass  # scoped packages ya traen @scope/name en el path
                elif path.count("/") >= 2 and not name.startswith("@"):
                    # Nested: node_modules/a/node_modules/b → solo el último
                    name = path.rsplit("node_modules/", 1)[-1]
            version = info.get("version")
            if not version:
                continue
            is_dev = name in dev_names
            dependencies.append(
                Dependency(
                    name=name,
                    version=str(version),
                    ecosystem="npm",
                    direct=name in direct_names or is_dev,
                    dependency_type="dev" if is_dev else "production",
                )
            )
        return dependencies

    def _parse_yarn_lockfile(self, full_path: str) -> List[Dependency]:
        """Parsea yarn.lock (formato clásico, bloques 'name@version:')."""
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        dependencies: List[Dependency] = []
        for match in re.finditer(r'^([\w@.\-/]+)@([^:]+):\n', content, re.MULTILINE):
            dep_spec, version = match.group(1), match.group(2)
            version = version.strip().strip('"')
            if not version or version in ("unknown", "range"):
                continue
            name = dep_spec.rsplit("@", 1)[0] if "@" in dep_spec else dep_spec
            dependencies.append(
                Dependency(name=name, version=version, ecosystem="npm")
            )
        return dependencies

    def _parse_poetry_lockfile(self, full_path: str) -> List[Dependency]:
        """Parsea poetry.lock (TOML)."""
        content = Path(full_path).read_text(encoding="utf-8", errors="ignore")
        dependencies: List[Dependency] = []
        current: Optional[dict] = None
        for line in content.splitlines():
            stripped = line.strip()
            if line.startswith("[[package]]"):
                if current and current.get("name") and current.get("version"):
                    dependencies.append(
                        Dependency(
                            name=current["name"],
                            version=current["version"],
                            ecosystem="PyPI",
                        )
                    )
                current = {}
            elif current is not None:
                if stripped.startswith("name ="):
                    current["name"] = stripped.split("=", 1)[1].strip().strip('"')
                elif stripped.startswith("version ="):
                    current["version"] = stripped.split("=", 1)[1].strip().strip('"')
        if current and current.get("name") and current.get("version"):
            dependencies.append(
                Dependency(
                    name=current["name"],
                    version=current["version"],
                    ecosystem="PyPI",
                )
            )
        return dependencies

    def _parse_requirements(self, full_path: str) -> List[Dependency]:
        """Parsea requirements.txt (líneas nombre==version)."""
        dependencies: List[Dependency] = []
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                match = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([^\s;]+)", line)
                if not match:
                    continue
                name = match.group(1)
                version = match.group(2).rstrip(",")
                if name.startswith("git+") or "://" in name:
                    continue
                dependencies.append(
                    Dependency(
                        name=name.split("[")[0],
                        version=version,
                        ecosystem="PyPI",
                    )
                )
        return dependencies

    def _parse_go_sum(self, full_path: str) -> List[Dependency]:
        """Parsea go.sum (líneas 'modulo version hash')."""
        dependencies: List[Dependency] = []
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                module, version = parts[0], parts[1]
                if version.endswith("/go.mod"):
                    continue
                if "!" in version:
                    continue
                dependencies.append(
                    Dependency(
                        name=module,
                        version=version,
                        ecosystem="Go",
                    )
                )
        return dependencies

    def _parse_gemfile_lock(self, full_path: str) -> List[Dependency]:
        """Parsea Gemfile.lock (sección GEM remote)."""
        dependencies: List[Dependency] = []
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = re.match(r"^\s{4}([\w\-]+) \(([\w.\-]+)\)$", line)
                if match:
                    dependencies.append(
                        Dependency(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="RubyGems",
                        )
                    )
        return dependencies

    def _parse_cargo_lock(self, full_path: str) -> List[Dependency]:
        """Parsea Cargo.lock (TOML, bloques [[package]])."""
        content = Path(full_path).read_text(encoding="utf-8", errors="ignore")
        dependencies: List[Dependency] = []
        current: Optional[dict] = None
        for line in content.splitlines():
            if line.startswith("[[package]]"):
                if current and current.get("name") and current.get("version"):
                    dependencies.append(
                        Dependency(
                            name=current["name"],
                            version=current["version"],
                            ecosystem="crates.io",
                        )
                    )
                current = {}
            elif current is not None:
                stripped = line.strip()
                if stripped.startswith("name ="):
                    current["name"] = stripped.split("=", 1)[1].strip().strip('"')
                elif stripped.startswith("version ="):
                    current["version"] = stripped.split("=", 1)[1].strip().strip('"')
        if current and current.get("name") and current.get("version"):
            dependencies.append(
                Dependency(
                    name=current["name"],
                    version=current["version"],
                    ecosystem="crates.io",
                )
            )
        return dependencies

    def _parse_composer_lock(self, full_path: str) -> List[Dependency]:
        """Parsea composer.lock (JSON)."""
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        dependencies: List[Dependency] = []
        for package in data.get("packages", []) or []:
            name = package.get("name")
            version = (package.get("version") or "").lstrip("v")
            if name and version:
                dependencies.append(
                    Dependency(name=name, version=version, ecosystem="Packagist")
                )
        return dependencies

    def _parse_pipfile_lock(self, full_path: str) -> List[Dependency]:
        """Parsea Pipfile.lock (JSON con secciones default/develop)."""
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        dependencies: List[Dependency] = []
        for section in ("default", "develop"):
            for name, info in (data.get(section) or {}).items():
                version = (info or {}).get("version", "")
                match = re.search(r"==([\w.\-]+)", version)
                if not match:
                    continue
                dependencies.append(
                    Dependency(
                        name=name,
                        version=match.group(1),
                        ecosystem="PyPI",
                        direct=True,
                        dependency_type="dev" if section == "develop" else "production",
                    )
                )
        return dependencies

    def _query_osv(self, dependencies: List[Dependency]) -> List[DependencyVulnerability]:
        """Consulta OSV: batch de IDs y luego el detalle de cada advisory."""
        if not dependencies:
            return []

        queries = [
            {"package": {"name": dep.name, "ecosystem": dep.ecosystem},
             "version": dep.version}
            for dep in dependencies
        ]

        results = DependencyScanner._post_batch(queries)
        if not results:
            return []

        id_to_dep: dict = {}
        for dep, result in zip(dependencies, results):
            if not result or "vulns" not in result:
                continue
            for entry in result["vulns"]:
                if not isinstance(entry, dict) or not entry.get("id"):
                    continue
                id_to_dep.setdefault(entry["id"], dep)

        vulnerabilities: List[DependencyVulnerability] = []
        for vuln_id, dep in id_to_dep.items():
            detail = DependencyScanner._get_vuln_detail(vuln_id)
            if not detail:
                continue
            vulnerability = self._build_vulnerability(dep, detail)
            if vulnerability:
                vulnerabilities.append(vulnerability)
        return DependencyScanner._dedupe_vulnerabilities(vulnerabilities)

    @staticmethod
    def _dedupe_vulnerabilities(
        vulnerabilities: List[DependencyVulnerability],
    ) -> List[DependencyVulnerability]:
        """Elimina advisories repetidos del mismo CVE, conservando el más severo."""
        best: Dict[tuple, DependencyVulnerability] = {}
        for vulnerability in vulnerabilities:
            identifiers = tuple(vulnerability.cve_ids or vulnerability.aliases or [vulnerability.summary])
            key = (vulnerability.name, identifiers)
            if key not in best or DependencyScanner._rank(vulnerability) > DependencyScanner._rank(best[key]):
                best[key] = vulnerability
        return sorted(best.values(), key=lambda v: (v.name.lower(), v.version))

    @staticmethod
    def _rank(vulnerability: DependencyVulnerability) -> float:
        """Ponderación de severidad para quedarse con el advisory más grave."""
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        score = order.get(vulnerability.severity.value, 0)
        if vulnerability.cvss_score is not None:
            score += vulnerability.cvss_score / 10.0
        if vulnerability.is_fix_available:
            score += 0.1
        return score

    @staticmethod
    def _get_vuln_detail(vuln_id: str) -> Optional[dict]:
        """Trae el advisory completo de OSV para un ID."""
        try:
            request = urllib.request.Request(f"{OSV_VULN_URL}{vuln_id}", method="GET")
            with urllib.request.urlopen(request, timeout=OSV_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            console.print(
                f"[bold yellow]Advertencia:[/] no se pudo obtener el detalle "
                f"de [cyan]{vuln_id}[/]: {exc}"
            )
            return None

    @staticmethod
    def _post_batch(queries: List[dict]) -> Optional[List[dict]]:
        """Envía el batch a OSV; devuelve None si no hubo respuesta."""
        try:
            body = json.dumps({"queries": queries}).encode("utf-8")
            request = urllib.request.Request(
                OSV_QUERY_BATCH_URL,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=OSV_TIMEOUT_SECONDS) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            console.print(
                f"[bold yellow]Advertencia:[/] no se pudo consultar OSV "
                f"(dependencias sin verificar): {exc}"
            )
            return None
        return data.get("results") if isinstance(data, dict) else None

    @staticmethod
    def _build_vulnerability(
        dep: Dependency, vuln: dict
    ) -> Optional[DependencyVulnerability]:
        """Convierte un advisory de OSV en DependencyVulnerability."""
        try:
            affected = DependencyScanner._select_affected(vuln, dep.version)
            package = affected.get("package", {})
            severity_list = affected.get("severity") or vuln.get("severity") or []
            cvss_score = DependencyScanner._extract_cvss_score(severity_list)
            severity = DependencyScanner._map_severity(vuln, cvss_score)
            fixed_version, affected_range = DependencyScanner._extract_fix(affected)
            cve_ids, aliases = DependencyScanner._split_ids(
                vuln.get("id", ""), vuln.get("aliases", [])
            )

            purl = package.get("purl")
            if not purl:
                purl = (
                    f"pkg:{DependencyScanner._purl_ecosystem(dep.ecosystem)}/"
                    f"{dep.name}@{dep.version}"
                )
            elif "@" not in purl.rsplit("/", 1)[-1]:
                purl = f"{purl.rstrip('/')}@{dep.version}"

            references = [
                ref.get("url", "")
                for ref in (vuln.get("references") or [])
                if ref.get("url")
            ]
            database_specific = vuln.get("database_specific") or {}
            cwe_ids = database_specific.get("cwe_ids") or [
                weak.get("CWE", "").replace("CWE-", "")
                for weak in (vuln.get("weaknesses") or [])
                if weak.get("CWE", "").startswith("CWE-")
            ]

            return DependencyVulnerability(
                name=dep.name,
                ecosystem=dep.ecosystem,
                version=dep.version,
                direct=dep.direct,
                dependency_type=dep.dependency_type,
                purl=purl,
                cve_ids=cve_ids,
                aliases=aliases,
                cwe_ids=cwe_ids,
                severity=severity,
                cvss_score=cvss_score,
                summary=vuln.get("summary", "") or "",
                details=vuln.get("details"),
                fixed_version=fixed_version,
                affected_range=affected_range,
                is_fix_available=bool(fixed_version),
                exploited_in_wild=database_specific.get("exploited_in_wild"),
                epss_score=database_specific.get("epss_score"),
                published=vuln.get("published"),
                modified=vuln.get("modified"),
                references=references,
            )
        except (KeyError, TypeError, ValueError):
            console.print(
                f"[bold yellow]Advertencia:[/] advisory de OSV malformado "
                f"para [cyan]{dep.name}@{dep.version}[/]"
            )
            return None

    @staticmethod
    def _extract_cvss_score(severity_list: List[dict]) -> Optional[float]:
        """Extrae el score numérico de una lista de severidades CVSS."""
        for item in severity_list or []:
            score = item.get("score")
            if not score:
                continue
            score = str(score)
            # OSV devuelve "9.8" o el vector completo "CVSS:3.1/AV:N/..."
            if score.startswith("CVSS:"):
                parsed = DependencyScanner._parse_cvss_vector(score)
                if parsed is not None:
                    return parsed
                continue
            try:
                return float(score)
            except ValueError:
                continue
        return None

    @staticmethod
    def _parse_cvss_vector(vector: str) -> Optional[float]:
        """Calcula el score base CVSS v3.x desde el vector (p.ej. AV:N/AC:L/...)."""
        metrics: Dict[str, str] = {}
        for part in vector.split("/")[1:]:
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value.upper()
        try:
            av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
            ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
            ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
            scope_changed = metrics["S"] == "C"
            pr_table = (
                {"N": 0.85, "L": 0.68, "H": 0.5}
                if scope_changed
                else {"N": 0.85, "L": 0.62, "H": 0.27}
            )
            pr = pr_table[metrics["PR"]]
            c = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["C"]]
            i = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["I"]]
            a = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["A"]]
        except KeyError:
            return None

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            exploitability = 8.22 * av * ac * pr * ui
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            impact = 6.42 * iss
            exploitability = 8.22 * av * ac * pr * ui
            base = min(impact + exploitability, 10.0)
        if base < 0.0:
            return None
        return round(math.ceil(base * 10) / 10, 1)

    @staticmethod
    def _select_affected(vuln: dict, version: str) -> dict:
        """Elige el bloque 'affected' cuyo rango contiene la versión del dep."""
        affected_list = vuln.get("affected") or [{}]
        for affected in affected_list:
            for rng in affected.get("ranges", []) or []:
                if rng.get("type") != "SEMVER":
                    continue
                events = rng.get("events", []) or []
                introduced = None
                fixed = None
                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                if introduced is None:
                    continue
                if introduced != "0" and not DependencyScanner._semver_lte(
                    introduced, version
                ):
                    continue
                if fixed and not DependencyScanner._semver_lt(version, fixed):
                    continue
                return affected
        return affected_list[0]

    @staticmethod
    def _semver_parts(version: str) -> List[int]:
        """Divide una versión en sus componentes numéricos."""
        return [int(p) for p in re.findall(r"\d+", version)]

    @staticmethod
    def _semver_lt(a: str, b: str) -> bool:
        """Compara dos versiones semver-ish; True si a < b."""
        return DependencyScanner._semver_parts(a) < DependencyScanner._semver_parts(b)

    @staticmethod
    def _semver_lte(a: str, b: str) -> bool:
        """Compara dos versiones semver-ish; True si a <= b."""
        return DependencyScanner._semver_parts(a) <= DependencyScanner._semver_parts(b)

    @staticmethod
    def _map_severity(vuln: dict, cvss_score: Optional[float]) -> Severity:
        """Determina la severidad desde OSV (database_specific o CVSS)."""
        database_specific = vuln.get("database_specific") or {}
        severity_str = str(database_specific.get("severity") or "").upper()
        try:
            if severity_str:
                return Severity(severity_str)
        except ValueError:
            pass
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return Severity.CRITICAL
            if cvss_score >= 7.0:
                return Severity.HIGH
            if cvss_score >= 4.0:
                return Severity.MEDIUM
            return Severity.LOW
        return Severity.HIGH

    @staticmethod
    def _extract_fix(affected: dict) -> Tuple[Optional[str], Optional[str]]:
        """Extrae la versión corregida y el rango vulnerable de un affected."""
        fixed_version = None
        affected_range = None
        for rng in affected.get("ranges", []) or []:
            events = rng.get("events", []) or []
            introduced = None
            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed_version = event["fixed"]
                    break
            if introduced is not None:
                if fixed_version:
                    affected_range = f">={introduced},<{fixed_version}"
                else:
                    affected_range = f">={introduced}"
        return fixed_version, affected_range

    @staticmethod
    def _split_ids(vuln_id: str, aliases: List[str]) -> Tuple[List[str], List[str]]:
        """Separa IDs CVE de aliases (GHSA, GMS...)."""
        all_ids = [vuln_id] + list(aliases or [])
        cve_ids = [i for i in all_ids if i.startswith("CVE-")]
        other = [i for i in all_ids if not i.startswith("CVE-")]
        return cve_ids, other

    @staticmethod
    def _purl_ecosystem(ecosystem: str) -> str:
        """Mapea el ecosistema OSV al type del purl."""
        mapping = {
            "PyPI": "pypi",
            "npm": "npm",
            "Go": "golang",
            "RubyGems": "gem",
            "Packagist": "composer",
            "Maven": "maven",
            "crates.io": "cargo",
        }
        return mapping.get(ecosystem, ecosystem.lower())

"""Interfaz de línea de comandos para vibeaudit."""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from vibeaudit.deliverables import DeliverablesGenerator
from vibeaudit.ingester import RepoIngester, sanitize_url
from vibeaudit.llm import LLMAuditor, LLMUnavailableError
from vibeaudit.memory import MemoryEntry, MemoryStore
from vibeaudit.reporter import AuditReporter
from vibeaudit.scanners.checkov import CheckovScanner
from vibeaudit.scanners.cicd import CICDScanner
from vibeaudit.scanners.cloud import CloudScanner
from vibeaudit.scanners.custom import CustomRulesScanner
from vibeaudit.scanners.deps import DependencyScanner
from vibeaudit.scanners.gitleaks import GitleaksScanner
from vibeaudit.scanners.semgrep import SemgrepScanner
from vibeaudit.sonar import SonarRunner, save_sonar_json

app = typer.Typer(
    name="vibeaudit",
    help="Auditoría de seguridad para repositorios Git (secretos, SAST e IaC)",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


class OutputFormat(str, Enum):
    """Formatos de salida soportados por el CLI."""

    JSON = "json"
    HTML = "html"
    MD = "md"


@app.callback()
def _callback() -> None:
    """Auditoría de seguridad para repositorios Git (secretos, SAST e IaC)."""


def main() -> None:
    """Punto de entrada para el comando instalable `vibeaudit`."""
    app()


@app.command()
def scan(
    repo_url: Optional[str] = typer.Option(
        None, "--repo-url", "-u", help="URL del repositorio Git a auditar"
    ),
    local_path: Optional[Path] = typer.Option(
        None, "--path", help="Directorio local a auditar sin clonar"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Ruta del archivo de salida (default: audit-report.<formato>)",
    ),
    rules: Optional[Path] = typer.Option(
        None,
        "--rules",
        help="Directorio con reglas semgrep YAML custom 'Vibe Coding' (default: bundle incluido)",
    ),
    token: Optional[str] = typer.Option(
        None, "--token", help="Token de acceso para clonar repositorios privados"
    ),
    branch: Optional[str] = typer.Option(
        None, "--branch", help="Rama a auditar (solo con --repo-url)"
    ),
    tag: Optional[str] = typer.Option(
        None, "--tag", help="Tag a auditar (solo con --repo-url)"
    ),
    depth: int = typer.Option(
        1, "--depth", min=1, help="Profundidad del clone (default: 1)"
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.JSON,
        "--format",
        "-f",
        help="Formato de salida: json, html o md",
        show_default="json",
    ),
    dashboard: bool = typer.Option(
        False,
        "--dashboard",
        help="Genera además un dashboard HTML interactivo junto al reporte",
    ),
    llm: bool = typer.Option(
        False,
        "--llm",
        help="Auditoría LLM por checklists (motor local/gratuito, p. ej. Ollama)",
    ),
    memory: Optional[Path] = typer.Option(
        None,
        "--memory",
        help="Directorio de la memoria de hallazgos recurrentes (dedupe y fixes conocidos)",
    ),
    cloud: bool = typer.Option(
        False,
        "--cloud",
        help="Escanea la nube del proveedor configurado (solo lectura, credenciales por env)",
    ),
    deliverables: Optional[Path] = typer.Option(
        None,
        "--deliverables",
        help="Directorio donde generar entregables de cliente (C4, roadmap, backlog)",
    ),
    sonar_json: Optional[Path] = typer.Option(
        None,
        "--sonar-json",
        help="Exporta el reporte a sonar-issues.json (Generic Issue Import de SonarQube)",
    ),
    sonar_scan: bool = typer.Option(
        False,
        "--sonar-scan",
        help="Ejecuta sonar-scanner real sobre el repo (requiere binario y servidor SonarQube)",
    ),
) -> None:
    """Audita un repositorio (clona) o un directorio local: Gitleaks, Semgrep, Checkov."""
    try:
        if (repo_url is None) == (local_path is None):
            raise ValueError(
                "Indica --repo-url o --path (exactamente uno de los dos)"
            )

        if branch is not None and tag is not None:
            raise ValueError("Indica --branch o --tag (no ambos)")

        if local_path is not None and (token or branch or tag or depth != 1):
            raise ValueError(
                "--token, --branch, --tag y --depth solo aplican con --repo-url"
            )

        if rules is None:
            rules = Path(__file__).parent / "rules"
        if rules is not None and not rules.is_dir():
            raise ValueError(
                f"El directorio de reglas no existe o no es un directorio: {rules}"
            )

        if output is None:
            output = Path(f"audit-report.{output_format.value}")

        source = local_path if local_path is not None else repo_url
        console.print(
            f"[bold green]▶ Auditando[/] [cyan]{sanitize_url(str(source))}[/] "
            f"[bold green]→[/] [cyan]{output}[/]"
        )
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            if local_path is not None:
                task = progress.add_task("Analizando directorio local...", total=None)
            else:
                task = progress.add_task("Clonando repositorio...", total=None)

            with RepoIngester(
                repo_url=repo_url,
                local_path=local_path,
                token=token,
                branch=branch or tag,
                depth=depth,
            ) as ingester:
                ingester.clone()
                project = ingester.analyze()
                assert ingester.repo_path is not None

                progress.update(
                    task, description=f"Ejecutando Gitleaks en [cyan]{project.name}[/]..."
                )
                secrets = GitleaksScanner(ingester.repo_path).scan()

                progress.update(task, description="Ejecutando Semgrep...")
                vulnerabilities = SemgrepScanner(ingester.repo_path).scan()

                progress.update(task, description="Ejecutando Checkov...")
                iac_issues = CheckovScanner(ingester.repo_path).scan()

                progress.update(task, description="Analizando CI/CD...")
                cicd_issues = CICDScanner(ingester.repo_path).scan()

                progress.update(task, description="Analizando dependencias...")
                dependency_vulnerabilities = DependencyScanner(
                    ingester.repo_path
                ).scan()

                custom_issues = []
                if rules is not None:
                    progress.update(
                        task, description="Ejecutando reglas custom (Vibe Coding)..."
                    )
                    custom_issues = CustomRulesScanner(
                        ingester.repo_path, rules
                    ).scan()

                progress.update(task, description="Generando reporte...")
                reporter = AuditReporter(
                    project=project,
                    vulnerabilities=vulnerabilities,
                    secrets=secrets,
                    iac_issues=iac_issues,
                    cicd_issues=cicd_issues,
                    dependency_vulnerabilities=dependency_vulnerabilities,
                    custom_issues=custom_issues,
                    repo_path=ingester.repo_path,
                )
                report = reporter.build()

                if llm:
                    progress.update(
                        task, description="Ejecutando auditor LLM (checklists)..."
                    )
                    try:
                        report.llm_findings = LLMAuditor(report).audit()
                    except LLMUnavailableError as exc:
                        console.print(f"[yellow]Advertencia:[/] {exc}")
                        console.print(
                            "[yellow]Se genera el reporte sin análisis LLM.[/]"
                        )

                recurrent: list = []
                if memory is not None:
                    progress.update(
                        task, description="Consultando memoria de hallazgos recurrentes..."
                    )
                    recurrent = MemoryStore(memory).ingest_report(report)
                    report.recurrent_findings = recurrent
                    console.print(
                        f"[cyan]Memoria:[/] {len(recurrent)} hallazgos recurrentes reconocidos"
                    )

                cloud_issues: list = []
                if cloud:
                    progress.update(
                        task, description="Escaneando la nube (solo lectura)..."
                    )
                    cloud_scanner = CloudScanner()
                    cloud_issues = cloud_scanner.scan()
                    report.cloud_issues = cloud_issues
                    report.cloud_resources = cloud_scanner.resources
                    console.print(
                        f"[cyan]Nube:[/] {len(cloud_issues)} configs inseguras detectadas "
                        f"({len(cloud_scanner.resources)} recursos analizados)"
                    )

                if deliverables is not None:
                    progress.update(
                        task, description="Generando entregables (C4, roadmap, backlog)..."
                    )
                    files = DeliverablesGenerator(report).generate(deliverables)
                    console.print(
                        f"[bold green]✔ Entregables en[/] [cyan]{deliverables}[/]: "
                        + ", ".join(sorted(files))
                    )

                if sonar_json is not None:
                    progress.update(
                        task, description="Exportando issues a SonarQube (Generic Import)..."
                    )
                    save_sonar_json(report, sonar_json)
                    console.print(
                        f"[bold green]✔ sonar-issues en[/] [cyan]{sonar_json}[/] "
                        f"(importar vía 'Generic Issue Import' de SonarQube)"
                    )

                if sonar_scan:
                    progress.update(
                        task, description="Ejecutando sonar-scanner sobre el repo..."
                    )
                    try:
                        rc = SonarRunner(ingester.repo_path, sonar_json).scan()
                        console.print(
                            f"[cyan]sonar-scanner:[/] análisis finalizado (código {rc}). "
                            "Revisa la salida del escáner para más detalle."
                        )
                    except RuntimeError as exc:
                        console.print(f"[yellow]Advertencia:[/] {exc}")

        # Fuera del with: el directorio temporal ya fue limpiado
        if output_format == OutputFormat.JSON:
            reporter.save_to_file(output)
        elif output_format == OutputFormat.MD:
            reporter.save_markdown(output)
        else:
            reporter.save_html(output)
        if dashboard:
            dashboard_path = output.with_name(f"{output.stem}-dashboard.html")
            reporter.save_dashboard(dashboard_path)
            console.print(
                f"[bold green]✔ Dashboard guardado en[/] [cyan]{dashboard_path}[/]"
            )
        console.print(
            f"[bold green]✔ Reporte guardado en[/] [cyan]{output}[/] "
            f"([bold]{len(secrets)} secretos, "
            f"{len(vulnerabilities)} vulnerabilidades, "
            f"{len(iac_issues)} problemas IaC, "
            f"{len(cicd_issues)} riesgos CI/CD, "
            f"{len(dependency_vulnerabilities)} deps con CVEs, "
            f"{len(report.llm_findings)} hallazgos LLM, "
            f"{len(report.recurrent_findings)} recurrentes, "
            f"{len(report.cloud_issues)} nube[/])"
        )
        reporter.print_summary()

    except ValueError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        console.print(f"[bold red]Error de permisos:[/] {exc}")
        raise typer.Exit(code=1) from exc
    except RuntimeError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        if "credenciales de nube" in str(exc):
            console.print(
                "[yellow]Nube:[/] configura las credenciales del proveedor "
                "por entorno (AWS_ACCESS_KEY_ID, AZURE_CLIENT_ID...) y reintenta."
            )
        else:
            console.print(
                "[yellow]Sugerencia:[/] verifica que gitleaks, semgrep y checkov "
                "estén instalados (brew install gitleaks semgrep; pip install checkov)"
            )
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        console.print(
            f"[bold red]Error de archivo:[/] no se pudo escribir el reporte: {exc}"
        )
        raise typer.Exit(code=1) from exc


memory_app = typer.Typer(
    name="memory",
    help="Memoria local de hallazgos recurrentes (dedupe y fixes conocidos)",
    no_args_is_help=True,
)


@memory_app.command("add")
def memory_add(
    directory: Path = typer.Argument(..., help="Directorio de la memoria"),
    rule: str = typer.Option(..., "--rule", help="Regla/paquete de la clase de hallazgo"),
    fix: str = typer.Option("", "--fix", help="Solución/fix conocida para esa clase"),
    evidence: str = typer.Option("", "--evidence", help="Texto de evidencia (opcional)"),
    framework: str = typer.Option("", "--framework", help="Marco (OWASP, AWS WAF...)"),
) -> None:
    """Registra en la memoria una clase de hallazgo con su fix conocido."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    store = MemoryStore(directory)
    store.upsert(
        MemoryEntry(
            id=hashlib.md5(rule.encode()).hexdigest()[:12],
            rule=rule,
            evidence=evidence,
            recommendation=fix,
            framework=framework,
            occurrences=1,
            first_seen=now,
            last_seen=now,
        )
    )
    console.print(f"[bold green]✔ Memoria actualizada en[/] [cyan]{store.path}[/]")
    console.print(f"   [cyan]{rule}[/] → {fix or '(sin fix registrado)'}")


@memory_app.command("list")
def memory_list(
    directory: Path = typer.Argument(..., help="Directorio de la memoria"),
) -> None:
    """Lista las entradas de la memoria de hallazgos recurrentes."""
    store = MemoryStore(directory)
    entries = store.entries()
    if not entries:
        console.print("La memoria está vacía.")
        return
    table = Table(title=f"Memoria de hallazgos recurrentes ({store.path})")
    table.add_column("Regla", style="cyan")
    table.add_column("Ocurrencias", justify="right")
    table.add_column("Framework")
    table.add_column("Fix conocido")
    for entry in entries:
        table.add_row(
            entry.rule,
            str(entry.occurrences),
            entry.framework or "-",
            entry.recommendation or "-",
        )
    console.print(table)


app.add_typer(memory_app)


if __name__ == "__main__":
    main()

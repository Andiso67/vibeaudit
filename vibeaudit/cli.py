"""Interfaz de línea de comandos para vibeaudit."""

from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from vibeaudit.ingester import RepoIngester, sanitize_url
from vibeaudit.reporter import AuditReporter
from vibeaudit.scanners.checkov import CheckovScanner
from vibeaudit.scanners.cicd import CICDScanner
from vibeaudit.scanners.custom import CustomRulesScanner
from vibeaudit.scanners.deps import DependencyScanner
from vibeaudit.scanners.gitleaks import GitleaksScanner
from vibeaudit.scanners.semgrep import SemgrepScanner

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
        help="Directorio con reglas semgrep YAML custom 'Vibe Coding'",
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

        # Fuera del with: el directorio temporal ya fue limpiado
        if output_format == OutputFormat.JSON:
            reporter.save_to_file(output)
        elif output_format == OutputFormat.MD:
            reporter.save_markdown(output)
        else:
            reporter.save_html(output)
        console.print(
            f"[bold green]✔ Reporte guardado en[/] [cyan]{output}[/] "
            f"([bold]{len(secrets)} secretos, "
            f"{len(vulnerabilities)} vulnerabilidades, "
            f"{len(iac_issues)} problemas IaC, "
            f"{len(cicd_issues)} riesgos CI/CD, "
            f"{len(dependency_vulnerabilities)} deps con CVEs, "
            f"{len(custom_issues)} reglas custom[/])"
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


if __name__ == "__main__":
    main()

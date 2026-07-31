"""Interfaz de línea de comandos para vibeaudit."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from vibeaudit.ingester import RepoIngester
from vibeaudit.reporter import AuditReporter
from vibeaudit.scanners.checkov import CheckovScanner
from vibeaudit.scanners.gitleaks import GitleaksScanner
from vibeaudit.scanners.semgrep import SemgrepScanner

app = typer.Typer(
    name="vibeaudit",
    help="Auditoría de seguridad para repositorios Git (secretos, SAST e IaC)",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


@app.callback()
def _callback() -> None:
    """Auditoría de seguridad para repositorios Git (secretos, SAST e IaC)."""


def main() -> None:
    """Punto de entrada para el comando instalable `vibeaudit`."""
    app()


@app.command()
def scan(
    repo_url: str = typer.Option(
        ..., "--repo-url", "-u", help="URL del repositorio Git a auditar"
    ),
    output: Path = typer.Option(
        Path("audit-report.json"),
        "--output",
        "-o",
        help="Ruta del archivo JSON de salida",
    ),
) -> None:
    """Audita un repositorio: clona, ejecuta Gitleaks, Semgrep y Checkov."""
    console.print(
        f"[bold green]▶ Auditando[/] [cyan]{repo_url}[/] [bold green]→[/] "
        f"[cyan]{output}[/]"
    )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Clonando repositorio...", total=None)

            with RepoIngester(repo_url) as ingester:
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

                progress.update(task, description="Generando reporte...")
                reporter = AuditReporter(
                    project=project,
                    vulnerabilities=vulnerabilities,
                    secrets=secrets,
                    iac_issues=iac_issues,
                    repo_path=ingester.repo_path,
                )
                report = reporter.build()

        # Fuera del with: el directorio temporal ya fue limpiado
        reporter.save_to_file(output)
        console.print(
            f"[bold green]✔ Reporte guardado en[/] [cyan]{output}[/] "
            f"([bold]{len(secrets)} secretos, "
            f"{len(vulnerabilities)} vulnerabilidades, "
            f"{len(iac_issues)} problemas IaC[/])"
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

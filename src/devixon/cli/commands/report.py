"""
CLI Report Generation and Export Commands.
"""

from pathlib import Path
from typing import Optional
import shutil
import typer
from rich.console import Console
from rich.table import Table
from devixon.core.config import load_config
from devixon.database.session import get_session
from devixon.database.models import Assessment, Finding, Asset
from devixon.reports.generator import ReportGenerator

console = Console()


def generate_report(
    assessment_id: Optional[str] = typer.Option(None, "--id", help="Assessment ID (defaults to latest)"),
    format_type: str = typer.Option("all", "--format", "-f", help="Format: html, markdown, json, csv, all"),
):
    """Generate professional assessment reports."""
    cfg = load_config()
    reports_dir = Path(cfg.output.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    session = get_session()
    try:
        if assessment_id:
            assessment = session.query(Assessment).filter(Assessment.id == assessment_id).first()
        else:
            assessment = session.query(Assessment).order_by(Assessment.created_at.desc()).first()

        if not assessment:
            console.print("[yellow]No assessments found to generate reports for.[/yellow]")
            return

        findings = session.query(Finding).filter(Finding.assessment_id == assessment.id).all()
        assets = session.query(Asset).filter(Asset.assessment_id == assessment.id).all()

        generator = ReportGenerator()
        base_name = f"devixon_{assessment.target.replace('.', '_')}_{assessment.id[:8]}"

        console.print(f"\n[bold cyan]GENERATING REPORTS FOR {assessment.target} ({assessment.id[:8]})[/bold cyan]\n")

        fmt = format_type.lower()
        if fmt in ("all", "html"):
            p = generator.generate_html(assessment, findings, assets, reports_dir / f"{base_name}.html")
            console.print(f"[green]HTML Report:[/green] {p}")

        if fmt in ("all", "markdown", "md"):
            p = generator.generate_markdown(assessment, findings, assets, reports_dir / f"{base_name}.md")
            console.print(f"[green]Markdown Report:[/green] {p}")

        if fmt in ("all", "json"):
            p = generator.generate_json(assessment, findings, assets, reports_dir / f"{base_name}.json")
            console.print(f"[green]JSON Export:[/green] {p}")

        if fmt in ("all", "csv"):
            p = generator.generate_csv(findings, reports_dir / f"{base_name}.csv")
            console.print(f"[green]CSV Export:[/green] {p}")

        console.print(f"\n[bold green]Report generation complete! Files located in {reports_dir}[/bold green]\n")

    finally:
        session.close()


def list_reports():
    """List previously generated assessment reports."""
    cfg = load_config()
    reports_dir = Path(cfg.output.reports_dir)
    if not reports_dir.exists() or not list(reports_dir.glob("*")):
        console.print(f"[yellow]No reports found in {reports_dir}[/yellow]")
        return

    table = Table(title="Generated Assessment Reports", show_header=True, header_style="bold green")
    table.add_column("Filename", style="bold cyan")
    table.add_column("Format", style="yellow")
    table.add_column("Size", justify="right")

    for f in reports_dir.glob("*"):
        if f.is_file():
            table.add_row(f.name, f.suffix.upper().replace(".", ""), f"{f.stat().st_size} bytes")

    console.print("\n")
    console.print(table)
    console.print(f"\nDirectory: {reports_dir}\n")


def export_report(
    source_filename: str = typer.Argument(..., help="Report filename to export"),
    dest: Path = typer.Argument(..., help="Destination path"),
):
    """Export a report file to an external location."""
    cfg = load_config()
    reports_dir = Path(cfg.output.reports_dir)
    src_path = reports_dir / source_filename

    if not src_path.exists():
        console.print(f"[red]Report '{source_filename}' not found in {reports_dir}[/red]")
        raise typer.Exit(1)

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_path, dest)
    console.print(f"[green]Report exported to:[/green] {dest}")

"""
CLI Report Generation Commands.
"""

from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
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

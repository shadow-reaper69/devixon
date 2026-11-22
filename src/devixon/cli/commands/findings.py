"""
CLI Findings Management Commands.
"""

from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from devixon.database.session import get_session
from devixon.database.models import Finding, Assessment
from devixon.security.validation import get_verification_checklist

console = Console()


def list_findings(
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity (CRITICAL, HIGH, etc.)"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status (CONFIRMED, NEEDS_REVIEW, etc.)"),
):
    """List security findings from latest assessment."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found. Run 'devixon recon quick' first.[/yellow]")
            return

        query = session.query(Finding).filter(Finding.assessment_id == latest.id)
        if severity:
            query = query.filter(Finding.severity == severity.upper())
        if status:
            query = query.filter(Finding.verification_status == status.upper())

        findings = query.all()
        console.print(f"\n[bold cyan]FINDINGS FOR ASSESSMENT {latest.id[:8]} ({latest.target})[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold green")
        table.add_column("ID", style="dim")
        table.add_column("Severity", style="bold")
        table.add_column("Status", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("CVSS", justify="right")

        sev_colors = {
            "CRITICAL": "red",
            "HIGH": "magenta",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFORMATIONAL": "blue",
        }

        for f in findings:
            c = sev_colors.get(f.severity.upper(), "white")
            table.add_row(
                f.id[:8],
                f"[{c}]{f.severity}[/{c}]",
                f.verification_status,
                f.title,
                str(f.cvss_score or "N/A"),
            )

        console.print(table)
        console.print(f"\nTotal: {len(findings)} findings\n")

    finally:
        session.close()


def inspect_finding(finding_id: str = typer.Argument(..., help="Finding ID or prefix")):
    """Inspect finding details, evidence, and manual verification steps."""
    session = get_session()
    try:
        f = session.query(Finding).filter(Finding.id.like(f"{finding_id}%")).first()
        if not f:
            console.print(f"[red]Finding with ID '{finding_id}' not found.[/red]")
            return

        console.print(f"\n[bold cyan]FINDING: {f.title}[/bold cyan]")
        console.print(f"ID: [dim]{f.id}[/dim] | Severity: [bold red]{f.severity}[/bold red] | CVSS: {f.cvss_score or 'N/A'}")
        console.print(f"Category: {f.category} | Status: [bold]{f.verification_status}[/bold] (Confidence: {f.confidence})\n")

        console.print("[bold]Description:[/bold]")
        console.print(f"{f.description}\n")

        console.print("[bold]Impact:[/bold]")
        console.print(f"{f.impact}\n")

        console.print("[bold]Remediation:[/bold]")
        console.print(f"{f.remediation}\n")

        if f.evidence:
            console.print("[bold]Sanitized Evidence:[/bold]")
            for ev in f.evidence:
                console.print(f"[{ev.evidence_type} from {ev.source}]:")
                console.print(f"  {ev.sanitized_data}")
            console.print("")

        checklist = get_verification_checklist(f.category)
        if checklist:
            console.print(f"[bold cyan]Manual Verification Checklist ({checklist.category}):[/bold cyan]")
            for step in checklist.manual_steps:
                console.print(f"  [dim]{step}[/dim]")
            console.print(f"\n[bold yellow]Safe Test Guidance:[/bold yellow] {checklist.safe_test_guidance}\n")

    finally:
        session.close()


def update_finding(
    finding_id: str = typer.Argument(..., help="Finding ID or prefix"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="New severity"),
    status: Optional[str] = typer.Option(None, "--status", help="New verification status"),
):
    """Update finding severity or status."""
    session = get_session()
    try:
        f = session.query(Finding).filter(Finding.id.like(f"{finding_id}%")).first()
        if not f:
            console.print(f"[red]Finding with ID '{finding_id}' not found.[/red]")
            return

        if severity:
            f.severity = severity.upper()
        if status:
            f.verification_status = status.upper()
        session.commit()
        console.print(f"[green]Finding '{f.title}' successfully updated.[/green]")
    finally:
        session.close()


def verify_finding(
    finding_id: str = typer.Argument(..., help="Finding ID or prefix"),
    status: str = typer.Option("CONFIRMED", "--status", "-s", help="New status: CONFIRMED, FIXED, ACCEPTED_RISK"),
    notes: Optional[str] = typer.Option(None, "--notes", help="Verification notes"),
):
    """Confirm manual verification of a finding."""
    session = get_session()
    try:
        f = session.query(Finding).filter(Finding.id.like(f"{finding_id}%")).first()
        if not f:
            console.print(f"[red]Finding with ID '{finding_id}' not found.[/red]")
            return

        f.verification_status = status.upper()
        if notes:
            f.false_positive_reason = notes
        session.commit()
        console.print(f"[green]Finding '{f.title}' status updated to {status.upper()}[/green]")
    finally:
        session.close()


def dismiss_finding(
    finding_id: str = typer.Argument(..., help="Finding ID or prefix"),
    reason: str = typer.Option("FALSE_POSITIVE", "--reason", "-r", help="Reason: FALSE_POSITIVE, ACCEPTED_RISK, NOT_REPRODUCIBLE"),
    notes: Optional[str] = typer.Option(None, "--notes", help="Detailed dismissal notes"),
):
    """Dismiss a finding as false positive or accepted risk."""
    session = get_session()
    try:
        f = session.query(Finding).filter(Finding.id.like(f"{finding_id}%")).first()
        if not f:
            console.print(f"[red]Finding with ID '{finding_id}' not found.[/red]")
            return

        f.verification_status = reason.upper()
        if notes:
            f.false_positive_reason = notes
        session.commit()
        console.print(f"[yellow]Finding '{f.title}' dismissed as {reason.upper()}[/yellow]")
    finally:
        session.close()

"""
CLI AI Analyst Commands.
"""

import asyncio
from typing import Optional
import typer
from rich.console import Console
from devixon.ai.client import AIAnalystClient
from devixon.database.session import get_session
from devixon.database.models import Finding, Assessment

console = Console()


def analyze_ai(finding_id: str = typer.Argument(..., help="Finding ID or prefix to analyze")):
    """Run AI analysis on a specific finding's evidence."""
    session = get_session()
    try:
        f = session.query(Finding).filter(Finding.id.like(f"{finding_id}%")).first()
        if not f:
            console.print(f"[red]Finding with ID '{finding_id}' not found.[/red]")
            return

        client = AIAnalystClient()
        if not client.is_available():
            console.print("[yellow]Notice: AI is currently disabled or DEVIXON_AI_API_KEY is not set. Using deterministic fallback.[/yellow]")

        ev_text = "\n".join([ev.sanitized_data for ev in f.evidence]) or f.description
        console.print(f"\n[bold cyan]ANALYZING FINDING EVIDENCE WITH AI: {f.title}[/bold cyan]\n")

        analysis = asyncio.run(client.analyze_finding(
            title=f.title,
            category=f.category,
            evidence_text=ev_text,
            asset_info=f.assessment.target if f.assessment else "target",
        ))

        console.print(f"[bold]Confidence Evaluation:[/bold] {analysis.confidence}")
        console.print(f"[bold]Reasoning Summary:[/bold] {analysis.reasoning_summary}")
        console.print(f"[bold]Potential Impact:[/bold] {analysis.potential_impact}")
        console.print(f"[bold]Remediation Guidance:[/bold] {analysis.remediation_recommendation}\n")

    finally:
        session.close()


def summarize_ai():
    """Generate high-level attack surface and posture summary using AI."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found.[/yellow]")
            return

        findings = session.query(Finding).filter(Finding.assessment_id == latest.id).all()
        console.print(f"\n[bold cyan]AI ATTACK SURFACE SUMMARY: {latest.target}[/bold cyan]\n")
        console.print(f"Target: [bold]{latest.target}[/bold] | Profile: {latest.scan_profile}")
        console.print(f"Total Discovered Assets: {len(latest.assets)}")
        console.print(f"Total Security Findings: {len(findings)}\n")

        high_issues = [f.title for f in findings if f.severity.upper() in ("CRITICAL", "HIGH")]
        if high_issues:
            console.print("[bold red]Primary Critical/High Risk Vectors:[/bold red]")
            for issue in high_issues:
                console.print(f"  • {issue}")
        else:
            console.print("[green]No critical or high severity issues identified in scan.[/green]")
        console.print("")
    finally:
        session.close()


def explain_ai(finding_id: str = typer.Argument(..., help="Finding ID or prefix")):
    """Explain root cause and technical concepts behind a finding."""
    session = get_session()
    try:
        f = session.query(Finding).filter(Finding.id.like(f"{finding_id}%")).first()
        if not f:
            console.print(f"[red]Finding with ID '{finding_id}' not found.[/red]")
            return

        console.print(f"\n[bold cyan]EXPLANATION: {f.title}[/bold cyan]\n")
        console.print(f"[bold]Why this happens:[/bold] {f.description}")
        console.print(f"\n[bold]Risk & Impact:[/bold] {f.impact}\n")
    finally:
        session.close()


def remediate_ai(finding_id: str = typer.Argument(..., help="Finding ID or prefix")):
    """Generate detailed developer-friendly remediation guidance."""
    session = get_session()
    try:
        f = session.query(Finding).filter(Finding.id.like(f"{finding_id}%")).first()
        if not f:
            console.print(f"[red]Finding with ID '{finding_id}' not found.[/red]")
            return

        console.print(f"\n[bold cyan]REMEDIATION GUIDANCE: {f.title}[/bold cyan]\n")
        console.print(f"{f.remediation}\n")
    finally:
        session.close()

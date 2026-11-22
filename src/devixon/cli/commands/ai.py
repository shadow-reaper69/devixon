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

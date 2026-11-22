"""
CLI Assets and Endpoints Commands.
"""

import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from devixon.database.session import get_session
from devixon.database.models import Asset, Endpoint, Assessment

console = Console()


def list_assets():
    """List discovered assets and resolved IP addresses."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found.[/yellow]")
            return

        assets = session.query(Asset).filter(Asset.assessment_id == latest.id).all()
        table = Table(title=f"Discovered Assets ({latest.target})", show_header=True, header_style="bold green")
        table.add_column("Hostname", style="bold cyan")
        table.add_column("IP Address", style="white")
        table.add_column("Type", style="dim")
        table.add_column("Scope Status", style="green")
        table.add_column("Source", style="dim")

        for a in assets:
            table.add_row(
                a.hostname,
                a.ip_address or "Unresolved",
                a.asset_type,
                a.scope_status,
                a.discovery_source,
            )

        console.print("\n")
        console.print(table)
        console.print(f"\nTotal: {len(assets)} assets\n")
    finally:
        session.close()


def list_endpoints():
    """List discovered web endpoints and parameter signatures."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found.[/yellow]")
            return

        endpoints = (
            session.query(Endpoint)
            .join(Asset)
            .filter(Asset.assessment_id == latest.id)
            .all()
        )

        table = Table(title=f"Discovered Endpoints ({latest.target})", show_header=True, header_style="bold green")
        table.add_column("Method", style="bold")
        table.add_column("Path", style="cyan")
        table.add_column("Parameters", style="yellow")
        table.add_column("Status Code", style="dim")

        for ep in endpoints[:50]:
            table.add_row(
                ep.method,
                ep.path,
                ep.params or "-",
                str(ep.status_code or "-"),
            )

        console.print("\n")
        console.print(table)
        console.print(f"\nTotal: {len(endpoints)} endpoints recorded\n")
    finally:
        session.close()

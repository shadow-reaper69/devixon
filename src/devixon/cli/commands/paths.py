"""
CLI Discovered Paths Management Commands.
"""

from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from devixon.database.session import get_session
from devixon.database.models import DiscoveredPath, Assessment

console = Console()


def list_paths(
    status_filter: Optional[int] = typer.Option(None, "--status", "-s", help="Filter by HTTP status code"),
):
    """List discovered files and directories from assessments."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found.[/yellow]")
            return

        query = session.query(DiscoveredPath).filter(DiscoveredPath.assessment_id == latest.id)
        if status_filter:
            query = query.filter(DiscoveredPath.status_code == status_filter)

        paths = query.order_by(DiscoveredPath.status_code.asc()).all()

        table = Table(title=f"Discovered Paths & Files ({latest.target})", show_header=True, header_style="bold green")
        table.add_column("Status", style="bold")
        table.add_column("Path", style="cyan")
        table.add_column("Size", justify="right")
        table.add_column("Redirect Location", style="yellow")
        table.add_column("Tool", style="dim")

        for p in paths:
            st = str(p.status_code)
            color = "green" if st.startswith("2") else "yellow" if st.startswith("3") else "red"
            table.add_row(
                f"[{color}]{st}[/{color}]",
                p.path,
                f"{p.content_length} B",
                p.redirect_location or "-",
                p.discovery_tool,
            )

        console.print("\n")
        console.print(table)
        console.print(f"\nTotal: {len(paths)} paths discovered\n")
    finally:
        session.close()

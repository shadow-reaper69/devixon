"""
CLI Target Management Commands.
"""

from typing import Optional
from pathlib import Path
import json
import typer
from rich.console import Console
from rich.table import Table
from devixon.core.scope import normalize_target
from devixon.core.config import DEFAULT_DATA_DIR
from devixon.core.exceptions import TargetValidationError

console = Console()
TARGETS_FILE = DEFAULT_DATA_DIR / "targets.json"


def _load_targets():
    if TARGETS_FILE.exists():
        try:
            return json.loads(TARGETS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def _save_targets(targets):
    TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    TARGETS_FILE.write_text(json.dumps(targets, indent=2), encoding="utf-8")


def add_target(
    target: str = typer.Argument(..., help="Target domain, URL, or IP address"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Organizational tag or program name"),
):
    """Add a target to the target registry."""
    try:
        norm = normalize_target(target)
    except TargetValidationError as e:
        console.print(f"[red]Invalid target:[/red] {e.message}")
        raise typer.Exit(1)

    targets = _load_targets()
    for t in targets:
        if t["target"] == norm:
            console.print(f"[yellow]Target '{norm}' is already registered.[/yellow]")
            return

    targets.append({
        "target": norm,
        "tag": tag or "default",
    })
    _save_targets(targets)
    console.print(f"[green]Target '{norm}' successfully added.[/green]")


def list_targets():
    """List registered targets."""
    targets = _load_targets()
    if not targets:
        console.print("[yellow]No registered targets found. Use 'devixon target add <target>' to register one.[/yellow]")
        return

    table = Table(title="Registered Target Assets", show_header=True, header_style="bold green")
    table.add_column("Target", style="bold cyan")
    table.add_column("Tag / Program", style="yellow")

    for t in targets:
        table.add_row(t["target"], t.get("tag", "default"))

    console.print("\n")
    console.print(table)
    console.print(f"\nTotal: {len(targets)} targets\n")


def inspect_target(target: str = typer.Argument(..., help="Target domain or IP")):
    """Inspect a registered target."""
    norm = normalize_target(target)
    targets = _load_targets()
    found = next((t for t in targets if t["target"] == norm), None)

    if not found:
        console.print(f"[red]Target '{norm}' not found in registry.[/red]")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]TARGET DETAILS[/bold cyan]")
    console.print(f"Target: [bold]{found['target']}[/bold]")
    console.print(f"Tag: {found.get('tag', 'default')}\n")

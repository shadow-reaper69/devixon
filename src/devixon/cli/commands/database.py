"""
CLI Database Backup and Restore Commands.
"""

from pathlib import Path
import shutil
import typer
from rich.console import Console
from devixon.core.config import load_config

console = Console()


def backup_database(
    dest: Path = typer.Option(None, "--dest", "-d", help="Destination path for backup file"),
):
    """Backup the DEVIXON SQLite database."""
    cfg = load_config()
    db_path = Path(cfg.database_path)

    if not db_path.exists():
        console.print(f"[red]Database not found at {db_path}[/red]")
        raise typer.Exit(1)

    if dest is None:
        dest = db_path.parent / f"devixon_backup_{db_path.name}"

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(db_path, dest)
    console.print(f"[green]Database successfully backed up to:[/green] {dest}")


def restore_database(
    source: Path = typer.Argument(..., help="Path to backup database file to restore from"),
):
    """Restore the DEVIXON SQLite database from a backup."""
    if not source.exists():
        console.print(f"[red]Backup source file '{source}' does not exist.[/red]")
        raise typer.Exit(1)

    cfg = load_config()
    db_path = Path(cfg.database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy2(source, db_path)
    console.print(f"[green]Database successfully restored from {source} to {db_path}[/green]")

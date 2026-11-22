"""
CLI Configuration Commands.
"""

from pathlib import Path
import typer
from rich.console import Console
from rich.syntax import Syntax
from devixon.core.config import load_config, DEFAULT_CONFIG_FILE, AppConfig

console = Console()


def show_config():
    """Display current configuration."""
    cfg = load_config()
    console.print(f"\n[bold cyan]DEVIXON CONFIGURATION[/bold cyan] ([dim]{DEFAULT_CONFIG_FILE}[/dim])\n")
    syntax = Syntax(cfg.model_dump_json(indent=2), "json", theme="monokai", line_numbers=True)
    console.print(syntax)
    console.print("")


def validate_config():
    """Validate configuration syntax and values."""
    try:
        cfg = load_config()
        # Verify database path directory exists
        db_path = Path(cfg.database_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Verify rate limits
        if cfg.rate_limits.requests_per_second <= 0:
            console.print("[red]Invalid rate_limits.requests_per_second: must be > 0[/red]")
            raise typer.Exit(1)
        if cfg.rate_limits.max_concurrency <= 0:
            console.print("[red]Invalid rate_limits.max_concurrency: must be > 0[/red]")
            raise typer.Exit(1)

        console.print("[bold green]Configuration is valid and verified.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Configuration validation error:[/bold red] {e}")
        raise typer.Exit(1)

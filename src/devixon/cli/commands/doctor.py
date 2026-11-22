"""
CLI Doctor Command.
Performs comprehensive system, environment, database, and tool diagnostics.
"""

import sys
import shutil
import platform
import typer
from rich.console import Console
from rich.table import Table
from devixon import __version__
from devixon.core.config import load_config
from devixon.database.session import get_engine

console = Console()


def doctor_command():
    """Run comprehensive system and environment diagnostics."""
    console.print("\n[bold cyan]DEVIXON SYSTEM DIAGNOSTICS & DOCTOR[/bold cyan]\n")

    table = Table(title="System Environment", show_header=True, header_style="bold green")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Details", style="dim")

    # Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    table.add_row("Python Version", "[green]OK[/green]" if py_ok else "[red]FAIL[/red]", f"Python {py_ver}")

    # OS
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    table.add_row("Operating System", "[green]OK[/green]", os_info)

    # DEVIXON version
    table.add_row("DEVIXON Core", "[green]OK[/green]", f"v{__version__}")

    # Config
    cfg = load_config()
    table.add_row("Configuration", "[green]OK[/green]", f"Default Profile: {cfg.default_profile}")

    # Database
    db_ok = False
    try:
        engine = get_engine()
        with engine.connect() as conn:
            db_ok = True
        table.add_row("Database (SQLite)", "[green]OK[/green]", str(cfg.database_path))
    except Exception as e:
        table.add_row("Database (SQLite)", "[red]ERROR[/red]", str(e))

    console.print(table)

    # External Tools Diagnostics
    tool_table = Table(title="Reconnaissance Tool Integrations", show_header=True, header_style="bold green")
    tool_table.add_column("Tool", style="cyan")
    tool_table.add_column("Status", style="bold")
    tool_table.add_column("Path / Notes", style="dim")

    tools = [
        ("subfinder", "Subdomain discovery tool"),
        ("amass", "OWASP Amass OSINT"),
        ("dnsx", "Fast multi-purpose DNS toolkit"),
        ("httpx", "ProjectDiscovery HTTP probe tool"),
        ("nmap", "Network port and service scanner"),
        ("katana", "Next-gen web crawler"),
        ("gau", "Get All URLs from archives"),
        ("ffuf", "Fast web fuzzer"),
    ]

    for tool_name, desc in tools:
        path = shutil.which(tool_name)
        if path:
            tool_table.add_row(tool_name, "[green]INSTALLED[/green]", path)
        else:
            tool_table.add_row(tool_name, "[yellow]OPTIONAL (FALLBACK ACTIVE)[/yellow]", f"Native Python fallback available for {desc}")

    console.print("\n")
    console.print(tool_table)

    console.print("\n[bold green]Ready to perform authorized security assessments![/bold green]\n")

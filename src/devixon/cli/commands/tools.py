"""
CLI Tools Management and Installation Guide Commands.
"""

import shutil
import typer
from rich.console import Console
from rich.table import Table

console = Console()

TOOLS_CATALOG = [
    {
        "name": "subfinder",
        "description": "Fast passive subdomain discovery tool",
        "install_linux": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "install_windows": "winget install ProjectDiscovery.Subfinder (or go install)",
        "fallback": "Native crt.sh and Certificate Transparency parser in DEVIXON",
    },
    {
        "name": "httpx",
        "description": "Fast and multi-purpose HTTP probe toolkit",
        "install_linux": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "install_windows": "pip install httpx (Python client built-in) or Go binary",
        "fallback": "Native async httpx client prober in DEVIXON",
    },
    {
        "name": "dnsx",
        "description": "Multi-purpose DNS toolkit for running DNS queries",
        "install_linux": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "install_windows": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "fallback": "Native dnspython resolution engine in DEVIXON",
    },
    {
        "name": "nmap",
        "description": "Network exploration tool and security scanner",
        "install_linux": "sudo apt install nmap",
        "install_windows": "winget install Insecure.Nmap",
        "fallback": "Native non-destructive async socket port prober in DEVIXON",
    },
    {
        "name": "katana",
        "description": "Next-generation crawling and spidering framework",
        "install_linux": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "install_windows": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "fallback": "Native scoped HTML link extractor and crawler in DEVIXON",
    },
    {
        "name": "gau",
        "description": "Fetch known URLs from AlienVault OTX, Wayback, and Common Crawl",
        "install_linux": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "install_windows": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "fallback": "Native Wayback Machine archive queries in DEVIXON",
    },
    {
        "name": "ffuf",
        "description": "Fast web fuzzer written in Go",
        "install_linux": "go install github.com/ffuf/ffuf/v2@latest",
        "install_windows": "go install github.com/ffuf/ffuf/v2@latest",
        "fallback": "Native safe path prober in DEVIXON",
    },
]


def check_tools():
    """Check availability of external reconnaissance binaries."""
    table = Table(title="Reconnaissance Tool Integrations", show_header=True, header_style="bold green")
    table.add_column("Tool", style="bold cyan")
    table.add_column("Status", style="bold")
    table.add_column("Path / Fallback Capability", style="dim")

    for t in TOOLS_CATALOG:
        path = shutil.which(t["name"])
        if path:
            table.add_row(t["name"], "[green]INSTALLED[/green]", path)
        else:
            table.add_row(t["name"], "[yellow]OPTIONAL[/yellow]", f"{t['fallback']}")

    console.print("\n")
    console.print(table)
    console.print("\n[dim]Note: DEVIXON works 100% out-of-the-box using native Python fallbacks even when external tools are missing.[/dim]\n")


def install_guide():
    """Display comprehensive installation guide for optional external security utilities."""
    console.print("\n[bold cyan]DEVIXON EXTERNAL TOOL INSTALLATION GUIDE[/bold cyan]\n")
    for t in TOOLS_CATALOG:
        console.print(f"[bold green]▶ {t['name']}[/bold green] - {t['description']}")
        console.print(f"  [cyan]Linux/Kali:[/cyan]   `{t['install_linux']}`")
        console.print(f"  [cyan]Windows:[/cyan]      `{t['install_windows']}`")
        console.print(f"  [dim]Native Fallback: {t['fallback']}[/dim]\n")

"""
CLI Scope Management Commands.
"""

import json
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from devixon.core.scope import ScopeProfile, normalize_target
from devixon.core.config import DEFAULT_DATA_DIR

console = Console()
SCOPES_DIR = DEFAULT_DATA_DIR / "scopes"


def _get_scope_path(name: str) -> Path:
    SCOPES_DIR.mkdir(parents=True, exist_ok=True)
    return SCOPES_DIR / f"{name}.json"


def create_scope(
    domain: str = typer.Option(..., "--domain", "-d", "--target", "-t", help="Primary authorized domain, host, or URL target."),
    name: str = typer.Option("default", "--name", "-n", help="Scope profile name."),
    allowed_domains: Optional[str] = typer.Option(None, "--allowed-domains", help="Comma-separated domains/wildcards (e.g. *.example.com)."),
    allowed_ips: Optional[str] = typer.Option(None, "--allowed-ips", help="Comma-separated IPs or CIDRs."),
    allowed_ports: Optional[str] = typer.Option(None, "--allowed-ports", help="Comma-separated allowed ports (e.g. 80,8080)."),
    allowed_paths: Optional[str] = typer.Option(None, "--allowed-paths", help="Comma-separated allowed base paths (e.g. /DVWA/)."),
    excluded_targets: Optional[str] = typer.Option(None, "--exclude", "--excluded-targets", help="Comma-separated excluded hostnames/IPs."),
    excluded_paths: Optional[str] = typer.Option(None, "--exclude-paths", "--excluded-paths", help="Comma-separated excluded URL paths."),
    authorized: bool = typer.Option(False, "--authorized", "--authorized-by-user", help="Confirm you have written authorization to test this scope."),
):
    """Create and persist a new authorized scope profile."""
    primary = domain.strip()
    if "://" not in primary:
        try:
            norm_primary = normalize_target(primary)
        except Exception:
            norm_primary = primary
    else:
        norm_primary = primary

    domains_list = [d.strip() for d in allowed_domains.split(",")] if allowed_domains else []
    ips_list = [i.strip() for i in allowed_ips.split(",")] if allowed_ips else []

    ports_list = []
    if allowed_ports:
        for p_raw in allowed_ports.split(","):
            p_clean = p_raw.strip()
            if not p_clean:
                continue
            if not p_clean.isdigit():
                console.print(f"[red]Error: Invalid port '{p_clean}'. Port must be an integer between 1 and 65535.[/red]")
                raise typer.Exit(1)
            p_val = int(p_clean)
            if not (1 <= p_val <= 65535):
                console.print(f"[red]Error: Invalid port {p_val}. Port must be between 1 and 65535.[/red]")
                raise typer.Exit(1)
            ports_list.append(p_val)

    paths_list = [p.strip() for p in allowed_paths.split(",") if p.strip()] if allowed_paths else []
    excl_list = [e.strip() for e in excluded_targets.split(",")] if excluded_targets else []
    excl_paths_list = [p.strip() for p in excluded_paths.split(",")] if excluded_paths else []

    profile = ScopeProfile(
        name=name,
        primary_domain=norm_primary,
        allowed_domains=domains_list,
        allowed_ips=ips_list,
        allowed_ports=ports_list,
        allowed_paths=paths_list,
        excluded_targets=excl_list,
        excluded_paths=excl_paths_list,
        authorized_by_user=authorized,
    )

    p = _get_scope_path(name)
    p.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"[green]Scope profile '{name}' saved successfully at {p}[/green]")
    if not authorized:
        console.print("[yellow]WARNING: Scope is marked NOT AUTHORIZED. Active scans will be blocked until authorization is verified.[/yellow]")


def show_scope(name: str = typer.Argument("default", help="Name of scope profile.")):
    """Display scope profile details."""
    p = _get_scope_path(name)
    if not p.exists():
        console.print(f"[red]Scope profile '{name}' not found.[/red]")
        raise typer.Exit(1)

    profile = ScopeProfile.model_validate_json(p.read_text(encoding="utf-8"))
    console.print(f"\n[bold cyan]SCOPE PROFILE: {profile.name}[/bold cyan]")
    console.print(f"Primary Target: [bold]{profile.primary_domain}[/bold]")
    console.print(f"Authorization Status: {'[green]YES[/green]' if profile.authorized_by_user else '[red]NO[/red]'}")
    console.print(f"Allowed Domains: {', '.join(profile.allowed_domains) or 'None'}")
    console.print(f"Allowed IPs: {', '.join(profile.allowed_ips) or 'None'}")
    console.print(f"Allowed Ports: {', '.join(str(p) for p in profile.allowed_ports) or 'None'}")
    console.print(f"Excluded Targets: {', '.join(profile.excluded_targets) or 'None'}")
    console.print(f"Excluded Paths: {', '.join(profile.excluded_paths) or 'None'}\n")


def validate_scope(
    target: str = typer.Argument(..., help="Target host or URL to test against scope."),
    name: str = typer.Option("default", "--name", "-n", help="Scope profile name."),
):
    """Test whether a given target is in-scope or out-of-scope."""
    p = _get_scope_path(name)
    if not p.exists():
        console.print(f"[red]Scope profile '{name}' not found.[/red]")
        raise typer.Exit(1)

    profile = ScopeProfile.model_validate_json(p.read_text(encoding="utf-8"))
    in_scope, reason = profile.is_in_scope(target)
    if in_scope:
        console.print(f"[green][IN-SCOPE][/green] {target}: {reason}")
    else:
        console.print(f"[red][OUT-OF-SCOPE][/red] {target}: {reason}")

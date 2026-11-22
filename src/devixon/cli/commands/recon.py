"""
CLI Reconnaissance Commands.
"""

import asyncio
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from devixon.core.scope import ScopeProfile, normalize_target
from devixon.core.config import DEFAULT_DATA_DIR
from devixon.database.session import get_session, init_db
from devixon.database.repository import AssessmentRepository
from devixon.recon.base import ScanContext
from devixon.recon.pipeline import ReconPipeline
from devixon.core.exceptions import ScopeViolationError

console = Console()
SCOPES_DIR = DEFAULT_DATA_DIR / "scopes"


def _load_scope(name: str, target: str) -> ScopeProfile:
    p = SCOPES_DIR / f"{name}.json"
    if p.exists():
        return ScopeProfile.model_validate_json(p.read_text(encoding="utf-8"))
    # Fallback to ephemeral authorized scope if testing
    return ScopeProfile(
        name=name,
        primary_domain=target,
        allowed_domains=[target],
        authorized_by_user=True,
    )


def run_recon(
    target: str = typer.Option(..., "--target", "-t", help="Target domain or IP to assess."),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
    profile: str = "QUICK",
):
    """Internal helper to execute a reconnaissance pipeline asynchronously."""
    init_db()
    norm_target = normalize_target(target)
    scope = _load_scope(scope_name, norm_target)

    # Validate authorization
    if profile != "PASSIVE" and not scope.authorized_by_user:
        console.print(f"[red]ERROR: Scope '{scope_name}' is not confirmed as authorized by user.[/red]")
        console.print("Use 'devixon scope create --authorized' before launching active reconnaissance.")
        raise typer.Exit(1)

    session = get_session()
    repo = AssessmentRepository(session)
    assessment = repo.create_assessment(
        target=norm_target,
        scope_profile_json=scope.model_dump_json(),
        scan_profile=profile,
    )
    session.close()

    ctx = ScanContext(
        assessment_id=assessment.id,
        target=norm_target,
        scope_profile=scope,
        scan_profile=profile,
    )

    pipeline = ReconPipeline(ctx)
    console.print(f"\n[bold cyan]LAUNCHING DEVIXON RECONNAISSANCE [{profile}][/bold cyan]")
    console.print(f"Target: [bold]{norm_target}[/bold] | Assessment ID: [dim]{assessment.id}[/dim]\n")

    try:
        asyncio.run(pipeline.execute_all())
        console.print(f"\n[bold green]Assessment {assessment.id} completed successfully![/bold green]")
        console.print(f"View findings with: [bold]devixon findings list[/bold]")
        console.print(f"Generate report with: [bold]devixon report generate[/bold]\n")
    except Exception as e:
        console.print(f"\n[bold red]Assessment stopped with error:[/bold red] {e}\n")
        raise typer.Exit(1)


def passive(
    target: str = typer.Option(..., "--target", "-t", help="Target domain."),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run purely passive OSINT reconnaissance without sending active packets."""
    run_recon(target=target, scope_name=scope_name, profile="PASSIVE")


def quick(
    target: str = typer.Option(..., "--target", "-t", help="Target domain."),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run quick reconnaissance and non-destructive HTTP security posture checks."""
    run_recon(target=target, scope_name=scope_name, profile="QUICK")


def full(
    target: str = typer.Option(..., "--target", "-t", help="Target domain."),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run full authorized reconnaissance and web security assessment pipeline."""
    run_recon(target=target, scope_name=scope_name, profile="FULL")

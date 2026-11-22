"""
CLI Reconnaissance Commands.
Includes subdomains, hosts, crawl, paths, urls, endpoints, full, quick, passive, status, resume, and cancel.
"""

import asyncio
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from devixon.core.scope import ScopeProfile
from devixon.core.target import CanonicalTarget, parse_canonical_target
from devixon.core.config import DEFAULT_DATA_DIR
from devixon.database.session import get_session, init_db
from devixon.database.repository import AssessmentRepository
from devixon.database.models import Assessment, ScanStage
from devixon.recon.base import ScanContext
from devixon.recon.pipeline import ReconPipeline
from devixon.core.exceptions import ScopeViolationError

console = Console()
SCOPES_DIR = DEFAULT_DATA_DIR / "scopes"


def _load_scope(name: str, target_model: CanonicalTarget) -> ScopeProfile:
    p = SCOPES_DIR / f"{name}.json"
    if p.exists():
        scope = ScopeProfile.model_validate_json(p.read_text(encoding="utf-8"))

        # Target-port authorization validation & backward-compatible scope alignment
        if target_model.port is not None and target_model.target_type == "URL":
            if scope.allowed_ports:
                if target_model.port not in scope.allowed_ports:
                    raise ScopeViolationError(
                        f"Target port {target_model.port} is NOT authorized in scope profile '{name}' (allowed ports: {scope.allowed_ports})."
                    )
            else:
                scope.allowed_ports = [target_model.port]

        # Target base-path confinement
        if target_model.base_path and target_model.base_path != "/":
            if not scope.allowed_paths:
                scope.allowed_paths = [target_model.base_path]
            elif target_model.base_path not in scope.allowed_paths:
                scope.allowed_paths.append(target_model.base_path)

        return scope

    allowed_domains = [target_model.hostname]
    allowed_ips = [target_model.hostname] if target_model.target_type == "IP" else []
    allowed_ports = [target_model.port] if target_model.port else []
    allowed_paths = [target_model.base_path] if target_model.base_path and target_model.base_path != "/" else []

    return ScopeProfile(
        name=name,
        primary_domain=target_model.canonical_url if target_model.target_type == "URL" else target_model.hostname,
        allowed_domains=allowed_domains,
        allowed_ips=allowed_ips,
        allowed_ports=allowed_ports,
        allowed_paths=allowed_paths,
        authorized_by_user=True,
    )


def run_recon(
    target: str,
    scope_name: str = "default",
    profile: str = "QUICK",
):
    """Internal helper to execute a reconnaissance pipeline asynchronously."""
    init_db()
    target_model = parse_canonical_target(target)
    scope = _load_scope(scope_name, target_model)

    # Validate authorization
    if profile != "PASSIVE" and not scope.authorized_by_user:
        console.print(f"[red]ERROR: Scope '{scope_name}' is not confirmed as authorized by user.[/red]")
        console.print("Use 'devixon scope create --authorized' before launching active reconnaissance.")
        raise typer.Exit(1)

    target_to_store = target_model.canonical_url if target_model.target_type == "URL" else target_model.hostname

    session = get_session()
    repo = AssessmentRepository(session)
    assessment = repo.create_assessment(
        target=target_to_store,
        scope_profile_json=scope.model_dump_json(),
        scan_profile=profile,
    )
    session.close()

    ctx = ScanContext(
        assessment_id=assessment.id,
        target=target_to_store,
        scope_profile=scope,
        scan_profile=profile,
        target_model=target_model,
    )

    pipeline = ReconPipeline(ctx)
    console.print(f"\n[bold cyan]LAUNCHING DEVIXON RECONNAISSANCE [{profile}][/bold cyan]")
    console.print(f"Target: [bold]{target_to_store}[/bold] | Assessment ID: [dim]{assessment.id}[/dim]\n")

    try:
        asyncio.run(pipeline.execute_all())
        console.print(f"\n[bold green]Assessment {assessment.id} completed successfully![/bold green]")
        console.print(f"View findings with: [bold]devixon findings list[/bold]")
        console.print(f"Generate report with: [bold]devixon report generate[/bold]\n")
    except Exception as e:
        console.print(f"\n[bold red]Assessment stopped with error:[/bold red] {e}\n")
        raise typer.Exit(1)


TARGET_HELP = "Target domain, IP address, or full HTTP/HTTPS URL."


def subdomains(
    target: str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run subdomain discovery and DNS enumeration only."""
    run_recon(target=target, scope_name=scope_name, profile="SUBDOMAINS")


def hosts(
    target: str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run live HTTP/HTTPS host and service discovery only."""
    run_recon(target=target, scope_name=scope_name, profile="HOSTS")


def crawl(
    target: str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run scope-governed web link crawler."""
    run_recon(target=target, scope_name=scope_name, profile="CRAWL")


def paths(
    target: str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run safe directory and file path discovery."""
    run_recon(target=target, scope_name=scope_name, profile="PATHS")


def urls(
    target: str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run historical URL intelligence from archives."""
    run_recon(target=target, scope_name=scope_name, profile="URLS")


def endpoints(
    target: str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run endpoint, API, and parameter extraction."""
    run_recon(target=target, scope_name=scope_name, profile="ENDPOINTS")


def passive(
    target: str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run purely passive OSINT reconnaissance without sending active packets."""
    run_recon(target=target, scope_name=scope_name, profile="PASSIVE")


def quick(
    target: str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run quick reconnaissance and non-destructive HTTP security posture checks."""
    run_recon(target=target, scope_name=scope_name, profile="QUICK")


def full(
    target: str = typer.Option(..., "--target", "-t", help=TARGET_HELP),
    scope_name: str = typer.Option("default", "--scope", "-s", help="Scope profile name."),
):
    """Run full authorized reconnaissance and web security assessment pipeline."""
    run_recon(target=target, scope_name=scope_name, profile="FULL")


def recon_status(
    assessment_id: Optional[str] = typer.Option(None, "--id", help="Assessment ID (defaults to latest)"),
):
    """Check status and stage progress of an assessment."""
    session = get_session()
    try:
        if assessment_id:
            assessment = session.query(Assessment).filter(Assessment.id == assessment_id).first()
        else:
            assessment = session.query(Assessment).order_by(Assessment.created_at.desc()).first()

        if not assessment:
            console.print("[yellow]No assessments found.[/yellow]")
            return

        console.print(f"\n[bold cyan]ASSESSMENT STATUS: {assessment.target} ({assessment.id[:8]})[/bold cyan]")
        console.print(f"Status: [bold]{assessment.status}[/bold] | Profile: {assessment.scan_profile}")
        console.print(f"Started: {assessment.start_time.strftime('%Y-%m-%d %H:%M:%S UTC') if assessment.start_time else 'N/A'}")
        console.print(f"Ended: {assessment.end_time.strftime('%Y-%m-%d %H:%M:%S UTC') if assessment.end_time else 'N/A'}\n")

        stages = session.query(ScanStage).filter(ScanStage.assessment_id == assessment.id).all()
        if stages:
            table = Table(title="Pipeline Stage Execution Status", show_header=True, header_style="bold green")
            table.add_column("Stage ID", style="dim")
            table.add_column("Name", style="bold")
            table.add_column("Status", style="cyan")
            table.add_column("Duration", justify="right")

            for s in stages:
                table.add_row(
                    s.stage_id,
                    s.name,
                    s.status,
                    f"{s.duration:.2f}s" if s.duration else "-",
                )
            console.print(table)
            console.print("")
    finally:
        session.close()


def recon_resume(
    assessment_id: str = typer.Argument(..., help="Assessment ID to resume"),
):
    """Resume an interrupted assessment."""
    session = get_session()
    try:
        assessment = session.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            console.print(f"[red]Assessment '{assessment_id}' not found.[/red]")
            return
        console.print(f"[green]Resuming assessment {assessment_id} for {assessment.target}...[/green]")
        scope = ScopeProfile.model_validate_json(assessment.scope_profile_json)
        ctx = ScanContext(
            assessment_id=assessment.id,
            target=assessment.target,
            scope_profile=scope,
            scan_profile=assessment.scan_profile,
        )
        pipeline = ReconPipeline(ctx)
        asyncio.run(pipeline.execute_all())
        console.print("[bold green]Assessment resumed and completed successfully![/bold green]")
    finally:
        session.close()


def recon_cancel(
    assessment_id: Optional[str] = typer.Option(None, "--id", help="Assessment ID (defaults to latest)"),
):
    """Mark an active assessment as cancelled."""
    session = get_session()
    try:
        if assessment_id:
            assessment = session.query(Assessment).filter(Assessment.id == assessment_id).first()
        else:
            assessment = session.query(Assessment).order_by(Assessment.created_at.desc()).first()

        if not assessment:
            console.print("[yellow]No assessments found.[/yellow]")
            return

        assessment.status = "CANCELLED"
        session.commit()
        console.print(f"[yellow]Assessment {assessment.id[:8]} marked as CANCELLED.[/yellow]")
    finally:
        session.close()

"""
CLI Assets and Endpoints Management Commands.
Displays real data from Asset, Subdomain, LiveHost, InternalLink, Endpoint, and Parameter models.
"""

import json
import csv
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from devixon.database.session import get_session
from devixon.database.models import Asset, Subdomain, LiveHost, Endpoint, Parameter, Assessment

console = Console()


def list_assets():
    """List discovered assets, subdomains, and live hosts."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found.[/yellow]")
            return

        subdomains = session.query(Subdomain).filter(Subdomain.assessment_id == latest.id).all()
        live_hosts = session.query(LiveHost).filter(LiveHost.assessment_id == latest.id).all()

        table = Table(title=f"Discovered Subdomains & Hosts ({latest.target})", show_header=True, header_style="bold green")
        table.add_column("Subdomain / Host", style="bold cyan")
        table.add_column("Resolved IP", style="white")
        table.add_column("Resolution Status", style="dim")
        table.add_column("HTTP Live Status", style="green")
        table.add_column("Source", style="dim")

        live_map = {lh.host: lh for lh in live_hosts}

        for s in subdomains:
            lh = live_map.get(s.subdomain)
            http_status = f"HTTP {lh.status_code} ({lh.title or 'OK'})" if lh else "No Web Service"
            table.add_row(
                s.subdomain,
                s.resolved_ip or "Unresolved",
                s.resolution_status,
                http_status,
                s.discovery_source,
            )

        console.print("\n")
        console.print(table)
        console.print(f"\nTotal: {len(subdomains)} subdomains ({len(live_hosts)} live HTTP hosts)\n")
    finally:
        session.close()


def inspect_asset(hostname: str = typer.Argument(..., help="Asset hostname to inspect")):
    """Inspect an asset and its associated services, technologies, live hosts, and findings."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found.[/yellow]")
            return

        sub = session.query(Subdomain).filter(Subdomain.subdomain == hostname).first()
        live = session.query(LiveHost).filter(LiveHost.host == hostname).first()
        asset = session.query(Asset).filter(Asset.hostname == hostname).first()

        if not sub and not live and not asset:
            console.print(f"[red]Asset '{hostname}' not found.[/red]")
            return

        console.print(f"\n[bold cyan]ASSET RECONNAISSANCE INTELLIGENCE: {hostname}[/bold cyan]")
        resolved_ip = (sub.resolved_ip if sub else None) or (asset.ip_address if asset else None) or "Unresolved"
        res_status = sub.resolution_status if sub else "UNKNOWN"
        console.print(f"IP: [bold]{resolved_ip}[/bold] | DNS Status: {res_status}")

        if live:
            console.print(f"Live URL: {live.url} | Status: HTTP {live.status_code} | Server: {live.web_server or 'Unknown'}")
            console.print(f"Page Title: {live.title or 'None'} | Response Time: {live.response_time_ms} ms")
            if live.technologies_json:
                console.print(f"Technologies: {live.technologies_json}")

        if asset and asset.findings:
            console.print(f"\n[bold red]Associated Security Findings ({len(asset.findings)}):[/bold red]")
            for f in asset.findings:
                console.print(f"  - [{f.severity}] {f.title} ({f.verification_status})")
        console.print("")
    finally:
        session.close()


def export_assets(
    out: Path = typer.Option(Path("assets_export.json"), "--out", "-o", help="Output export file path (.json or .csv)"),
):
    """Export assets inventory to JSON or CSV."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found to export.[/yellow]")
            return

        subdomains = session.query(Subdomain).filter(Subdomain.assessment_id == latest.id).all()
        out.parent.mkdir(parents=True, exist_ok=True)

        if out.suffix.lower() == ".csv":
            with open(out, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Subdomain", "Resolved_IP", "Status", "Source"])
                for s in subdomains:
                    writer.writerow([s.subdomain, s.resolved_ip or "", s.resolution_status, s.discovery_source])
        else:
            data = [
                {
                    "subdomain": s.subdomain,
                    "resolved_ip": s.resolved_ip,
                    "resolution_status": s.resolution_status,
                    "discovery_source": s.discovery_source,
                }
                for s in subdomains
            ]
            out.write_text(json.dumps(data, indent=2), encoding="utf-8")

        console.print(f"[green]Assets successfully exported to:[/green] {out}")
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

        endpoints = session.query(Endpoint).filter(Endpoint.assessment_id == latest.id).all()

        table = Table(title=f"Discovered Endpoints ({latest.target})", show_header=True, header_style="bold green")
        table.add_column("Method", style="bold")
        table.add_column("Path", style="cyan")
        table.add_column("Parameters", style="yellow")
        table.add_column("Origin", style="dim")

        for ep in endpoints[:60]:
            origin = "[dim]Historical[/dim]" if ep.is_historical else "[green]Crawl[/green]"
            table.add_row(
                ep.method,
                ep.path,
                ep.params or "-",
                origin,
            )

        console.print("\n")
        console.print(table)
        console.print(f"\nTotal: {len(endpoints)} endpoints recorded\n")
    finally:
        session.close()


def inspect_endpoint(endpoint_id: str = typer.Argument(..., help="Endpoint ID or path")):
    """Inspect endpoint parameters and methods."""
    session = get_session()
    try:
        ep = session.query(Endpoint).filter(
            (Endpoint.id.like(f"{endpoint_id}%")) | (Endpoint.path == endpoint_id)
        ).first()
        if not ep:
            console.print(f"[red]Endpoint '{endpoint_id}' not found.[/red]")
            return

        console.print(f"\n[bold cyan]ENDPOINT DETAILS: {ep.url}[/bold cyan]")
        console.print(f"Path: {ep.path} | Method: {ep.method} | Historical: {ep.is_historical}")
        console.print(f"Discovery Source: {ep.discovery_source}")

        params = session.query(Parameter).filter(Parameter.endpoint_id == ep.id).all()
        if params:
            console.print("\n[bold]Parameters:[/bold]")
            for p in params:
                console.print(f"  - {p.name} ({p.param_type}) [Example: {p.example_value or '-'}]")
        console.print("")
    finally:
        session.close()


def export_endpoints(
    out: Path = typer.Option(Path("endpoints_export.json"), "--out", "-o", help="Output export file path (.json or .csv)"),
):
    """Export endpoints inventory to JSON or CSV."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found to export.[/yellow]")
            return

        endpoints = session.query(Endpoint).filter(Endpoint.assessment_id == latest.id).all()
        out.parent.mkdir(parents=True, exist_ok=True)

        if out.suffix.lower() == ".csv":
            with open(out, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Path", "Method", "Params", "Historical", "Source"])
                for ep in endpoints:
                    writer.writerow([ep.url, ep.path, ep.method, ep.params or "", ep.is_historical, ep.discovery_source])
        else:
            data = [
                {
                    "url": ep.url,
                    "path": ep.path,
                    "method": ep.method,
                    "params": ep.params,
                    "is_historical": ep.is_historical,
                    "discovery_source": ep.discovery_source,
                }
                for ep in endpoints
            ]
            out.write_text(json.dumps(data, indent=2), encoding="utf-8")

        console.print(f"[green]Endpoints successfully exported to:[/green] {out}")
    finally:
        session.close()

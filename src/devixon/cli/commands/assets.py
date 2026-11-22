"""
CLI Assets and Endpoints Management Commands.
"""

import json
import csv
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from devixon.database.session import get_session
from devixon.database.models import Asset, Endpoint, Assessment

console = Console()


def list_assets():
    """List discovered assets and resolved IP addresses."""
    session = get_session()
    try:
        latest = session.query(Assessment).order_by(Assessment.created_at.desc()).first()
        if not latest:
            console.print("[yellow]No assessments found.[/yellow]")
            return

        assets = session.query(Asset).filter(Asset.assessment_id == latest.id).all()
        table = Table(title=f"Discovered Assets ({latest.target})", show_header=True, header_style="bold green")
        table.add_column("Hostname", style="bold cyan")
        table.add_column("IP Address", style="white")
        table.add_column("Type", style="dim")
        table.add_column("Scope Status", style="green")
        table.add_column("Source", style="dim")

        for a in assets:
            table.add_row(
                a.hostname,
                a.ip_address or "Unresolved",
                a.asset_type,
                a.scope_status,
                a.discovery_source,
            )

        console.print("\n")
        console.print(table)
        console.print(f"\nTotal: {len(assets)} assets\n")
    finally:
        session.close()


def inspect_asset(hostname: str = typer.Argument(..., help="Asset hostname to inspect")):
    """Inspect an asset and its associated services, endpoints, and findings."""
    session = get_session()
    try:
        asset = session.query(Asset).filter(Asset.hostname == hostname).first()
        if not asset:
            console.print(f"[red]Asset '{hostname}' not found.[/red]")
            return

        console.print(f"\n[bold cyan]ASSET DETAILS: {asset.hostname}[/bold cyan]")
        console.print(f"IP: {asset.ip_address or 'Unresolved'} | Type: {asset.asset_type} | Scope: {asset.scope_status}")
        console.print(f"Discovery Source: {asset.discovery_source}")

        if asset.services:
            console.print("\n[bold]Services / Open Ports:[/bold]")
            for s in asset.services:
                console.print(f"  - Port {s.port}/{s.protocol} ({s.service_name}) [Confidence: {s.confidence}]")

        if asset.findings:
            console.print(f"\n[bold red]Associated Findings ({len(asset.findings)}):[/bold red]")
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

        assets = session.query(Asset).filter(Asset.assessment_id == latest.id).all()
        out.parent.mkdir(parents=True, exist_ok=True)

        if out.suffix.lower() == ".csv":
            with open(out, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Hostname", "IP", "Type", "Scope", "Source"])
                for a in assets:
                    writer.writerow([a.hostname, a.ip_address or "", a.asset_type, a.scope_status, a.discovery_source])
        else:
            data = [
                {
                    "hostname": a.hostname,
                    "ip_address": a.ip_address,
                    "asset_type": a.asset_type,
                    "scope_status": a.scope_status,
                    "discovery_source": a.discovery_source,
                }
                for a in assets
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

        endpoints = (
            session.query(Endpoint)
            .join(Asset)
            .filter(Asset.assessment_id == latest.id)
            .all()
        )

        table = Table(title=f"Discovered Endpoints ({latest.target})", show_header=True, header_style="bold green")
        table.add_column("Method", style="bold")
        table.add_column("Path", style="cyan")
        table.add_column("Parameters", style="yellow")
        table.add_column("Status Code", style="dim")

        for ep in endpoints[:50]:
            table.add_row(
                ep.method,
                ep.path,
                ep.params or "-",
                str(ep.status_code or "-"),
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
        console.print(f"Path: {ep.path} | Method: {ep.method} | Status: {ep.status_code or 'Unknown'}")
        console.print(f"Parameters: {ep.params or 'None'} | Content-Type: {ep.content_type or 'Unknown'}\n")
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

        endpoints = (
            session.query(Endpoint)
            .join(Asset)
            .filter(Asset.assessment_id == latest.id)
            .all()
        )
        out.parent.mkdir(parents=True, exist_ok=True)

        if out.suffix.lower() == ".csv":
            with open(out, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Path", "Method", "Params", "Status"])
                for ep in endpoints:
                    writer.writerow([ep.url, ep.path, ep.method, ep.params or "", ep.status_code or ""])
        else:
            data = [
                {
                    "url": ep.url,
                    "path": ep.path,
                    "method": ep.method,
                    "params": ep.params,
                    "status_code": ep.status_code,
                }
                for ep in endpoints
            ]
            out.write_text(json.dumps(data, indent=2), encoding="utf-8")

        console.print(f"[green]Endpoints successfully exported to:[/green] {out}")
    finally:
        session.close()

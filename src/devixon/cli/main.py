"""
DEVIXON Master CLI Application.
"""

import typer
from rich.console import Console
from devixon import __version__
from devixon.cli.commands.doctor import doctor_command
from devixon.cli.commands.setup import setup_command
from devixon.cli.commands.selftest import selftest_command
from devixon.cli.commands import scope as scope_cmd
from devixon.cli.commands import recon as recon_cmd
from devixon.cli.commands import findings as findings_cmd
from devixon.cli.commands import assets as assets_cmd
from devixon.cli.commands import report as report_cmd
from devixon.cli.commands import ai as ai_cmd

console = Console()

app = typer.Typer(
    name="devixon",
    help="DEVIXON: AI-Assisted Reconnaissance & Security Assessment Framework",
    add_completion=False,
)

# Root level commands
app.command(name="doctor", help="Run system and external tool diagnostics.")(doctor_command)
app.command(name="setup", help="Interactive setup and onboarding wizard.")(setup_command)
app.command(name="self-test", help="Run internal validation self-tests.")(selftest_command)

# Subcommand groups
scope_app = typer.Typer(help="Manage authorized scope profiles.")
scope_app.command(name="create")(scope_cmd.create_scope)
scope_app.command(name="show")(scope_cmd.show_scope)
scope_app.command(name="validate")(scope_cmd.validate_scope)
app.add_typer(scope_app, name="scope")

recon_app = typer.Typer(help="Execute reconnaissance pipelines.")
recon_app.command(name="passive")(recon_cmd.passive)
recon_app.command(name="quick")(recon_cmd.quick)
recon_app.command(name="full")(recon_cmd.full)
app.add_typer(recon_app, name="recon")

findings_app = typer.Typer(help="Inspect and verify security findings.")
findings_app.command(name="list")(findings_cmd.list_findings)
findings_app.command(name="inspect")(findings_cmd.inspect_finding)
findings_app.command(name="verify")(findings_cmd.verify_finding)
app.add_typer(findings_app, name="findings")

assets_app = typer.Typer(help="Manage discovered assets inventory.")
assets_app.command(name="list")(assets_cmd.list_assets)
app.add_typer(assets_app, name="assets")

endpoints_app = typer.Typer(help="Manage discovered web endpoints.")
endpoints_app.command(name="list")(assets_cmd.list_endpoints)
app.add_typer(endpoints_app, name="endpoints")

report_app = typer.Typer(help="Generate assessment reports in HTML, Markdown, JSON, and CSV.")
report_app.command(name="generate")(report_cmd.generate_report)
app.add_typer(report_app, name="report")

ai_app = typer.Typer(help="AI-assisted evidence analysis.")
ai_app.command(name="analyze")(ai_cmd.analyze_ai)
app.add_typer(ai_app, name="ai")


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]DEVIXON[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show DEVIXON version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
):
    """
    DEVIXON — Terminal-first security assessment and reconnaissance framework.
    """
    pass


if __name__ == "__main__":
    app()

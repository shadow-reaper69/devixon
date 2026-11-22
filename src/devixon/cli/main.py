"""
DEVIXON Master CLI Application.
"""

import typer
from rich.console import Console
from devixon import __version__
from devixon.cli.commands.doctor import doctor_command
from devixon.cli.commands.setup import setup_command
from devixon.cli.commands.selftest import selftest_command
from devixon.cli.commands import config as config_cmd
from devixon.cli.commands import target as target_cmd
from devixon.cli.commands import scope as scope_cmd
from devixon.cli.commands import recon as recon_cmd
from devixon.cli.commands import findings as findings_cmd
from devixon.cli.commands import assets as assets_cmd
from devixon.cli.commands import paths as paths_cmd
from devixon.cli.commands import report as report_cmd
from devixon.cli.commands import ai as ai_cmd
from devixon.cli.commands import tools as tools_cmd
from devixon.cli.commands import database as db_cmd

console = Console()

app = typer.Typer(
    name="devixon",
    help="DEVIXON: AI-Assisted Reconnaissance & Security Assessment Framework",
    add_completion=False,
)

# Root level diagnostic commands
app.command(name="doctor", help="Run system and external tool diagnostics.")(doctor_command)
app.command(name="setup", help="Interactive setup and onboarding wizard.")(setup_command)
app.command(name="self-test", help="Run internal validation self-tests.")(selftest_command)

# Config subcommands
config_app = typer.Typer(help="Inspect and validate DEVIXON configuration.")
config_app.command(name="show")(config_cmd.show_config)
config_app.command(name="validate")(config_cmd.validate_config)
app.add_typer(config_app, name="config")

# Target subcommands
target_app = typer.Typer(help="Manage target asset registry.")
target_app.command(name="add")(target_cmd.add_target)
target_app.command(name="list")(target_cmd.list_targets)
target_app.command(name="inspect")(target_cmd.inspect_target)
app.add_typer(target_app, name="target")

# Scope subcommands
scope_app = typer.Typer(help="Manage authorized scope profiles.")
scope_app.command(name="create")(scope_cmd.create_scope)
scope_app.command(name="show")(scope_cmd.show_scope)
scope_app.command(name="validate")(scope_cmd.validate_scope)
app.add_typer(scope_app, name="scope")

# Recon subcommands
recon_app = typer.Typer(help="Execute reconnaissance pipelines.")
recon_app.command(name="subdomains")(recon_cmd.subdomains)
recon_app.command(name="hosts")(recon_cmd.hosts)
recon_app.command(name="crawl")(recon_cmd.crawl)
recon_app.command(name="paths")(recon_cmd.paths)
recon_app.command(name="urls")(recon_cmd.urls)
recon_app.command(name="endpoints")(recon_cmd.endpoints)
recon_app.command(name="passive")(recon_cmd.passive)
recon_app.command(name="quick")(recon_cmd.quick)
recon_app.command(name="full")(recon_cmd.full)
recon_app.command(name="status")(recon_cmd.recon_status)
recon_app.command(name="resume")(recon_cmd.recon_resume)
recon_app.command(name="cancel")(recon_cmd.recon_cancel)
app.add_typer(recon_app, name="recon")

# Findings subcommands
findings_app = typer.Typer(help="Inspect, verify, and manage security findings.")
findings_app.command(name="list")(findings_cmd.list_findings)
findings_app.command(name="inspect")(findings_cmd.inspect_finding)
findings_app.command(name="update")(findings_cmd.update_finding)
findings_app.command(name="verify")(findings_cmd.verify_finding)
findings_app.command(name="dismiss")(findings_cmd.dismiss_finding)
app.add_typer(findings_app, name="findings")

# Assets subcommands
assets_app = typer.Typer(help="Manage discovered assets inventory.")
assets_app.command(name="list")(assets_cmd.list_assets)
assets_app.command(name="inspect")(assets_cmd.inspect_asset)
assets_app.command(name="export")(assets_cmd.export_assets)
app.add_typer(assets_app, name="assets")

# Endpoints subcommands
endpoints_app = typer.Typer(help="Manage discovered web endpoints.")
endpoints_app.command(name="list")(assets_cmd.list_endpoints)
endpoints_app.command(name="inspect")(assets_cmd.inspect_endpoint)
endpoints_app.command(name="export")(assets_cmd.export_endpoints)
app.add_typer(endpoints_app, name="endpoints")

# Paths subcommands
paths_app = typer.Typer(help="Manage discovered files and directories.")
paths_app.command(name="list")(paths_cmd.list_paths)
app.add_typer(paths_app, name="paths")

# Report subcommands
report_app = typer.Typer(help="Generate and export assessment reports.")
report_app.command(name="generate")(report_cmd.generate_report)
report_app.command(name="list")(report_cmd.list_reports)
report_app.command(name="export")(report_cmd.export_report)
app.add_typer(report_app, name="report")

# AI subcommands
ai_app = typer.Typer(help="AI-assisted evidence analysis.")
ai_app.command(name="analyze")(ai_cmd.analyze_ai)
ai_app.command(name="summarize")(ai_cmd.summarize_ai)
ai_app.command(name="explain")(ai_cmd.explain_ai)
ai_app.command(name="remediate")(ai_cmd.remediate_ai)
app.add_typer(ai_app, name="ai")

# Tools subcommands
tools_app = typer.Typer(help="Reconnaissance tool integrations and installation guides.")
tools_app.command(name="check")(tools_cmd.check_tools)
tools_app.command(name="install-guide")(tools_cmd.install_guide)
app.add_typer(tools_app, name="tools")

# Database subcommands
db_app = typer.Typer(help="Database backup and restore.")
db_app.command(name="backup")(db_cmd.backup_database)
db_app.command(name="restore")(db_cmd.restore_database)
app.add_typer(db_app, name="database")


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

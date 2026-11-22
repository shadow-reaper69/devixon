"""
CLI Setup and Onboarding Wizard.
"""

import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm
from devixon.core.config import load_config, save_config, AppConfig
from devixon.database.session import init_db

console = Console()


def setup_command():
    """Interactive onboarding wizard to configure DEVIXON."""
    console.print("\n[bold cyan]DEVIXON INITIAL SETUP & ONBOARDING[/bold cyan]\n")

    cfg = load_config()

    profile = Prompt.ask(
        "Select default scan profile",
        choices=["QUICK", "PASSIVE", "FULL"],
        default=cfg.default_profile,
    )
    cfg.default_profile = profile

    enable_ai = Confirm.ask("Enable AI-assisted analysis?", default=cfg.ai.enabled)
    cfg.ai.enabled = enable_ai

    if enable_ai:
        provider = Prompt.ask(
            "Select AI provider",
            choices=["openai", "ollama", "local"],
            default=cfg.ai.provider,
        )
        cfg.ai.provider = provider
        model = Prompt.ask("Model name", default=cfg.ai.model)
        cfg.ai.model = model

    save_config(cfg)
    console.print("[green]Configuration saved successfully.[/green]")

    console.print("Initializing SQLite database schema...")
    init_db()
    console.print("[green]Database initialized successfully.[/green]")
    console.print("\n[bold]Setup complete! Run 'devixon doctor' or 'devixon scope create' to get started.[/bold]\n")

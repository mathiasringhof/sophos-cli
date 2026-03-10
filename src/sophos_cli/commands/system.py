"""Explicit system command tree placeholder."""

import typer

system_app = typer.Typer(no_args_is_help=True, help="Inspect and update system-level backup, notification, and retention resources.")

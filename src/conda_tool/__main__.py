#!/usr/bin/env python3
"""Conda Tool CLI with subcommand support."""

import argparse
import importlib
import sys

TOOLS: dict[str, str] = {
    "makedb": "Create package database from conda-forge",
    "dlpkg": "Download conda-forge package and create feedstock",
    "extract": "Extract conda constructor sh package",
    "modify": "Modify conda package contents",
    "repack": "Repack modified conda constructor sh package",
}


def main() -> None:
    """Dispatch to the requested subcommand module."""
    # Main parser with automatic help disabled so each tool can handle it.
    main_parser = argparse.ArgumentParser(
        description="Conda Tool - A Swiss Army knife for conda packages", add_help=False
    )
    main_parser.add_argument(
        "-V", "--version", action="store_true", help="Show version and exit"
    )

    # Subcommand parser.
    subparsers = main_parser.add_subparsers(title="available commands", dest="command")

    # Register all subcommands without adding their individual arguments yet.
    subcommands = {}
    for tool, help_text in TOOLS.items():
        subcommands[tool] = subparsers.add_parser(
            tool,
            help=help_text,
            add_help=False,  # Each tool handles its own help output.
        )

    # Parse the command name first.
    main_args, remaining = main_parser.parse_known_args()

    # Handle version requests.
    if main_args.version:
        print(f"conda-tool {importlib.import_module('conda_tool').__version__}")
        return

    # Ensure a valid subcommand was provided.
    if not main_args.command:
        main_parser.print_help()
        print("\nError: missing command")
        sys.exit(1)

    # Import the selected tool module.
    try:
        tool_module = importlib.import_module(f"conda_tool.{main_args.command}")
    except ImportError:
        print(f"Error: unknown command '{main_args.command}'", file=sys.stderr)
        sys.exit(1)

    # Rebuild sys.argv as tool name plus remaining arguments.
    sys.argv = [f"{main_args.command}.py"] + remaining

    # Execute the tool entry point.
    try:
        tool_module.main()
    except SystemExit:
        # Allow tools to exit on their own, such as after printing help.
        pass
    except Exception as e:
        print(f"Error in {main_args.command}: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

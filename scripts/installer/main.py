#!/usr/bin/env python3
"""HexStrike AI Installer - Main CLI Entry Point

Automated security tool installation for Kali/Parrot Linux.
Reduces setup time from 45+ minutes to 3-15 minutes.
"""

import sys
import click
from pathlib import Path
from typing import List, Dict, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import core modules
from scripts.installer.core.os_detector import OSDetector, UnsupportedOSError
from scripts.installer.core.tool_manager import ToolManager
from scripts.installer.core.reporter import Reporter
from scripts.installer.core.dependency_checker import DependencyChecker, DependencyError

# Import modes
from scripts.installer.modes.quick import get_quick_tools
from scripts.installer.modes.standard import get_standard_tools
from scripts.installer.modes.complete import get_complete_tools

# Import categories
from scripts.installer.categories.network import get_network_tools
from scripts.installer.categories.web import get_web_tools
from scripts.installer.categories.cloud import get_cloud_tools
from scripts.installer.categories.binary import get_binary_tools
from scripts.installer.categories.mobile import get_mobile_tools
from scripts.installer.categories.forensics import get_forensics_tools

console = Console()

# Category mapping
CATEGORY_FUNCTIONS = {
    'network': get_network_tools,
    'web': get_web_tools,
    'cloud': get_cloud_tools,
    'binary': get_binary_tools,
    'mobile': get_mobile_tools,
    'forensics': get_forensics_tools,
}


def validate_categories(categories: str) -> None:
    """Validate category names are valid

    Args:
        categories: Comma-separated category names

    Raises:
        ValueError: If invalid category provided
    """
    if not categories:
        return

    for cat in categories.split(','):
        cat = cat.strip()
        if cat not in CATEGORY_FUNCTIONS:
            raise ValueError(
                f"Invalid category '{cat}'. "
                f"Valid categories: {', '.join(CATEGORY_FUNCTIONS.keys())}"
            )


@click.command()
@click.option(
    '--mode',
    type=click.Choice(['quick', 'standard', 'complete'], case_sensitive=False),
    default='standard',
    help='Installation mode: quick (20 tools), standard (36 tools), complete (54+ tools)'
)
@click.option(
    '--categories',
    help='Comma-separated categories to install (e.g., network,web,cloud)'
)
@click.option(
    '--dry-run',
    is_flag=True,
    help='Show what would be installed without actually installing'
)
@click.option(
    '--output',
    type=click.Choice(['cli', 'html', 'json'], case_sensitive=False),
    default='cli',
    help='Output format for installation report'
)
@click.option(
    '--skip-checks',
    is_flag=True,
    help='Skip dependency checks (for advanced users)'
)
def main(mode: str, categories: str, dry_run: bool, output: str, skip_checks: bool) -> None:
    """HexStrike AI Installer - Automated Security Tool Installation

    Install 105+ security tools for penetration testing, bug bounty hunting,
    and security research on Kali/Parrot Linux.

    Examples:

        # Quick installation (20 essential tools, ~5 minutes)
        python main.py --mode quick

        # Standard installation (36 tools, ~15 minutes)
        python main.py --mode standard

        # Install specific categories
        python main.py --categories network,web

        # Dry run (preview without installing)
        python main.py --mode quick --dry-run

        # Generate HTML report
        python main.py --mode standard --output html
    """
    try:
        # Print banner
        console.print("\n[bold red]🛡️  HexStrike AI Installer v7.0[/bold red]")
        console.print("[dim]Automated Security Tool Installation[/dim]\n")

        # Step 0: Pre-flight dependency checks (unless skipped)
        if not skip_checks:
            console.print("[bold cyan]0. Checking dependencies...[/bold cyan]")
            dependency_checker = DependencyChecker()
            results = dependency_checker.check_all(raise_on_failure=False)

            # Display check results
            all_passed = True
            for result in results.values():
                status = "✓" if result.passed else "✗"
                color = "green" if result.passed else "yellow"
                console.print(f"   [{color}]{status}[/{color}] {result.name}: {result.message}")
                if not result.passed:
                    all_passed = False

            if not all_passed:
                console.print("\n[yellow]⚠ Some dependency checks failed. Installation may not work correctly.[/yellow]")
                console.print("[dim]Use --skip-checks to bypass these checks (not recommended)[/dim]\n")

            console.print()

        # Step 1: Detect and verify OS
        console.print("[bold cyan]1. Detecting operating system...[/bold cyan]")
        os_detector = OSDetector()
        os_info = os_detector.detect_os()
        console.print(f"   ✓ Detected: {os_info.name} {os_info.version}")

        os_detector.verify_supported_os()
        console.print("   ✓ OS is supported\n")

        # Step 2: Determine tool list
        console.print("[bold cyan]2. Building tool list...[/bold cyan]")

        # Get tools from mode
        if mode == 'quick':
            tools = get_quick_tools()
            console.print(f"   ✓ Mode: Quick ({len(tools)} tools)")
        elif mode == 'standard':
            tools = get_standard_tools()
            console.print(f"   ✓ Mode: Standard ({len(tools)} tools)")
        else:  # complete
            tools = get_complete_tools()
            console.print(f"   ✓ Mode: Complete ({len(tools)} tools)")

        # Filter by categories if specified
        if categories:
            validate_categories(categories)
            cat_tools = set()
            for cat in categories.split(','):
                cat = cat.strip()
                cat_func = CATEGORY_FUNCTIONS[cat]
                cat_tools.update(cat_func())

            # Intersect with mode tools
            tools = list(set(tools) & cat_tools)
            console.print(f"   ✓ Categories: {categories}")
            console.print(f"   ✓ Filtered to {len(tools)} tools\n")
        else:
            console.print()

        if len(tools) == 0:
            console.print("[yellow]⚠ No tools match the criteria[/yellow]")
            sys.exit(0)

        # Step 3: Scan existing tools
        console.print("[bold cyan]3. Scanning installed tools...[/bold cyan]")
        tool_manager = ToolManager(os_detector)
        installed, missing = tool_manager.scan_tools(tools)

        console.print(f"   ✓ Already installed: [green]{len(installed)}[/green]")
        console.print(f"   ✓ To be installed: [yellow]{len(missing)}[/yellow]\n")

        # Step 4: Install tools (if not dry-run)
        if dry_run:
            console.print("[bold yellow]🔍 DRY RUN - No changes will be made[/bold yellow]\n")
            results = {
                'total': len(tools),
                'installed': [{'name': t, 'version': 'unknown', 'category': 'unknown'} for t in installed],
                'missing': [{'name': t, 'package': t, 'category': 'unknown'} for t in missing],
                'failed': []
            }
        else:
            console.print("[bold cyan]4. Installing tools...[/bold cyan]")
            results = {
                'total': len(tools),
                'installed': [],
                'missing': [],
                'failed': []
            }

            # Install missing tools with progress
            if missing:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task(f"Installing {len(missing)} tools...", total=len(missing))

                    for tool in missing:
                        progress.update(task, description=f"Installing {tool}...")
                        result = tool_manager.install_tool(tool)

                        if result.success:
                            results['installed'].append({
                                'name': tool,
                                'version': 'installed',
                                'category': tool_manager.get_category(tool)
                            })
                        else:
                            results['failed'].append({
                                'name': tool,
                                'error': result.error
                            })

                        progress.advance(task)

            console.print(f"\n   ✓ Installation complete\n")

        # Step 5: Generate report
        console.print("[bold cyan]5. Generating report...[/bold cyan]")
        reporter = Reporter()

        if output == 'html':
            output_file = 'hexstrike_install_report.html'
            reporter.generate_html_report(results, output_file)
            console.print(f"   ✓ HTML report: {output_file}\n")

        elif output == 'json':
            output_file = 'hexstrike_install_report.json'
            reporter.export_json(results, output_file)
            console.print(f"   ✓ JSON report: {output_file}\n")

        else:  # cli
            reporter.show_summary(results)

        # Success summary
        console.print("[bold green]✨ Installation complete![/bold green]")
        if dry_run:
            console.print(f"[dim]Dry run completed - {len(missing)} tools would be installed[/dim]\n")
        else:
            console.print(f"[dim]Installed {len(results['installed'])} tools successfully[/dim]\n")

    except DependencyError as e:
        console.print(f"\n[bold red]❌ Dependency Error:[/bold red]")
        console.print(f"[red]{e}[/red]")
        console.print("\n[dim]Please resolve dependency issues before installing.[/dim]")
        console.print("[dim]Use --skip-checks to bypass (not recommended)[/dim]\n")
        sys.exit(1)

    except UnsupportedOSError as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}")
        console.print("[dim]This installer only supports Kali Linux and Parrot OS[/dim]\n")
        sys.exit(1)

    except ValueError as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}\n")
        sys.exit(1)

    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠ Installation cancelled by user[/yellow]\n")
        sys.exit(130)

    except Exception as e:
        console.print(f"\n[bold red]❌ Unexpected error:[/bold red] {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

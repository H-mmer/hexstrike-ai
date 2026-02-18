"""Multi-Format Reporting for Installation Results"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


class Reporter:
    """Generate reports in multiple formats (CLI, HTML, JSON)"""

    def __init__(self, use_colors: bool = True):
        self.console = Console() if use_colors else Console(no_color=True)
        self.template_dir = Path('scripts/installer/templates')

    def show_progress(self, description: str):
        """Create and return a progress bar"""
        return Progress()

    def show_summary(self, results: Dict[str, Any]):
        """Display terminal summary table"""
        total = results.get('total', 0)
        installed = len(results.get('installed', []))
        missing = len(results.get('missing', []))
        failed = len(results.get('failed', []))

        self.console.print("\n[bold]Installation Summary:[/bold]")
        self.console.print(f"  Total tools: {total}")
        self.console.print(f"  [green]Installed: {installed} ({installed/total*100:.1f}%)[/green]")
        self.console.print(f"  [yellow]Missing: {missing} ({missing/total*100:.1f}%)[/yellow]")
        if failed > 0:
            self.console.print(f"  [red]Failed: {failed}[/red]")

        # Show installed tools table
        if results.get('installed'):
            table = Table(title="Installed Tools", show_header=True, header_style="bold green")
            table.add_column("Tool", style="green")
            table.add_column("Version", style="dim")
            table.add_column("Category")

            for tool in sorted(results['installed'], key=lambda x: x['name'])[:10]:
                table.add_row(
                    tool['name'],
                    tool.get('version', 'unknown'),
                    tool.get('category', 'unknown')
                )

            if len(results['installed']) > 10:
                table.add_row("...", "...", f"({len(results['installed'])-10} more)")

            self.console.print(table)

        # Show missing tools table
        if results.get('missing'):
            table = Table(title="Missing Tools", show_header=True, header_style="bold yellow")
            table.add_column("Tool", style="yellow")
            table.add_column("Package")
            table.add_column("Category")

            for tool in sorted(results['missing'], key=lambda x: x['name'])[:10]:
                table.add_row(
                    tool['name'],
                    tool.get('package', tool['name']),
                    tool.get('category', 'unknown')
                )

            if len(results['missing']) > 10:
                table.add_row("...", "...", f"({len(results['missing'])-10} more)")

            self.console.print(table)

    def generate_html_report(self, results: Dict[str, Any], output_path: str):
        """Generate HTML report from template"""
        try:
            env = Environment(loader=FileSystemLoader(str(self.template_dir)))
            template = env.get_template('report.html.j2')

            html_content = template.render(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                total=results.get('total', 0),
                installed=results.get('installed', []),
                missing=results.get('missing', [])
            )

            with open(output_path, 'w') as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {output_path}")

        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")

    def export_json(self, results: Dict[str, Any], output_path: str):
        """Export results as JSON"""
        try:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total': results.get('total', 0),
                    'installed': len(results.get('installed', [])),
                    'missing': len(results.get('missing', [])),
                    'percentage': len(results.get('installed', [])) / results.get('total', 1) * 100
                },
                'installed': results.get('installed', []),
                'missing': results.get('missing', []),
                'failed': results.get('failed', [])
            }

            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)

            logger.info(f"JSON export saved: {output_path}")

        except Exception as e:
            logger.error(f"Error exporting JSON: {e}")

    def show_installation_plan(self, installed: List[str], missing: List[str], dry_run: bool = False):
        """Show what will be installed"""
        self.console.print("\n[bold cyan]Installation Plan:[/bold cyan]")
        self.console.print(f"  Already installed: [green]{len(installed)}[/green]")
        self.console.print(f"  To be installed: [yellow]{len(missing)}[/yellow]")

        if dry_run:
            self.console.print("\n[bold yellow]DRY RUN - No changes will be made[/bold yellow]")

        if missing:
            self.console.print("\n[bold]Tools to install:[/bold]")
            for tool in missing[:20]:
                self.console.print(f"  • {tool}")
            if len(missing) > 20:
                self.console.print(f"  ... and {len(missing)-20} more")

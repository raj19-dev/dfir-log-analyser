from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from models import Connection
import json
import os
from pathlib import Path

console = Console()


def default_report_directory() -> Path:
    """Return the per-user location used for exported reports."""
    return Path.home() / "Documents" / "DFIR Log Analyser" / "reports"

def display_report(connections: list[Connection], filepath: str):
    """Displays the full analysis report in the terminal"""
    
    console.print(Panel.fit(
        "[bold cyan]DFIR Log Analyser[/bold cyan]\n[dim]Digital Forensics & Incident Response Tool[/dim]",
        border_style="cyan"
    ))
    
    console.print(f"\n[dim]Analysing:[/dim] [bold]{filepath}[/bold]")
    console.print(f"[dim]Total connections found:[/dim] [bold]{len(connections)}[/bold]\n")
    
    # Summary counts
    malicious = sum(1 for c in connections if c.classification == "Malicious")
    suspicious = sum(1 for c in connections if c.classification == "Suspicious")
    normal = sum(1 for c in connections if c.classification == "Normal")
    
    # Summary panel
    console.print(Panel(
        f"[red]Malicious: {malicious}[/red]   [yellow]Suspicious: {suspicious}[/yellow]   [green]Normal: {normal}[/green]",
        title="Summary",
        border_style="white"
    ))
    
    console.print()
    
    # Connection table
    table = Table(box=box.ROUNDED, border_style="dim", show_lines=True, expand = True)
    table.add_column("Source IP", style="cyan", no_wrap=True)
    table.add_column("Destination IP", style="cyan", no_wrap=True)
    table.add_column("Port", justify="center")
    table.add_column("Events", justify="center")
    table.add_column("Duration", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Reason", style="dim")
    
    for conn in connections:
        # Keep output compatible with Windows consoles that use legacy code pages.
        status = {
            "Malicious": "[red]Malicious[/red]",
            "Suspicious": "[yellow]Suspicious[/yellow]",
            "Normal": "[green]Normal[/green]",
        }[conn.classification]

        table.add_row(
            conn.src_ip,
            conn.dst_ip,
            str(conn.dst_port) if conn.dst_port else "N/A",
            str(conn.event_count()),
            f"{conn.duration():.6f}s",
            status,
            conn.reason
        )
    
    console.print(table)

def export_json(
    connections: list[Connection],
    filepath: str,
    output_path: str | Path | None = None,
) -> Path:
    """Exports analysis results to a JSON file"""

    if output_path is None:
        output_dir = default_report_directory()
        output_path = output_dir / f"{Path(filepath).stem}_report.json"
    else:
        output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    results = []
    for conn in connections:
        results.append({
            "src_ip": conn.src_ip,
            "dst_ip": conn.dst_ip,
            "dst_port": conn.dst_port,
            "event_count": conn.event_count(),
            "duration": conn.duration(),
            "classification": conn.classification,
            "reason": conn.reason
        })
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    
    console.print(f"\n[dim]Report exported to[/dim] [bold cyan]{output_path}[/bold cyan]")
    return output_path

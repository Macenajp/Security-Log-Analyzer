import sys
import os
import csv
from datetime import datetime
from collections import Counter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.bar import Bar
from core.database import get_filtered_logs

console = Console()


def export_to_csv(logs, severity):
    category = severity if severity else 'ALL'
    timestamp_str = datetime.now().strftime('%Y-%m-%d_%I-%M-%S-%p')
    filename = f"data/logs_{timestamp_str}_{category}.csv"
    
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Source IP", "Threat Type", "Severity", "VirusTotal Reputation", "Timestamp"])
        for log in logs:
            writer.writerow(log)
            
    console.print(f"\n[bold green][+] Data successfully exported to: {filename}[/bold green]")


def generate_severity_chart_table(logs):
    severities = [log[2] for log in logs]
    counts = Counter(severities)
    total = len(logs)
    
    chart_table = Table(
        title="Severity Breakdown",
        title_style="italic",
        header_style="bold #AFC0FF",
        border_style="#AFC0FF",
        expand=True
    )
    chart_table.add_column("Level", justify="left", width=5, no_wrap=True)
    chart_table.add_column("Proportion", justify="left", ratio=1)
    
    if total == 0:
        chart_table.add_row("No data", "No data available")
        return chart_table

    max_count = max(counts.values()) if counts else 1
    available_bar_width = max(15, int(console.width * 0.22))

    for sev in ["HIGH", "MEDIUM", "LOW"]:
        count = counts.get(sev, 0)
        percentage = (count / total) * 100 if total > 0 else 0
        
        color = "red" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "green"
        proportional_width = int((count / max_count) * available_bar_width) if max_count > 0 else 0
        
        label_text = Text()
        label_text.append(f"{sev}\n", style=f"bold {color}")
        label_text.append(f"{percentage:.1f}%", style="dim")
        
        bar_text = Text()
        if proportional_width > 0:
            bar_str = "".join([
                segment.text for segment in Bar(
                    1, begin=0, end=1, color=color, width=proportional_width
                ).__rich_console__(console, console.options)
            ])
            bar_text.append(f"{bar_str}\n", style=color)
        else:
            bar_text.append("\n")
        bar_text.append(f"[ {count} ]\n", style="white")
        
        chart_table.add_row(label_text, bar_text)
        
    return chart_table


def get_top_ips(logs, sev_filter=None):
    if sev_filter:
        ips = [log[0] for log in logs if log[0] not in ['LOCAL_SYSTEM', 'N/A', 'NONE', ''] and log[2] == sev_filter]
    else:
        ips = [log[0] for log in logs if log[0] not in ['LOCAL_SYSTEM', 'N/A', 'NONE', '']]
        
    counts = Counter(ips)
    return counts.most_common(5)


def format_top_list(top_list):
    text = Text()
    if not top_list:
        text.append("No IPs recorded.", style="dim")
    else:
        for idx, (ip, count) in enumerate(top_list, 1):
            text.append(f"{idx}. ", style="dim")
            text.append(f"{ip:<15} ", style="#AFC0FF")
            text.append(f"({count})\n", style="white")
    return text


def show_dashboard():
    console.print(Align.center(Panel("[bold #AFC0FF]SecLA - Interactive Dashboard[/bold #AFC0FF]\n[dim]Database Analytics and Reporting[/dim]", border_style="#AFC0FF", expand=False)))
    
    console.print("\n[bold #AFC0FF]Select database filter:[/bold #AFC0FF]")
    console.print("[yellow][1][/yellow] - Show all threats")
    console.print("[yellow][2][/yellow] - HIGH severity only")
    console.print("[yellow][3][/yellow] - MEDIUM severity only")
    console.print("[yellow][4][/yellow] - LOW severity only")
    console.print("[yellow][5][/yellow] - Export current view to CSV")
    
    choice = input("\nOption to be requested: ").strip()
    
    if choice == "5":
        console.print("\n[yellow]Which severity would you like to export? (1=ALL, 2=HIGH, 3=MEDIUM, 4=LOW)[/yellow]")
        exp_choice = input("- Export Option: ").strip()
        filters = {"1": None, "2": "HIGH", "3": "MEDIUM", "4": "LOW"}
        severity = filters.get(exp_choice, None)

        if exp_choice not in filters:
            console.print("[bold red]Invalid option.[/bold red]")
            return
        
        logs = get_filtered_logs(severity_filter=severity)
        if not logs:
            console.print(f"[bold red]No logs found to export for category {severity if severity else 'ALL'}.[/bold red]")

            return
        
        export_to_csv(logs, severity)
        return

    filters = {"1": None, "2": "HIGH", "3": "MEDIUM", "4": "LOW"}

    if choice not in filters:
        console.print("[bold red]Invalid option.[/bold red]")
        return
        
    severity = filters.get(choice, None)
    logs = get_filtered_logs(severity_filter=severity)
    
    if not logs:
        console.print(f"\n[bold red]No logs found for category {severity if severity else 'ALL'}.[/bold red]")
        return

    console.print("\n")
    console.print(Align.center(f"[bold #AFC0FF]DATA DASHBOARD {f'({severity})' if severity else '(ALL)'}[/bold #AFC0FF]"))
    console.print("\n")

    top_panel_table = Table(
        show_header=True,
        header_style="bold #AFC0FF",
        border_style="#AFC0FF",
        expand=True,
        title="Top 5 Attacker IPs By Severity", 
        title_style="italic"
    )

    top_panel_table.add_column("Global (All)", justify="center", ratio=1)
    top_panel_table.add_column("HIGH Severity", justify="center", style="red", ratio=1)
    top_panel_table.add_column("MEDIUM Severity", justify="center", style="yellow", ratio=1)
    top_panel_table.add_column("LOW Severity", justify="center", style="green", ratio=1)

    top_panel_table.add_row(
        format_top_list(get_top_ips(logs)),
        format_top_list(get_top_ips(logs, "HIGH")),
        format_top_list(get_top_ips(logs, "MEDIUM")),
        format_top_list(get_top_ips(logs, "LOW"))
    )

    data_table = Table(
        title="Event Dashboard",
        title_style="italic",
        header_style="bold #AFC0FF",
        border_style="#AFC0FF",
        expand=True
    )

    data_table.add_column("Timestamp", style="dim", justify="center", no_wrap=True)
    data_table.add_column("Source (IP)", style="#AFC0FF", no_wrap=True)
    data_table.add_column("Threat", style="magenta", justify="center", no_wrap=True)
    data_table.add_column("Severity", justify="center", no_wrap=True)
    data_table.add_column("VirusTotal", ratio=1)

    for ip, threat, sev, vt, timestamp in logs:
        formatted_sev = f"[bold red]{sev}[/]" if sev == "HIGH" else f"[bold yellow]{sev}[/]" if sev == "MEDIUM" else f"[bold green]{sev}[/]"
        vt_color = "[bold red]" if "WARNING" in vt.upper() or "ERROR" in vt.upper() else "[dim]" if "LOCAL EVENT" in vt.upper() else "[bold green]"
        data_table.add_row(timestamp, ip, threat, formatted_sev, f"{vt_color}{vt}[/]")

    chart_table = generate_severity_chart_table(logs)

    bottom_grid = Table.grid(expand=True, padding=(0, 1))
    bottom_grid.add_column(ratio=1)
    bottom_grid.add_column(ratio=1)
    bottom_grid.add_row(data_table, chart_table)

    console.print(top_panel_table)
    console.print("\n")
    console.print(bottom_grid)
    console.print("\n")

if __name__ == "__main__":
    show_dashboard()
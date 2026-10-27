import sys
import os
import csv
from datetime import datetime

# Ensures the root folder is accessible to import 'core'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from rich.console import Console
from rich.table import Table
from core.database import get_filtered_logs

console = Console()


def export_to_csv(logs, severity):
    """Exports the filtered logs to a new CSV file."""
    category = severity if severity else 'ALL'
    
    # The format follows the international date and time standard, for example: 2026-10-27_02-45-30-PM
    timestamp_str = datetime.now().strftime('%Y-%m-%d_%I-%M-%S-%p')
    
    filename = f"data/logs_{timestamp_str}_{category}.csv"
    
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Source IP", "Threat Type", "Severity", "VirusTotal Reputation", "Timestamp"])
        for log in logs:
            writer.writerow(log)
            
    console.print(f"\n[bold green][+] Data successfully exported to: {filename}[/bold green]")


def show_dashboard():
    console.print("[bold #AFC0FF]Select database filter:[/bold #AFC0FF]")
    console.print("[#AFC0FF][1][/#AFC0FF] - Show all threats")
    console.print("[#AFC0FF][2][/#AFC0FF] - HIGH severity only")
    console.print("[#AFC0FF][3][/#AFC0FF] - MEDIUM severity only")
    console.print("[#AFC0FF][4][/#AFC0FF] - LOW severity only")
    console.print("[#AFC0FF][5][/#AFC0FF] - Export current view to CSV")
    
    choice = input("\nOption to be requested: ").strip()
    
    # Handle CSV Export
    if choice == "5":
        console.print("\n[#AFC0FF]Which severity would you like to export? (1=ALL, 2=HIGH, 3=MEDIUM, 4=LOW)[/#AFC0FF]")
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

    # Handle standard Terminal visualization
    filters = {"1": None, "2": "HIGH", "3": "MEDIUM", "4": "LOW"}
    
    if choice not in filters:
        console.print("[bold red]Invalid option.[/bold red]")
        return
        
    severity = filters.get(choice, None)
    logs = get_filtered_logs(severity_filter=severity)
    
    if not logs:
        console.print(f"\n[bold red]No logs found for category {severity if severity else 'ALL'}.[/bold red]")
        return
        
    table = Table(title=f"EVENT DASHBOARD {f'({severity})' if severity else '(ALL)'}", header_style="bold #AFC0FF", border_style="#AFC0FF")
    table.add_column("Timestamp", style="dim", justify="center")
    table.add_column("Source (IP)", style="#AFC0FF")
    table.add_column("Threat", style="magenta", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("VirusTotal")

    for ip, threat, sev, vt, timestamp in logs:
        if sev == "HIGH":
            formatted_sev = f"[bold red]{sev}[/bold red]"
        elif sev == "MEDIUM":
            formatted_sev = f"[bold yellow]{sev}[/bold yellow]"
        else:
            formatted_sev = f"[bold green]{sev}[/bold green]"
            
        vt_color = "[bold red]" if "WARNING" in vt.upper() else "[bold green]"
        
        table.add_row(timestamp, ip, threat, formatted_sev, f"{vt_color}{vt}[/]")

    console.print("\n")
    console.print(table)

if __name__ == "__main__":
    show_dashboard()
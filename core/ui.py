import csv
import json # v1.2
import os # v1.2
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.text import Text  # v.1.2.2

from core.log_reader import filter_suspicious_logs
from core.slm_analyzer import analyze_log_ia
from core.threat_intel import check_ip
from core.database import insert_log # v1.3


# v1.2 | Functions for loading and saving the cache of IP addresses analyzed by VirusTotal
def load_cache():
    if os.path.exists("data/vt_cache.json"):
        with open("data/vt_cache.json", "r") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open("data/vt_cache.json", "w") as f:
        json.dump(cache, f, indent=4)

console = Console()


def start_interface():
    header = Text.from_markup("[bold #AFC0FF]SecLA - Security Log Analyzer[/bold #AFC0FF]\n[dim]Starting the analysis and screening engine...[/dim]")
    header.justify = "center"

    console.print(Panel(header, border_style="#AFC0FF", expand=False))
    
    selected_model = "gemma3:4b"  # Standard AI Model
    log_File = "data/test_auth.log"

    console.print(f"\n[bold #AFC0FF][INFO][/bold #AFC0FF] Reading file: [magenta]{log_File}[/magenta]")
    suspicious_logs = filter_suspicious_logs(log_File)

    if not suspicious_logs:
        console.print("[bold green]All clear. No anomalous events detected.[/bold green]")
        return

    console.print(f"[bold red][ALERT][/bold red] The engine found [bold red]{len(suspicious_logs)}[/bold red] suspicious events.")
    console.print(f"[bold #AFC0FF][INFO][/bold #AFC0FF] Forwarding for analysis with model [bold magenta]{selected_model}[/bold magenta][white]...[/white]\n \n")

    file_csv = f"data/benchmarks/benchmark_{selected_model.replace(':', '_')}.csv"
    os.makedirs("data/benchmarks", exist_ok=True)

    # V.1.2.2 | Interface Improvements
    stats_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    stats_vt = {"CLEAN": 0, "THREAT": 0}
    
    primary_table = Table(title="DETAILED OVERVIEW OF EVENTS", header_style="bold #AFC0FF", border_style="#AFC0FF")
    primary_table.add_column("#", justify="right", style="dim", width=4)
    primary_table.add_column("Source (IP)", style="#AFC0FF", justify="left", no_wrap=True)
    primary_table.add_column("Threat Detected", style="#ffc9ff", justify="center")
    primary_table.add_column("Severity", justify="center")
    primary_table.add_column("Performance", justify="right", style="#AFC0FF")
    primary_table.add_column("VirusTotal", justify="left")

    with open(file_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        colunas = ['Model', 'Threat', 'Source (IP)', 'Level', 'Tokens_per_Second', 'Raw_Log', 'VirusTotal']
        writer = csv.DictWriter(csv_file, fieldnames=colunas)
        writer.writeheader()

        cache_ips = load_cache()

        for idx, log_line in enumerate(suspicious_logs, start=1):
            result_ia = analyze_log_ia(log_line, model=selected_model)
            
            if "error" in result_ia:
                primary_table.add_row(str(idx), "ERROR", result_ia["error"], "[bold red]ERROR[/bold red]", "0 t/s", "ERROR")
            else:
                threat = result_ia.get('threat', 'N/A').upper()
                source = str(result_ia.get('ip', 'N/A')).strip() 
                level = result_ia.get('severity', 'N/A').upper()
                speed_per_sec = result_ia.get("telemetry", {}).get("tokens_sec", 0)

                if level in stats_severity:
                    stats_severity[level] += 1

                # v1.3.2 It now ignores API calls when the event originates from the system (LOCAL_SYSTEM)
                result_virustotal = "Local Event (No IP)"
                if source not in ['N/A', 'LOCAL_SYSTEM', 'NONE', '']:
                    if source in cache_ips:
                        result_virustotal = cache_ips[source]
                    else:
                        result_virustotal = check_ip(source)  
                        cache_ips[source] = result_virustotal
                        save_cache(cache_ips)

                    if result_virustotal.startswith("WARNING") or result_virustotal.startswith("ERROR"):
                        stats_vt["THREAT"] += 1
                    else:
                        stats_vt["CLEAN"] += 1

                if level == "HIGH":
                    formatted_level = f"[bold red]{level}[/bold red]"
                elif level == "MEDIUM":
                    formatted_level = f"[bold yellow]{level}[/bold yellow]"
                else:
                    formatted_level = f"[bold green]{level}[/bold green]"

                if result_virustotal.startswith("WARNING") or result_virustotal.startswith("ERROR"):
                    formatted_virustotal = f"[bold red]{result_virustotal}[/bold red]"
                elif result_virustotal == "Local Event (No IP)":
                    formatted_virustotal = f"[dim]{result_virustotal}[/dim]"
                else:
                    formatted_virustotal = f"[bold green]{result_virustotal}[/bold green]"

                primary_table.add_row(str(idx), source, threat, formatted_level, f"{speed_per_sec} t/s", formatted_virustotal)

                # v1.3 | Inserting the logs into the SQLite database
                insert_log(
                    model=selected_model,
                    ip=source,
                    threat=threat,
                    severity=level,
                    vt_reputation=result_virustotal,
                    performance_ts=f"{speed_per_sec} t/s",
                    raw_log=log_line
                )


                writer.writerow({
                    'Model': selected_model,
                    'Threat': threat,
                    'Source (IP)': source,
                    'Level': level,
                    'Tokens_per_Second': speed_per_sec,
                    'Raw_Log': log_line,
                    'VirusTotal': result_virustotal
                })


    # V.1.2.2 | Creation of a secondary summary table
    summary_table = Table(title="GENERAL SUMMARY", header_style="bold #AFC0FF", border_style="#AFC0FF")
    summary_table.add_column("Category", style="#AFC0FF")
    summary_table.add_column("Status/Level", justify="left")
    summary_table.add_column("Quantity", justify="right", style="bold")

    summary_table.add_row("Severity", "HIGH", str(stats_severity["HIGH"]))
    summary_table.add_row("Severity", "MEDIUM", str(stats_severity["MEDIUM"]))
    summary_table.add_row("Severity", "LOW", str(stats_severity["LOW"]))
    
    summary_table.add_section()

    summary_table.add_row("Reputation (VT)", "CLEAN", str(stats_vt["CLEAN"]))
    summary_table.add_row("Reputation (VT)", "THREAT", str(stats_vt["THREAT"]))

    console.print(Align.left(primary_table)) # Displays the main table      
    console.print("\n")                                                           
    console.print(Align.left(summary_table)) # Displays the secondary summary table

    console.print(f"\n[bold green][+] Analysis completed! Results saved to: {file_csv}[/bold green]") 
    console.print(f"[dim]IP cache updated at: data/vt_cache.json[/dim]\n")
if __name__ == "__main__":
    start_interface()
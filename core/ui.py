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

# V1.2 | Funções para carregar e salvar cache de IPs analisados pelo VirusTotal
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
    cabecalho = Text.from_markup("[bold #AFC0FF]SecLA - Security Log Analyzer[/bold #AFC0FF]\n[dim]Iniciando o engine de análise e triagem...[/dim]")
    cabecalho.justify = "center"

    console.print(Panel(cabecalho, border_style="#AFC0FF", expand=False))
    
    selected_model = "gemma3:4b"  # Modelo de IA padrão
    log_File = "data/test_auth.log"

    console.print(f"\n[bold #AFC0FF][INFO][/bold #AFC0FF] Lendo arquivo: [magenta]{log_File}[/magenta]")
    suspicious_logs = filter_suspicious_logs(log_File)

    if not suspicious_logs:
        console.print("[bold green]Tudo limpo. Nenhum evento anômalo detectado.[/bold green]")
        return

    console.print(f"[bold red][ALERTA][/bold red] A engine encontrou [bold red]{len(suspicious_logs)}[/bold red] eventos suspeitos.")
    console.print(f"[bold #AFC0FF][INFO][/bold #AFC0FF] Repassando para análise com o modelo [bold magenta]{selected_model}[/bold magenta][white]...[/white]\n \n")

    arquivo_csv = f"data/benchmarks/benchmark_{selected_model.replace(':', '_')}.csv"
    os.makedirs("data/benchmarks", exist_ok=True)

    # V.1.2.2 | Melhoria da interface
    stats_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    stats_vt = {"CLEAN": 0, "THREAT": 0}
    
    primary_table = Table(title="VISÃO DETALHADA DOS EVENTOS", header_style="bold #AFC0FF", border_style="#AFC0FF")
    primary_table.add_column("#", justify="right", style="dim", width=4)
    primary_table.add_column("Origem (IP)", style="#AFC0FF", justify="left", no_wrap=True)
    primary_table.add_column("Ameaça Detectada", style="#ffc9ff", justify="center")
    primary_table.add_column("Severidade", justify="center")
    primary_table.add_column("Desempenho", justify="right", style="#AFC0FF")
    primary_table.add_column("VirusTotal", justify="left")

    with open(arquivo_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        colunas = ['Modelo', 'Ameaca', 'Origem', 'Nivel', 'Tokens_por_Segundo', 'Log_Bruto', 'VirusTotal']
        writer = csv.DictWriter(csv_file, fieldnames=colunas)
        writer.writeheader()

        cache_ips = load_cache()

        for idx, log_line in enumerate(suspicious_logs, start=1):
            result_ia = analyze_log_ia(log_line, model=selected_model)
            
            if "error" in result_ia:
                primary_table.add_row(str(idx), "ERRO", result_ia["error"], "[bold red]ERROR[/bold red]", "0 t/s", "ERRO")
            else:
                threat = result_ia.get('threat', 'N/A').upper()
                origin = str(result_ia.get('ip', 'N/A')).strip() 
                level = result_ia.get('severity', 'N/A').upper()
                speed_per_sec = result_ia.get("telemetry", {}).get("tokens_sec", 0)

                if level in stats_severity:
                    stats_severity[level] += 1

                result_virustotal = "Sem IP para checar"
                if origin != 'N/A':
                    if origin in cache_ips:
                        result_virustotal = cache_ips[origin]
                    else:
                        result_virustotal = check_ip(origin)  
                        cache_ips[origin] = result_virustotal
                    save_cache(cache_ips)

                    if result_virustotal.startswith("ATENÇÃO") or result_virustotal.startswith("ERRO"):
                        stats_vt["THREAT"] += 1
                    else:
                        stats_vt["CLEAN"] += 1

                if level == "HIGH":
                    formatted_level = f"[bold red]{level}[/bold red]"
                elif level == "MEDIUM":
                    formatted_level = f"[bold yellow]{level}[/bold yellow]"
                else:
                    formatted_level = f"[bold green]{level}[/bold green]"

                if result_virustotal.startswith("ATENÇÃO") or result_virustotal.startswith("ERRO"):
                    formatted_virustotal = f"[bold red]{result_virustotal}[/bold red]"
                else:
                    formatted_virustotal = f"[bold green]{result_virustotal}[/bold green]"

                primary_table.add_row(str(idx), origin, threat, formatted_level, f"{speed_per_sec} t/s", formatted_virustotal)

                # v1.3 | Inserindo os logs no banco de dados SQLite
                insert_log(
                    model=selected_model,
                    ip=origin,
                    threat=threat,
                    severity=level,
                    vt_reputation=result_virustotal,
                    performance_ts=f"{speed_per_sec} t/s",
                    raw_log=log_line
                )



                writer.writerow({
                    'Modelo': selected_model,
                    'Ameaca': threat,
                    'Origem': origin,
                    'Nivel': level,
                    'Tokens_por_Segundo': speed_per_sec,
                    'Log_Bruto': log_line,
                    'VirusTotal': result_virustotal
                })


    # V.1.2.2 | Criação de uma tabela secundária de resumo
    summary_table = Table(title="RESUMO GERAL", header_style="bold #AFC0FF", border_style="#AFC0FF")
    summary_table.add_column("Categoria", style="#AFC0FF")
    summary_table.add_column("Status/Nível", justify="left")
    summary_table.add_column("Quantidade", justify="right", style="bold")

    summary_table.add_row("Severidade", "HIGH", str(stats_severity["HIGH"]))
    summary_table.add_row("Severidade", "MEDIUM", str(stats_severity["MEDIUM"]))
    summary_table.add_row("Severidade", "LOW", str(stats_severity["LOW"]))
    
    summary_table.add_section()

    summary_table.add_row("Reputação (VT)", "LIMPO", str(stats_vt["CLEAN"]))
    summary_table.add_row("Reputação (VT)", "AMEAÇA", str(stats_vt["THREAT"]))

    console.print(Align.left(primary_table)) # Exibe a tabela principal      
    console.print("\n")                                                           
    console.print(Align.left(summary_table)) # Exibe a tabela seundária de resumo

    console.print(f"\n[bold green][+] Análise concluída! Resultados salvos em: {arquivo_csv}[/bold green]") 
    console.print(f"[dim]Cache de IPs atualizado em: data/vt_cache.json[/dim]\n")
if __name__ == "__main__":
    start_interface()
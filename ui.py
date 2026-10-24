import csv
import json # V1.2
import os # V1.2
from turtle import speed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align # V1.2

from log_Reader import filter_Suspicious_Logs
from slm_Analyzer import analyze_Log_IA

from threat_Intel import check_IP

# V1.2 | Funções para carregar e salvar cache de IPs analisados pelo VirusTotal
def load_cache():
    if os.path.exists("vt_cache.json"):
        with open("vt_cache.json", "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open("vt_cache.json", "w") as f:
        json.dump(cache, f, indent=4)


console = Console()

def start_interface():
    console.print(Panel.fit("[bold #AFC0FF]SecLA - Security Log Analyzer[/bold #AFC0FF]\nIniciando sistema de análise...", border_style="#AFC0FF"))
    
    selected_Model = "phi4-mini:3.8b"
    
    log_File = "test_auth.log"
    console.print(f"\n[*] Lendo arquivo: [yellow]{log_File}[/yellow]...")
    suspicious_Logs = filter_Suspicious_Logs(log_File)

    if not suspicious_Logs:
        console.print("[bold green][+] Tudo limpo. Nenhum evento anômalo detectado.[/bold green]")
        return

    console.print(f"[bold red][!] A engine encontrou {len(suspicious_Logs)} eventos suspeitos.[/bold red]")
    console.print(f"[*] Repassando para análise com: [bold magenta]{selected_Model}[/bold magenta]...\n")

    arquivo_csv = f"benchmark_{selected_Model.replace(':', '_')}.csv"

    # V1.1 Tabela de exibição para o terminal
    table = Table(show_lines=True, header_style="bold #AFC0FF", border_style="#AFC0FF")
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Origem (IP)", style="#AFC0FF", justify="left", no_wrap=True)
    table.add_column("Ameaça Detectada", style="#ffc9ff", justify="center")
    table.add_column("Severidade", justify="center")
    table.add_column("Desempenho", justify="right", style="#AFC0FF")
    table.add_column("VirusTotal", justify="left") # V1.2 | Coluna para exibiir o resultado do VírusTotal

    with open(arquivo_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        colunas = ['Modelo', 'Ameaca', 'Origem', 'Nivel', 'Tokens_por_Segundo', 'Log_Bruto', 'VirusTotal']
        writer = csv.DictWriter(csv_file, fieldnames=colunas)
        writer.writeheader()

        cache_ips = load_cache()

        for idx, log_Line in enumerate(suspicious_Logs, start=1):
            result_Ia = analyze_Log_IA(log_Line, model=selected_Model)
            
            if "error" in result_Ia:
                table.add_row(str(idx), "ERRO", result_Ia["error"], "[bold red]ERROR[/bold red]", "0 t/s", "ERRO")
            else:
                threat = result_Ia.get('threat', 'N/A').upper()
                
                origin = str(result_Ia.get('ip', 'N/A')).strip() 
                
                level = result_Ia.get('severity', 'N/A').upper()
                speed_Per_Sec = result_Ia.get("telemetry", {}).get("tokens_sec", 0)

                result_VirusTotal = "Sem IP para checar"
                if origin != 'N/A':
                    if origin in cache_ips:
                        result_VirusTotal = cache_ips[origin] # Puxa instantaneamente da memória local
                    else:
                        result_VirusTotal = check_IP(origin)  
                        cache_ips[origin] = result_VirusTotal # Salva o resultado na memória; Assim, impede o desperdício de requisições para o mesmo IP

                    save_cache(cache_ips)



                if level == "HIGH":
                    formatted_Level = f"[bold red]{level}[/bold red]"
                elif level == "MEDIUM":
                    formatted_Level = f"[bold yellow]{level}[/bold yellow]"
                else:
                    formatted_Level = f"[bold green]{level}[/bold green]"

                # V1.2 | Formatação de cores resultado do VirusTotal para exibição na tabela
                if result_VirusTotal.startswith("ATENÇÃO") or result_VirusTotal.startswith("ERRO"):
                    formatted_VirusTotal = f"[bold red]{result_VirusTotal}[/bold red]"
                else:
                    formatted_VirusTotal = f"[bold green]{result_VirusTotal}[/bold green]"


                table.add_row(str(idx), origin, threat, formatted_Level, f"{speed_Per_Sec} t/s", formatted_VirusTotal)

                writer.writerow({
                    'Modelo': selected_Model,
                    'Ameaca': threat,
                    'Origem': origin,
                    'Nivel': level,
                    'Tokens_por_Segundo': speed_Per_Sec,
                    'Log_Bruto': log_Line,
                    'VirusTotal': result_VirusTotal
                })

    # V1.1 | Renderiza a tabela completa de uma só vez, garantindo cerca performance de ~6% de velocidade a mais rápida do que renderizar linha por linha
    console.print(table)
    console.print(f"\n[bold green][+] Análise concluída! Os resultados foram salvos em: {arquivo_csv}[/bold green]")

if __name__ == "__main__":
    start_interface()
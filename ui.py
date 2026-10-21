import csv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from log_Reader import filter_Suspicious_Logs
from slm_Analyzer import analyze_Log_IA

console = Console()

def start_interface():
    console.print(Panel.fit("[bold cyan]SecLA - Security Log Analyzer[/bold cyan]\nIniciando sistema de varredura...", border_style="cyan"))
    
    modelo_selecionado = "phi4-mini:latest"
    
    log_File = "test_auth.log"
    console.print(f"\n[*] Lendo arquivo: [yellow]{log_File}[/yellow]...")
    suspicious_Logs = filter_Suspicious_Logs(log_File)

    if not suspicious_Logs:
        console.print("[bold green][+] Tudo limpo. Nenhum evento anômalo detectado.[/bold green]")
        return

    console.print(f"[bold red][!] A engine encontrou {len(suspicious_Logs)} eventos suspeitos.[/bold red]")
    console.print(f"[*] Repassando para análise semântica com [bold magenta]{modelo_selecionado}[/bold magenta]...\n")

    arquivo_csv = f"benchmark_{modelo_selecionado.replace(':', '_')}.csv"
    
    # Tabela de exibição para o terminal (Renderização em lote no final para 100% de performance)
    table = Table(show_lines=True)
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Origem (IP)", style="cyan", no_wrap=True)
    table.add_column("Ameaça Detectada", style="magenta")
    table.add_column("Severidade", justify="center")
    table.add_column("Desempenho", justify="right", style="green")

    with open(arquivo_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        colunas = ['Modelo', 'Ameaca', 'Origem', 'Nivel', 'Tokens_por_Segundo', 'Log_Bruto']
        writer = csv.DictWriter(csv_file, fieldnames=colunas)
        writer.writeheader()

        for idx, log_Line in enumerate(suspicious_Logs, start=1):
            result_Ia = analyze_Log_IA(log_Line, modelo=modelo_selecionado)
            
            if "error" in result_Ia:
                table.add_row(str(idx), "ERRO", result_Ia["error"], "[bold red]ERROR[/bold red]", "0 t/s")
            else:
                ameaca = result_Ia.get('threat', 'N/A').upper()
                origem = result_Ia.get('ip', 'N/A')
                nivel = result_Ia.get('severity', 'N/A').upper()
                velocidade = result_Ia.get("telemetry", {}).get("tokens_sec", 0)

                if nivel == "HIGH":
                    nivel_formatado = f"[bold red]{nivel}[/bold red]"
                elif nivel == "MEDIUM":
                    nivel_formatado = f"[bold yellow]{nivel}[/bold yellow]"
                else:
                    nivel_formatado = f"[bold green]{nivel}[/bold green]"

                table.add_row(str(idx), origem, ameaca, nivel_formatado, f"{velocidade} t/s")
                
                writer.writerow({
                    'Modelo': modelo_selecionado,
                    'Ameaca': ameaca,
                    'Origem': origem,
                    'Nivel': nivel,
                    'Tokens_por_Segundo': velocidade,
                    'Log_Bruto': log_Line
                })
    
    # Renderiza a tabela completa de uma só vez, sem overhead durante a inferência
    console.print(table)
    console.print(f"\n[bold green][+] Análise concluída! Resultados salvos em: {arquivo_csv}[/bold green]")

if __name__ == "__main__":
    start_interface()
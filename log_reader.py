# Importação das funções dos outros arquivos
from log_reader import filter_suspicious_logs
from slm_analyzer import analyze_Log_IA

def main():
    # 1. Definição de qual arquivo vai ser analisado (usando o falso que geramos para testes iniciais)
    log_File = "test_auth.log"
    print(f"[*] Iniciando o SecLA - Analisando o arquivo: {log_File}...")

    # 2. Chamada da função de filtro para separar apenas o que é perigoso
    suspicious_Logs = filter_suspicious_logs(log_File)

    # 3. Verifica se há algo para analisar
    if not suspicious_Logs:
        print("[+] Nenhum log suspeito encontrado. O sistema está seguro.")
        return

    print(f"[!] Atenção: {len(suspicious_Logs)} logs suspeitos encontrados.")
    print("[*] Iniciando análise de ameaças via IA Local (PHI4-Mini)...\n")
    print("-" * 60)

    # 4. Cada log suspeito é passado para a IA ler e classificar
    for log_Line in suspicious_Logs:
        print(f"-> Log Bruto: {log_Line}")
        
        # Faz a requisição para o Ollama
        final_Result_IA = analyze_Log_IA(log_Line)
        
        print(f"   [SecLA IA]: {final_Result_IA}\n")
        print("-" * 60)

if __name__ == "__main__":
    main()
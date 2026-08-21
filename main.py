from log_Reader import filter_Suspicious_Logs
from slm_Analyzer import analyze_Log_IA

def main():

    # Bloco de análise de arquivo 
    log_File = "test_auth.log"
    print(f"[*] SecLA Iniciado - Lendo arquivo: {log_File}...")

    suspicious_Logs = filter_Suspicious_Logs(log_File)

    if not suspicious_Logs:
        print("[+] Tudo limpo. Nenhum evento anômalo detectado.")
        return

    print(f"[!] A engine encontrou {len(suspicious_Logs)} eventos suspeitos.")
    print("[*] Repassando para análise contextual (SLM)...\n")
    print("=" * 60)


    # Bloco de escolha da IA e de formatação do print
    for log_Line in suspicious_Logs:
        print(f"RAW LOG: {log_Line}")
        
        result_Ia = analyze_Log_IA(log_Line, modelo="phi4-mini:latest") # Aqui pode ser feito a troca/substiuição da SLM
        
        if "error" in result_Ia:
            print(f"   [!] ERRO IA: {result_Ia['error']}")
        else:
            print(f"   [SecLA] Ameaça: {result_Ia.get('threat', 'N/A').upper()}")
            print(f"   [SecLA] Origem: {result_Ia.get('ip', 'N/A')}")
            print(f"   [SecLA] Nível : {result_Ia.get('severity', 'N/A').upper()}")
            
        print("-" * 60)

if __name__ == "__main__":
    main()

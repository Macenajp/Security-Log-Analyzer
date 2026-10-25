import re


def filter_suspicious_logs(filepath):
    suspicious_logs = []
    
    # Padrões de anomalias (Regex)
    patterns = [
        r"Failed password",
        r"Invalid user",
        r"Connection closed by authenticating user",
        #V1.3 | Adicionando padrões de tráfego web suspeito
        r" 403\b",
        r"\.env",
        r"\.git",
        r"config\.php",
        r"UNION SELECT"
    ]
    
    try:
        with open(filepath, 'r') as file:
            for line in file:
                if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns): # V1.3 | Adicionando re.IGNORECASE para indiferenciar palavras em maiúsculo/minúsculo
                    suspicious_logs.append(line.strip())
                    
        return suspicious_logs
        
    except FileNotFoundError:
        print(f"[-] Erro: O arquivo {filepath} não foi encontrado.")
        return []
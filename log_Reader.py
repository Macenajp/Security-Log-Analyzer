import re

def filter_Suspicious_Logs(filepath):
    suspicious_Logs = []
    
    # Padrões de anomalias (Regex)
    patterns = [
        r"Failed password",
        r"Invalid user",
        r"Connection closed by authenticating user"
    ]
    
    try:
        with open(filepath, 'r') as file:
            for line in file:
                if any(re.search(pattern, line) for pattern in patterns):
                    suspicious_Logs.append(line.strip())
                    
        return suspicious_Logs
        
    except FileNotFoundError:
        print(f"[-] Erro: O arquivo {filepath} não foi encontrado.")
        return []
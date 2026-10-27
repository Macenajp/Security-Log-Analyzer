import re


def filter_suspicious_logs(filepath):
    suspicious_logs = []
    
    # Anomaly Patterns (Regex)
    patterns = [
        r"Failed password", r"Invalid user", r"Connection closed by authenticating user",   # SSH
        r" 401\b", r" 403\b", r" 404\b", r"sqlmap", r"nmap", r"dirb", r"UNION SELECT",      # Nginx / Apache
        r"segfault", r"kernel panic", r"unauthorized"                                       # Syslog
    ]
    
    try:
        with open(filepath, 'r') as file:
            for line in file:
                if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns): # V1.3 | Adding re.IGNORECASE to make words case-insensitive
                    suspicious_logs.append(line.strip())
                    
        return suspicious_logs
        
    except FileNotFoundError:
        print(f"[-] Error: The file {filepath} was not found.")
        return []
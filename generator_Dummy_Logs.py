# Código para realizar simulações e testes a partir da geração de logs falsos

import random
from datetime import datetime, timedelta

def generate_Dummy_Logs(filename="test_auth.log", num_lines=200):
    ips = ["192.168.1.15", "10.0.0.42", "203.0.113.5", "198.51.100.22"]
    users = ["root", "admin", "joao"]
    
    start_Time = datetime.now() - timedelta(hours=1)
    
    with open(filename, 'w') as f:
        for i in range(num_lines):
            start_Time += timedelta(seconds=random.randint(1, 15))
            timestamp = start_Time.strftime("%b %d %H:%M:%S")
            
            if random.random() > 0.2:
                f.write(f"{timestamp} pop-os sshd[123]: Accepted publickey for joao from {ips[0]} port 50123 ssh2\n")
            else:
                f.write(f"{timestamp} pop-os sshd[567]: Failed password for {random.choice(users)} from {random.choice(ips[2:])} port 33456 ssh2\n")
            
    print(f"[+] Arquivo {filename} gerado.")

if __name__ == "__main__":
    generate_Dummy_Logs()
# Código para realizar simulações e testes a partir da geração de logs falsos

import random
from datetime import datetime, timedelta


def generate_dummy_logs(filename="data/test_auth.log", num_lines=500):
    ips = ["192.168.1.15", "10.0.0.42", "203.0.113.5", "198.51.100.22"]
    users = ["root", "admin", "fulano"]

   # V1.3 Listas de rotas comuns para simular tráfego web
    methods = ["GET", "POST", "PUT", "DELETE"]
    normal_routes = ["/home", "/login", "/dashboard", "/contato", "/sobre", "/produtos", "/servicos", "/assets/logo.png", "/assets/style.css", "/assets/script.js", "/favicon.ico"]
    malicious_routes = ["/login?user=admin' OR '1'='1 UNION SELECT","/etc/passwd", "/var/www/html/config.php", "/admin.php", "/login.php", "/wp-config.php", "/.git", "/.htaccess", "/.env", "/config.json", "/backup.zip", "/admin", "/config", "/api", "/secret", "/wp-login.php", "/config.php"]


    start_time = datetime.now() - timedelta(hours=1)

    # V1.3 | Atualização para um padrão universal de logs
    with open(filename, 'w') as f:
        for i in range(num_lines):
            start_time += timedelta(seconds=random.randint(1, 15))            
            web_timestamp = start_time.strftime("%d/%b/%Y:%H:%M:%S")
            
            if random.random() > 0.2:
                f.write(f'{ips[0]} - - [{web_timestamp} -0300] "{random.choice(methods)} {random.choice(normal_routes)} HTTP/1.1" 200\n')                       # Tráfego Normal (Código HTTP 200 = Sucesso)
            else:
                f.write(f'{random.choice(ips[2:])} - - [{web_timestamp} -0300] "{random.choice(methods)} {random.choice(malicious_routes)} HTTP/1.1" 403\n')    # Tráfego Malicioso (Código HTTP 403 = Proibido/Bloqueado)
            
    print(f"[+] Arquivo {filename} gerado.")

if __name__ == "__main__":
    generate_dummy_logs()
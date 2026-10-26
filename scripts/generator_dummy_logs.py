import random
from datetime import datetime, timedelta


def generate_dummy_logs(filename="data/test_auth.log", num_lines=500):
    ips = ["192.168.1.15", "10.0.0.42", "203.0.113.5", "198.51.100.22"]
    users = ["root", "admin", "fulano"]

   # V1.3 Listas de rotas comuns para simular tráfego web
    methods = ["GET", "POST", "PUT", "DELETE"]
    normal_routes = ["/home", "/pagina-velha.html", "/login", "/dashboard", "/contato", "/sobre", "/produtos", "/servicos", "/assets/logo.png", "/assets/style.css", "/assets/script.js", "/favicon.ico"]
    malicious_routes = ["/login?user=admin' OR '1'='1 UNION SELECT","/etc/passwd", "/var/www/html/config.php", "/admin.php", "/login.php", "/wp-config.php", "/.git", "/.htaccess", "/.env", "/config.json", "/backup.zip", "/admin", "/config", "/api", "/secret", "/wp-login.php", "/config.php"]


    start_time = datetime.now() - timedelta(hours=1)

    # V1.3 | Atualização para um padrão universal de logs
    with open(filename, 'w') as f:
        for i in range(num_lines):
            start_time += timedelta(seconds=random.randint(1, 15))            
            web_timestamp = start_time.strftime("%d/%b/%Y:%H:%M:%S")
            
            if random.random() > 0.2:
                # Sorteia uma rota normal; Assim, é possível possibilitar a realização da checagem e vizualização do tráfego, independente da sua gravidade
                chosen_route = random.choice(normal_routes)
                
                if chosen_route == "/pagina-velha.html":
                    f.write(f'{ips[0]} - - [{web_timestamp} -0300] "{random.choice(methods)} {chosen_route} HTTP/1.1" 404\n') # Se a rota for a página velha, gera um erro 404 (Not Found - Categoria LOW)
                                                                                                                                # Caso contrário, tráfego normal (200 OK)
                else:
                    f.write(f'{ips[0]} - - [{web_timestamp} -0300] "{random.choice(methods)} {chosen_route} HTTP/1.1" 200\n')                       
            else:
                f.write(f'{random.choice(ips[2:])} - - [{web_timestamp} -0300] "{random.choice(methods)} {random.choice(malicious_routes)} HTTP/1.1" 403\n')    # Tráfego Malicioso (Código HTTP 403 = Proibido/Bloqueado)
            
    print(f"[+] Arquivo {filename} gerado.")

if __name__ == "__main__":
    generate_dummy_logs()

import random
from datetime import datetime, timedelta


def generate_dummy_logs(filename="data/test_auth.log", num_lines=1000):
    ips = ["192.168.1.15", "10.0.0.42", "203.0.113.5", "198.51.100.22"]
    users = ["root", "admin", "fulano"]

   # V1.3 Lists of common routes for simulating web traffic
    methods = ["GET", "POST", "PUT", "DELETE"]
    normal_routes = ["/home", "/pagina-velha.html", "/login", "/dashboard", "/contato", "/sobre", "/produtos", "/servicos", "/assets/logo.png", "/assets/style.css", "/assets/script.js", "/favicon.ico"]
    malicious_routes = ["/login?user=admin' OR '1'='1 UNION SELECT","/etc/passwd", "/var/www/html/config.php", "/admin.php", "/login.php", "/wp-config.php", "/.git", "/.htaccess", "/.env", "/config.json", "/backup.zip", "/admin", "/config", "/api", "/secret", "/wp-login.php", "/config.php"]


    start_time = datetime.now() - timedelta(hours=1)

    # V1.3 | Update to a universal log pattern
    with open(filename, 'w') as f:
        for i in range(num_lines):
            start_time += timedelta(seconds=random.randint(1, 15))            
            web_timestamp = start_time.strftime("%d/%b/%Y:%H:%M:%S")
            
            if random.random() > 0.2:
                # Randomly selects a normal route; this makes it possible to check and view traffic, regardless of its severity
                chosen_route = random.choice(normal_routes)
                
                if chosen_route == "/pagina-velha.html":
                    f.write(f'{ips[0]} - - [{web_timestamp} -0300] "{random.choice(methods)} {chosen_route} HTTP/1.1" 404\n') # If the route is the old page, it generates a 404 error (Not Found - LOW Category)
                                                                                                                                # Otherwise, normal traffic (200 OK)
                else:
                    f.write(f'{ips[0]} - - [{web_timestamp} -0300] "{random.choice(methods)} {chosen_route} HTTP/1.1" 200\n')                       
            else:
                f.write(f'{random.choice(ips[2:])} - - [{web_timestamp} -0300] "{random.choice(methods)} {random.choice(malicious_routes)} HTTP/1.1" 403\n')    # Malicious Traffic (HTTP Code 403 = Forbidden/Blocked)
            
    print(f"[+] File {filename} generated.")

if __name__ == "__main__":
    generate_dummy_logs()

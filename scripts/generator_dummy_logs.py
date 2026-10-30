import os
import random
from datetime import datetime, timedelta


def generate_dummy_logs(filename="data/test_auth.log", num_lines=500):
    # Garante que a pasta 'data/' existe antes de tentar criar o arquivo
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    ips = ["192.168.1.15", "10.0.0.42", "203.0.113.5", "198.51.100.22"]
    users = ["root", "admin", "guest", "john_doe"]


    # V1.3 Lists of common routes for simulating web traffic
    methods = ["GET", "POST", "PUT", "DELETE"]
    normal_routes = [
        "/home", "/pagina-velha.html", "/login", "/dashboard", "/contato", 
        "/sobre", "/produtos", "/servicos", "/assets/logo.png", 
        "/assets/style.css", "/assets/script.js", "/favicon.ico",
        "/old-page.html", "/about", "/contact", "/products", "/services", 
        "/blog", "/portfolio", "/careers", "/privacy-policy", "/terms-of-service"
    ]
    malicious_routes = [
        "/login?user=admin' OR '1'='1 UNION SELECT", "/etc/passwd", 
        "/var/www/html/config.php", "/admin.php", "/login.php", 
        "/wp-config.php", "/.git", "/.htaccess", "/.env", "/config.json", 
        "/backup.zip", "/admin", "/config", "/api", "/secret", "/wp-login.php"
    ]


    # V1.3.2 Lists of Syslog / Kernel events
    syslog_events = [
        f"kernel: [14235.12] Out of memory: Killed process {random.randint(1000, 9999)} (mysqld) — kernel panic - not syncing",
        f"kernel: [14299.84] nginx[{random.randint(1000, 9999)}]: segfault at 0000000000000008 ip 00007f8b4c error 4 in libc-2.31.so",
        f"systemd[1]: Failed to start Secure Socket Tunneling Protocol — unauthorized service execution attempt from {random.choice(ips[2:])}",
        "kernel: [14350.01] general protection fault: 0000 [#1] SMP PTI — segfault in auth_module.so"
    ]

    start_time = datetime.now() - timedelta(hours=1)

    with open(filename, 'w', encoding='utf-8') as f:
        for i in range(num_lines):
            start_time += timedelta(seconds=random.randint(1, 15))
            web_timestamp = start_time.strftime("%Y/%m/%d/%I-%M:%S-%p") 
            syslog_timestamp = start_time.strftime("%m %d %H:%M:%S")

            rand_val = random.random()


            # 80% Normal Traffic (Web 200 OK, Old Page 404 LOW, or SSH Accepted)
            if rand_val > 0.20:
                if random.random() > 0.15:
                    chosen_route = random.choice(normal_routes)

                    if chosen_route in ["/pagina-velha.html", "/old-page.html"]:
                        f.write(f'{ips[0]} - - [{web_timestamp} -0300] "{random.choice(methods)} {chosen_route} HTTP/1.1" 404\n')   # 404 Error (Not Found - LOW Category)
                    else:
                        f.write(f'{ips[0]} - - [{web_timestamp} -0300] "{random.choice(methods)} {chosen_route} HTTP/1.1" 200\n')   # 200 OK (Normal Traffic)
                else:
                    f.write(f"{syslog_timestamp} server-prod sshd[{random.randint(1000, 9999)}]: Accepted publickey for {users[3]} from {ips[0]} port {random.randint(30000, 60000)} ssh2\n")   # Normal SSH Login


            # 12% Malicious Web Traffic (HTTP 403)
            elif rand_val > 0.08:
                f.write(f'{random.choice(ips[2:])} - - [{web_timestamp} -0300] "{random.choice(methods)} {random.choice(malicious_routes)} HTTP/1.1" 403\n')


            # 5% Malicious SSH Traffic (Brute Force / Invalid User)
            elif rand_val > 0.03:
                attacker_ip = random.choice(ips[2:])
                target_user = random.choice(users)
                if random.random() > 0.5:
                    f.write(f"{syslog_timestamp} server-prod sshd[{random.randint(1000, 9999)}]: Failed password for {target_user} from {attacker_ip} port {random.randint(30000, 60000)} ssh2\n")
                else:
                    f.write(f"{syslog_timestamp} server-prod sshd[{random.randint(1000, 9999)}]: Invalid user {target_user} from {attacker_ip} port {random.randint(30000, 60000)} ssh2\n")


            # 3% Syslog / Kernel Anomalies (v1.3.2)
            else:
                f.write(f"{syslog_timestamp} server-prod {random.choice(syslog_events)}\n")

    print(f"[+] File {filename} generated with Multi-Format logs (Web, SSH, Syslog).")

if __name__ == "__main__":
    generate_dummy_logs()
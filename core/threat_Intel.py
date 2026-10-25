import os
import requests
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def check_IP(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    
    try:
        answer = requests.get(url, headers=headers)
        
        if answer.status_code == 200:
            data = answer.json()
            
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            if malicious > 0 or suspicious > 0:
                 return f"ATENÇÃO: O IP {ip} foi reportado como malicioso por {malicious} motores e suspeito por {suspicious}!"
            else:
                 return f"TUDO LIMPO: O IP {ip} parece limpo e seguro (0 detecções)."
                 
        else:
            return f"Erro na requisição. Código de status: {answer.status_code}"
            
    except Exception as e:
        return f"Ocorreu um erro: {e}"
    

if __name__ == "__main__":
    check_Result = check_IP("8.8.8.8")
    print(check_Result)
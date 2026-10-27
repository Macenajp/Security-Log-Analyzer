import os
import requests
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")


def check_ip(ip):
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
                 return f"WARNING: The IP {ip} has been reported as malicious by {malicious} engines and suspicious by {suspicious}!"
            else:
                 return f"ALL CLEAR: The IP {ip} appears to be clean and secure (0 detections)."
                 
        else:
            return f"Error in request. Status code: {answer.status_code}"
            
    except Exception as e:
        return f"An error occurred: {e}"
    

if __name__ == "__main__":
    check_result = check_ip("8.8.8.8")
    print(check_result)

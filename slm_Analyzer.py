import requests
import json

def analyze_Log_IA(log_Line, modelo="phi4-mini:latest"):
    url = "http://localhost:11434/api/generate"
    
    # Bloco do prompt imutável para a criação do Json
    prompt_str = f"""
    Analise o seguinte log de segurança. 
    Responda APENAS com um objeto JSON válido contendo as chaves:
    - "ip": (IP do atacante)
    - "threat": (tipo do ataque, ex: "brute_force", "invalid_user")
    - "severity": ("low", "medium", "high")
    
    NÃO inclua nenhuma explicação, texto adicional, markdown ou blocos de raciocínio.
    
    Log: '{log_Line}'
    """
    
    dados = {
        "model": modelo,
        "prompt": prompt_str,
        "stream": False,
        "format": "json", 
        "options": {
            "temperature": 0.0  
        }
    }
    
    try:
        resposta = requests.post(url, json=dados)
        resposta.raise_for_status()
        texto_puro = resposta.json().get("response", "").strip()
        
        # Bloco realiza a conversão do Json para um dicionário Python
        return json.loads(texto_puro)
        
    except json.JSONDecodeError:
        return {"error": "Falha ao estruturar o JSON", "raw_output": texto_puro}
    except requests.exceptions.RequestException as e:
        return {"error": f"Erro de conexão: {e}"}
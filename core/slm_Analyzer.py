import requests
import json
import re

def analyze_Log_IA(log_Line, model="phi4-mini:3.8b"):
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
        "model": model,
        "prompt": prompt_str,
        "stream": False,
        "format": "json", 
        "options": {
            "temperature": 0.0  
        }
    }
    
    try:
        answer = requests.post(url, json=dados)
        answer.raise_for_status()
        
        all_Data = answer.json()
        plain_Text = all_Data.get("response", "").strip()

        tokens = all_Data.get("eval_count", 0)
        time_Nanoseconds = all_Data.get("eval_duration", 1)
        time_Seconds = time_Nanoseconds / 1e9
        tokens_Per_Seconds = tokens / time_Seconds if time_Seconds > 0 else 0

        # Filtro de Regex para ignorar markdown (ex: ```json) e salvar apenas as chaves
        match = re.search(r'\{.*\}', plain_Text, re.DOTALL)
        clean_json_str = match.group(0) if match else plain_Text
            
        structured_Response = json.loads(clean_json_str)
        structured_Response["telemetry"] = {
            "tokens_sec": round(tokens_Per_Seconds, 2)
        }
        
        return structured_Response
        
    except json.JSONDecodeError:
        return {"error": "Falha ao estruturar o JSON", "raw_output": plain_Text}
    except requests.exceptions.RequestException as e:
        return {"error": f"Erro de conexão: {e}"}
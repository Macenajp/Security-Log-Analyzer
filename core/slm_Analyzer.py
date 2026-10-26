import requests
import json
import re


def analyze_log_ia(log_Line, model="phi4-mini:3.8b"):
    url = "http://localhost:11434/api/generate"
    
    # Bloco do prompt imutável para a criação do Json
    prompt_str = f"""
    Analise o seguinte log de segurança. 
    Responda APENAS com um objeto JSON válido contendo as chaves:
    - "ip": (IP do atacante)
    - "threat": (classifique usando EXATAMENTE UMA destas opções: "BRUTE_FORCE", "INVALID_USER", "SQL_INJECTION", "PATH_TRAVERSAL", "FORBIDDEN_ACCESS")
    - "severity": (use EXATAMENTE "LOW", "MEDIUM" ou "HIGH")
    
    Regras de Classificação de Ameaça (threat) - AVALIE NESTA ORDEM EXATA DE PRIORIDADE:
    1. Se o log contiver 'UNION SELECT' ou 'OR 1=1', use "SQL_INJECTION".
    2. Se o log contiver buscas por diretórios sensíveis (ex: '.env', '.git', 'config.php', 'passwd'), use "PATH_TRAVERSAL".
    3. Se o log contiver 'Failed password' ou 'Invalid user', use "INVALID_USER" ou "BRUTE_FORCE".
    4. Se o log retornar bloqueio (HTTP 403) E NÃO se encaixar em NENHUMA das regras acima, use "FORBIDDEN_ACCESS".
    
    Regras de Severidade (severity):
    - "HIGH": Injeções SQL, acessos a arquivos '.env' ou ataques usando usuários como 'root' e 'admin'.
    - "MEDIUM": Acesso negado comum (403) em páginas web não críticas ou falha de login de usuários normais.
    - "LOW": Qualquer outra anomalia menor.
    
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
        plain_text = all_Data.get("response", "").strip()

        tokens = all_Data.get("eval_count", 0)
        time_nanoseconds = all_Data.get("eval_duration", 1)
        time_seconds = time_nanoseconds / 1e9
        tokens_per_seconds = tokens / time_seconds if time_seconds > 0 else 0

        # Filtro de Regex para ignorar markdown (ex: ```json) e salvar apenas as chaves
        match = re.search(r'\{.*\}', plain_text, re.DOTALL)
        clean_json_str = match.group(0) if match else plain_text
            
        structured_response = json.loads(clean_json_str)
        structured_response["telemetry"] = {
            "tokens_sec": round(tokens_per_seconds, 2)
        }
        
        return structured_response
        
    except json.JSONDecodeError:
        return {"error": "Falha ao estruturar o JSON", "raw_output": plain_text}
    except requests.exceptions.RequestException as e:
        return {"error": f"Erro de conexão: {e}"}
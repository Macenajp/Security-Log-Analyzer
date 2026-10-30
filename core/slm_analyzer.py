import requests
import json
import re


def analyze_log_ia(log_line, model="gemma3:4b"):
    url = "http://localhost:11434/api/generate"
    
    # Immutable prompt block for creating JSON
    prompt_str = f"""
    Analyze the following security log. 
    Respond ONLY with a valid JSON object containing the keys:
    - "ip": (attacker's IP, or use "LOCAL_SYSTEM" if no IP address is present in the log)
    - "threat": (classify using EXACTLY ONE of these options: "BRUTE_FORCE", "INVALID_USER", "SQL_INJECTION", "PATH_TRAVERSAL", "FORBIDDEN_ACCESS", "RESOURCE_NOT_FOUND", "SYSTEM_FAILURE")
    - "severity": (use EXACTLY "LOW", "MEDIUM" or "HIGH")
    
    Threat Classification Rules - EVALUATE IN THIS EXACT ORDER OF PRIORITY:
    1. If the log contains 'UNION SELECT' or 'OR 1=1', use "SQL_INJECTION".
    2. If the log contains 'kernel panic', 'segfault', or 'unauthorized service', use "SYSTEM_FAILURE".
    3. If the log contains searches for sensitive directories (e.g., '.env', '.git', 'config.php', 'passwd'), use "PATH_TRAVERSAL".
    4. If the log contains 'Failed password' or 'Invalid user', use "INVALID_USER" or "BRUTE_FORCE".
    5. If the log returns a block (HTTP 403) AND DOES NOT fit ANY of the rules above, use "FORBIDDEN_ACCESS".
    6. If the log returns page not found (HTTP 404), use "RESOURCE_NOT_FOUND".
    
    Severity Rules:
    - "HIGH": SQL Injections, 'kernel panic', 'unauthorized service', access to '.env' files, or SSH attacks using 'root' and 'admin'.
    - "MEDIUM": Common access denied (403) on non-critical web pages, 'segfault' errors, or login failures of normal users (e.g., 'guest', 'john_doe').
    - "LOW": Page not found errors (404) or any other minor anomaly.
    
    DO NOT include any explanations, additional text, markdown, or reasoning blocks.
    
    Log: '{log_line}'
    """
    
    data = {
        "model": model,
        "prompt": prompt_str,
        "stream": False,
        "format": "json", 
        "options": {
            "temperature": 0.0  
        }
    }
    
    try:
        answer = requests.post(url, json=data)
        answer.raise_for_status()
        
        all_data = answer.json()
        plain_text = all_data.get("response", "").strip()

        tokens = all_data.get("eval_count", 0)
        time_nanoseconds = all_data.get("eval_duration", 1)
        time_seconds = time_nanoseconds / 1e9
        tokens_per_seconds = tokens / time_seconds if time_seconds > 0 else 0

        # Regex filter to ignore Markdown (e.g., ```json)) and save only the keys
        match = re.search(r'\{.*\}', plain_text, re.DOTALL)
        clean_json_str = match.group(0) if match else plain_text
            
        structured_response = json.loads(clean_json_str)
        structured_response["telemetry"] = {
            "tokens_sec": round(tokens_per_seconds, 2)
        }
        
        return structured_response
        
    except json.JSONDecodeError:
        return {"error": "Error structuring the JSON", "raw_output": plain_text}
    except requests.exceptions.RequestException as e:
        return {"error": f"Connection Error: {e}"}

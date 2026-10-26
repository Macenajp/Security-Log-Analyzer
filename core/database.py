import sqlite3
import os

DB_PATH = "data/secla_logs.db"


def get_connection():
    """Garante que a pasta 'data' existe e retorna a conexão com o SQLite."""
    os.makedirs("data", exist_ok=True)
    return sqlite3.connect(DB_PATH)


def initialize_db():
    """Cria a tabela 'security_logs' caso ela não exista no banco."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Criação modelo relacional
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            model_used TEXT,
            source_ip TEXT,
            threat_type TEXT,
            severity TEXT,
            vt_reputation TEXT,
            performance_ts TEXT,
            raw_log TEXT
        )
    ''')
    
    conn.commit()
    conn.close()


def insert_log(model, ip, threat, severity, vt_reputation, performance_ts, raw_log):
    """Função que será chamada pelo ui.py para salvar cada log na tabela."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Injeção de valores protegendo contra SQL Injection usando (?)
    cursor.execute('''
        INSERT INTO security_logs (model_used, source_ip, threat_type, severity, vt_reputation, performance_ts, raw_log)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (model, ip, threat, severity, vt_reputation, performance_ts, raw_log))
    
    conn.commit()
    conn.close()


def get_filtered_logs(severity_filter=None):
    """Busca logs no banco. Se severity_filter for passado, filtra por ele. Garante a ordem lógica."""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT source_ip, threat_type, severity, vt_reputation, timestamp FROM security_logs"
    params = ()
    
    if severity_filter:
        query += " WHERE severity = ?"
        params = (severity_filter,)
        
    # Bloco para ajudar a filtrar e ordernar os logs de acordo com a gravidade do alerta
    query += ''' ORDER BY 
                 CASE severity 
                    WHEN 'HIGH' THEN 1 
                    WHEN 'MEDIUM' THEN 2 
                    WHEN 'LOW' THEN 3 
                 END
             '''
             
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return rows


initialize_db()
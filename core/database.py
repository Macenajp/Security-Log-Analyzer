import sqlite3
import os

DB_PATH = "data/secla_logs.db"


def get_connection():
    """Ensures the 'data' folder exists and returns the SQLite connection."""
    os.makedirs("data", exist_ok=True)
    return sqlite3.connect(DB_PATH)


def initialize_db():
    """Creates the 'security_logs' table if it doesn't exist in the database."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Creating a Relational Model
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
    """Function that will be called by ui.py to save each log in the table."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Value injection to protect against SQL injection using (?)
    cursor.execute('''
        INSERT INTO security_logs (model_used, source_ip, threat_type, severity, vt_reputation, performance_ts, raw_log)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (model, ip, threat, severity, vt_reputation, performance_ts, raw_log))
    
    conn.commit()
    conn.close()


def get_filtered_logs(severity_filter=None):
    """Function to fetch logs from the database. If severity_filter is provided, it filters by that value. Ensures logical ordering."""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT source_ip, threat_type, severity, vt_reputation, timestamp FROM security_logs"
    params = ()
    
    if severity_filter:
        query += " WHERE severity = ?"
        params = (severity_filter,)
        
    # A section to help filter and sort logs based on alert severity
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
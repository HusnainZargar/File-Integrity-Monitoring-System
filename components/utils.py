import sqlite3
import time
import json

DB_FILE = 'components/baseline.db'


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS baselines (path TEXT PRIMARY KEY, attributes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, message TEXT)''')
    
    # Add details column if missing
    c.execute("PRAGMA table_info(logs)")
    columns = [col[1] for col in c.fetchall()]
    if 'details' not in columns:
        c.execute("ALTER TABLE logs ADD COLUMN details TEXT")
    
    conn.commit()
    conn.close()


def load_baseline():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT path, attributes FROM baselines")
    baseline = {row[0]: json.loads(row[1]) for row in c.fetchall()}
    conn.close()
    return baseline


def save_baseline(baseline):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for path, attrs in baseline.items():
        attrs_json = json.dumps(attrs)
        c.execute("INSERT OR REPLACE INTO baselines (path, attributes) VALUES (?, ?)", 
                  (path, attrs_json))
    conn.commit()
    conn.close()


def add_alert(message, details=None):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    details_json = json.dumps(details) if details else None
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (timestamp, message, details) VALUES (?, ?, ?)",
              (timestamp, message, details_json))
    conn.commit()
    conn.close()


def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT timestamp, message, details FROM logs ORDER BY timestamp DESC")
    logs = [{'timestamp': row[0], 'message': row[1],
             'details': json.loads(row[2]) if row[2] else None} 
            for row in c.fetchall()]
    conn.close()
    return logs


def get_alerts():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, message, details FROM logs 
        WHERE message LIKE '%change%' 
           OR message LIKE '%delete%' 
           OR message LIKE '%violation%' 
           OR message LIKE '%new%' 
           OR message LIKE '%moved%' 
           OR message LIKE '%renamed%'
        ORDER BY timestamp DESC
    """)
    alerts = [{'timestamp': row[0], 'message': row[1],
               'details': json.loads(row[2]) if row[2] else None} 
              for row in c.fetchall()]
    conn.close()
    return alerts

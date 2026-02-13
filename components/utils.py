import sqlite3
import time

DB_FILE = 'components/baseline.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS baselines (path TEXT PRIMARY KEY, hash TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, message TEXT)''')
    conn.commit()
    conn.close()

def load_baseline():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT path, hash FROM baselines")
    baseline = dict(c.fetchall())
    conn.close()
    return baseline

def save_baseline(baseline):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for path, h in baseline.items():
        c.execute("INSERT OR REPLACE INTO baselines (path, hash) VALUES (?, ?)", (path, h))
    conn.commit()
    conn.close()

def add_alert(message):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (timestamp, message) VALUES (?, ?)", (timestamp, message))
    conn.commit()
    conn.close()

def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT timestamp, message FROM logs ORDER BY timestamp DESC")
    logs = [{'timestamp': row[0], 'message': row[1]} for row in c.fetchall()]
    conn.close()
    return logs

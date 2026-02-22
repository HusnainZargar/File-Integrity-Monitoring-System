import os
import sqlite3
import time
import json

# Resolve DB path relative to this file so it works regardless of CWD
_components_dir = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(_components_dir, 'baseline.db')


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS baselines (path TEXT PRIMARY KEY, attributes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, message TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        last_login TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, message TEXT)''')
    # Add details column if missing
    c.execute("PRAGMA table_info(logs)")
    columns = [col[1] for col in c.fetchall()]
    if 'details' not in columns:
        c.execute("ALTER TABLE logs ADD COLUMN details TEXT")
    # Add last_login to users if missing
    c.execute("PRAGMA table_info(users)")
    user_cols = [col[1] for col in c.fetchall()]
    if 'last_login' not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
    conn.commit()
    conn.close()


def get_user(username):
    """Return user row as dict with username, password_hash, last_login or None."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("SELECT username, password_hash, last_login FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {'username': row[0], 'password_hash': row[1], 'last_login': row[2]}
    except sqlite3.OperationalError:
        conn.close()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT username, password_hash FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {'username': row[0], 'password_hash': row[1], 'last_login': None}


def update_user_password(username, password_hash):
    """Update password hash for the given username."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
    conn.commit()
    conn.close()


def create_user(username, password_hash):
    """Insert a new user. Fails if username exists."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    finally:
        conn.close()


def user_count():
    """Return number of users (for seeding default admin)."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    n = c.fetchone()[0]
    conn.close()
    return n


def update_last_login(username):
    """Set last_login to current timestamp for the given user."""
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET last_login = ? WHERE username = ?", (ts, username))
    conn.commit()
    conn.close()


def update_username(old_username, new_username):
    """Change username. Returns True if success, False if new_username already exists."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET username = ? WHERE username = ?", (new_username, old_username))
        if c.rowcount == 0:
            return False
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


# --- Config (key/value, value stored as JSON where needed) ---
_DEFAULT_CONFIG = {
    'monitoring_active': 1,
    'monitored_paths': [],  # list of absolute paths
    'recursive': 1,
    'ignore_hidden': 1,
    'auto_update_baseline': 0,
    'excluded_paths': [],   # list of path prefixes to skip
}


def get_config(key):
    """Get config value (returns Python type; lists/dicts from JSON)."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT value FROM config WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    if row is None:
        return _DEFAULT_CONFIG.get(key)
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        return row[0]


def set_config(key, value):
    """Set config value (will JSON-serialize lists/dicts)."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    v = json.dumps(value) if isinstance(value, (list, dict)) else str(value)
    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, v))
    conn.commit()
    conn.close()


def add_settings_audit(message):
    """Append a message to settings audit log."""
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO settings_audit (timestamp, message) VALUES (?, ?)", (ts, message))
    conn.commit()
    conn.close()


def get_settings_audit(limit=100):
    """Return recent settings audit entries (newest first)."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT timestamp, message FROM settings_audit ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{'timestamp': r[0], 'message': r[1]} for r in rows]


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


def remove_baseline_under_path(path_prefix):
    """Remove all baseline entries whose path equals path_prefix or starts with path_prefix/."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    prefix = path_prefix.rstrip('/') + '/'
    c.execute("DELETE FROM baselines WHERE path = ? OR path LIKE ?", (path_prefix, prefix + '%'))
    conn.commit()
    conn.close()


def clear_baseline():
    """Delete all baseline entries."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM baselines")
    conn.commit()
    conn.close()


def clear_logs():
    """Delete all log entries (events and alerts)."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM logs")
    conn.commit()
    conn.close()


def clear_settings_audit():
    """Delete all settings audit log entries."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM settings_audit")
    conn.commit()
    conn.close()


def clear_all_except_account():
    """Clear logs, settings_audit, and baselines in one transaction. Does not touch users or config."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM logs")
        c.execute("DELETE FROM settings_audit")
        c.execute("DELETE FROM baselines")
        c.execute("DELETE FROM config")
        conn.commit()
    except sqlite3.OperationalError:
        conn.rollback()
    finally:
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
    """Return only file/attribute integrity alerts; exclude baseline/operational messages."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, message, details FROM logs 
        WHERE (message LIKE '%change%' 
           OR message LIKE '%delete%' 
           OR message LIKE '%violation%' 
           OR message LIKE '%new%' 
           OR message LIKE '%moved%' 
           OR message LIKE '%renamed%')
        AND message NOT LIKE '%Added to baseline%'
        AND message NOT LIKE '%Initial scan done%'
        AND message NOT LIKE '%Monitoring started%'
        ORDER BY timestamp DESC
    """)
    alerts = [{'timestamp': row[0], 'message': row[1],
               'details': json.loads(row[2]) if row[2] else None}
              for row in c.fetchall()]
    conn.close()
    return alerts

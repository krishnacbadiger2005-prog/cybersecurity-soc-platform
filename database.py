# database.py
import os
import sqlite3

# When running in Docker, the shared database volume is mounted at /app/database
if os.path.exists("/app/database") or os.environ.get("DOCKER_CONTAINER"):
    DATABASE = "/app/database/security.db"
else:
    DATABASE = os.environ.get("DATABASE_PATH", "security.db")


def get_db():
    db_dir = os.path.dirname(DATABASE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            source TEXT DEFAULT 'PORTFOLIO',
            event_hash TEXT
        )
    """)

    # Apply migrations if existing table lacked columns
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(login_events)")
    cols = [col[1] for col in cursor.fetchall()]
    if "source" not in cols:
        cursor.execute("ALTER TABLE login_events ADD COLUMN source TEXT DEFAULT 'PORTFOLIO'")
        cursor.execute("UPDATE login_events SET source = 'PORTFOLIO' WHERE source IS NULL")
    if "event_hash" not in cols:
        cursor.execute("ALTER TABLE login_events ADD COLUMN event_hash TEXT")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_login_events_hash ON login_events(event_hash)")

    conn.commit()
    conn.close()


def log_login_event(username, ip_address, status, source="PORTFOLIO"):
    db_dir = os.path.dirname(DATABASE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO login_events
        (username, ip_address, status, source)
        VALUES (?, ?, ?, ?)
    """, (username, ip_address, status, source))
    conn.commit()
    conn.close()


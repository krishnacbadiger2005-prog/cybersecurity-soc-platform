"""
log_parser.py — Linux Authentication Log Parser for SOC Security Lab
=====================================================================
Parses Linux SSH authentication logs (auth.log / journal), extracts
structured telemetry (username, IP, timestamp, status), tags the source
as LINUX_AUTH_LOG, applies deduplication hashing, and ingests events into
the shared SQLite database.
"""

import re
import os
import sqlite3
import hashlib
from datetime import datetime

# Resolve default database path (security.db in repository root)
LAB_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(LAB_DIR)
# When running in Docker, the shared database volume is mounted at /app/database
if os.path.exists("/app/database") or os.environ.get("DOCKER_CONTAINER"):
    DEFAULT_DB_PATH = "/app/database/security.db"
else:
    DEFAULT_DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "security.db"))
DEFAULT_LOG_PATH = os.path.join(LAB_DIR, "sample_logs", "auth.log")


def parse_log_line(line):
    """
    Parse a single Linux authentication log line.
    
    Detects:
      - 'Accepted password' -> status = 'SUCCESS'
      - 'Failed password'   -> status = 'FAILED'
      
    Extracts:
      - timestamp:  e.g. 'Sep 20 10:02:10'
      - username:   e.g. 'krishna'
      - ip_address: e.g. '192.168.1.20'
      - status:     'SUCCESS' or 'FAILED'
      
    Returns a dictionary or None if line is not an authentication event.
    """
    if "Failed password" in line:
        status = "FAILED"
    elif "Accepted password" in line:
        status = "SUCCESS"
    else:
        return None

    # Extract username: appears after 'for' (optionally with 'invalid user') and before 'from'
    username_match = re.search(r"for (?:invalid user )?(\S+) from", line)
    if not username_match:
        return None
    username = username_match.group(1)

    # Extract IP address: IPv4 format after 'from'
    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    if not ip_match:
        return None
    ip_address = ip_match.group(1)

    # Extract timestamp from beginning of line (e.g., 'Sep 20 10:02:10')
    timestamp_match = re.search(r"^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line.strip())
    if timestamp_match:
        timestamp = timestamp_match.group(1)
    else:
        # Fallback to current timestamp if not present
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")

    return {
        "username": username,
        "ip_address": ip_address,
        "status": status,
        "timestamp": timestamp
    }


def parse_log_file(filename):
    """
    Read an authentication log file and parse all authentication events.
    Returns a list of parsed event dictionaries.
    """
    events = []
    if not os.path.exists(filename):
        # Also check relative to current working directory or LAB_DIR
        alt_path = os.path.join(LAB_DIR, filename)
        if os.path.exists(alt_path):
            filename = alt_path
        else:
            raise FileNotFoundError(f"Log file not found: {filename}")

    with open(filename, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            event = parse_log_line(line)
            if event:
                events.append(event)

    return events


def compute_event_hash(event, source="LINUX_AUTH_LOG"):
    """
    Generate a deterministic SHA-256 fingerprint for the event (STEP 26).
    Signature: source + timestamp + username + ip_address + status
    """
    raw_key = f"{source}|{event.get('timestamp')}|{event.get('username')}|{event.get('ip_address')}|{event.get('status')}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def ensure_db_schema(conn):
    """Ensure login_events table exists with source and event_hash columns."""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL
        )
    """)

    # Check for missing columns and apply migrations
    cursor.execute("PRAGMA table_info(login_events)")
    columns = [row[1] for row in cursor.fetchall()]

    if "source" not in columns:
        cursor.execute("ALTER TABLE login_events ADD COLUMN source TEXT DEFAULT 'PORTFOLIO'")
        cursor.execute("UPDATE login_events SET source = 'PORTFOLIO' WHERE source IS NULL")

    if "event_hash" not in columns:
        cursor.execute("ALTER TABLE login_events ADD COLUMN event_hash TEXT")

    # Create index on event_hash for fast duplicate lookups
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_login_events_hash ON login_events(event_hash)")
    conn.commit()


def insert_events(events, db_path=None, source="LINUX_AUTH_LOG"):
    """
    Insert parsed authentication events into SQLite database with source tagging
    and duplicate event prevention using event_hash.
    
    Returns:
      dict with keys: parsed, inserted, duplicates
    """
    if db_path is None:
        db_path = DEFAULT_DB_PATH

    conn = sqlite3.connect(db_path)
    ensure_db_schema(conn)
    cursor = conn.cursor()

    parsed_count = len(events)
    inserted_count = 0
    duplicate_count = 0

    for event in events:
        event_hash = compute_event_hash(event, source)

        # Check for duplicate
        cursor.execute("SELECT id FROM login_events WHERE event_hash = ? LIMIT 1", (event_hash,))
        if cursor.fetchone():
            duplicate_count += 1
            continue

        cursor.execute("""
            INSERT INTO login_events (username, ip_address, timestamp, status, source, event_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            event["username"],
            event["ip_address"],
            event["timestamp"],
            event["status"],
            source,
            event_hash
        ))
        inserted_count += 1

    conn.commit()
    conn.close()

    return {
        "parsed": parsed_count,
        "inserted": inserted_count,
        "duplicates": duplicate_count
    }


if __name__ == "__main__":
    # Resolve log path
    target_log = DEFAULT_LOG_PATH
    if not os.path.exists(target_log):
        target_log = "sample_logs/auth.log"

    print(f"Reading log file: {target_log}")
    events = parse_log_file(target_log)

    print("\n--- Parsed Events ---")
    for event in events:
        print(event)

    print("\n--- Ingesting into Database ---")
    result = insert_events(events, db_path=DEFAULT_DB_PATH, source="LINUX_AUTH_LOG")
    print(f"Parsed {result['parsed']} events")
    if result['duplicates'] > 0:
        print(f"Inserted {result['inserted']} events ({result['duplicates']} duplicates skipped)")
    else:
        print(f"Inserted {result['inserted']} events")

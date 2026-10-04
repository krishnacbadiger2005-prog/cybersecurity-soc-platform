"""
view_db.py — CLI Database Inspector for Portfolio & Security Lab
================================================================
A lightweight CLI tool to view tables, users, and login events directly in PowerShell
without needing sqlite3.exe installed.

Usage:
    python view_db.py              # Display summary and recent records
    python view_db.py users        # Display all users
    python view_db.py events       # Display all login events
    python view_db.py metrics      # Display Phase 3 Security Lab metrics
    python view_db.py query "SQL"  # Run any custom SQL query
"""

import sys
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security.db")

def print_table(headers, rows):
    if not rows:
        print("  (No records found)\n")
        return

    # Calculate column widths
    str_rows = [[str(item if item is not None else "NULL") for item in row] for row in rows]
    col_widths = [len(h) for h in headers]
    for row in str_rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(val))

    # Print header
    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    separator = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    print(header_line)
    print(separator)

    # Print rows
    for row in str_rows:
        print(" | ".join(row[i].ljust(col_widths[i]) for i in range(len(headers))))
    print(f"Total: {len(rows)} row(s)\n")


def view_summary():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("=" * 60)
    print("  PORTFOLIO & SECURITY LAB DATABASE INSPECTOR (security.db)")
    print("=" * 60)

    # Tables list
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [r[0] for r in cursor.fetchall()]
    print(f"\nDiscovered Tables: {', '.join(tables)}\n")

    # Users
    if "users" in tables:
        print("[ Table: users ]")
        cursor.execute("SELECT id, username, SUBSTR(password_hash, 1, 24) || '...' as password_hash, created_at FROM users")
        headers = ["id", "username", "password_hash", "created_at"]
        print_table(headers, cursor.fetchall())

    # Login events
    if "login_events" in tables:
        print("[ Table: login_events (Recent 10) ]")
        cursor.execute("SELECT id, username, ip_address, timestamp, status, source FROM login_events ORDER BY id DESC LIMIT 10")
        headers = ["id", "username", "ip_address", "timestamp", "status", "source"]
        print_table(headers, cursor.fetchall())

    conn.close()


def view_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    print("\n--- ALL USERS ---")
    cursor.execute("SELECT id, username, password_hash, created_at FROM users")
    print_table(["id", "username", "password_hash", "created_at"], cursor.fetchall())
    conn.close()


def view_events():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    print("\n--- ALL LOGIN EVENTS ---")
    cursor.execute("SELECT id, username, ip_address, timestamp, status, source FROM login_events ORDER BY id DESC")
    print_table(["id", "username", "ip_address", "timestamp", "status", "source"], cursor.fetchall())
    conn.close()


def view_metrics():
    # Load from security-lab database module if possible
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "security-lab"))
        import database
        data = database.get_dashboard_data()
        print("\n" + "=" * 50)
        print("  SECURITY LAB METRICS SUMMARY (PHASE 3)")
        print("=" * 50)
        print(f"Total Authentication Attempts : {data['total_attempts']}")
        print(f"Successful Attempts           : {data['successful_attempts']} ({data['success_rate']}%)")
        print(f"Failed Attempts               : {data['failed_attempts']} ({data['failure_rate']}%)")
        print("\nTop Source IPs:")
        for idx, ip in enumerate(data['top_source_ips'], 1):
            print(f"  #{idx}  {ip['ip_address']:16} {ip['count']} attempt(s)")
        print("\nRecent 5 Events:")
        for ev in data['recent_events'][:5]:
            status_flag = "[OK]  " if ev['status'] == 'SUCCESS' else "[FAIL]"
            print(f"  #{ev['id']:<3} {ev['timestamp']} | {status_flag} {ev['username']:<12} from {ev['ip_address']}")
        print("=" * 50 + "\n")
    except Exception as e:
        print(f"Error computing metrics: {e}")


def run_custom_query(sql):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        if cursor.description:
            headers = [desc[0] for desc in cursor.description]
            print_table(headers, cursor.fetchall())
        else:
            conn.commit()
            print("Query executed successfully.")
    except Exception as e:
        print(f"SQL Error: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        view_summary()
    elif sys.argv[1].lower() == "users":
        view_users()
    elif sys.argv[1].lower() == "events":
        view_events()
    elif sys.argv[1].lower() == "metrics":
        view_metrics()
    elif sys.argv[1].lower() == "query" and len(sys.argv) > 2:
        run_custom_query(" ".join(sys.argv[2:]))
    else:
        print("Usage: python view_db.py [users | events | metrics | query <SQL>]")

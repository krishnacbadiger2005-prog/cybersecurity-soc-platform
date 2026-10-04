import sqlite3
import os
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# When running in Docker, the shared database volume is mounted at /app/database
if os.path.exists("/app/database") or os.environ.get("DOCKER_CONTAINER"):
    DATABASE = "/app/database/security.db"
else:
    DATABASE = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "security.db"))


class EventRecord(tuple):
    """
    Hybrid record supporting both tuple indices for template rendering:
      event[0] -> username
      event[1] -> ip_address
      event[2] -> timestamp
      event[3] -> status
      event[4] -> source
    And dictionary keys for API/pipeline compatibility:
      event['id'], event['username'], event['ip_address'], event['timestamp'], event['status'], event['source']
    """
    def __new__(cls, d):
        return super().__new__(cls, (
            d.get("username", ""),
            d.get("ip_address", ""),
            d.get("timestamp", ""),
            d.get("status", ""),
            d.get("source", "PORTFOLIO")
        ))

    def __init__(self, d):
        self._dict = dict(d)
        if "source" not in self._dict:
            self._dict["source"] = "PORTFOLIO"

    def __getitem__(self, item):
        if isinstance(item, str):
            return self._dict.get(item)
        return super().__getitem__(item)

    def __contains__(self, key):
        return key in self._dict

    def keys(self):
        return self._dict.keys()

    def get(self, key, default=None):
        return self._dict.get(key, default)


class IpRecord(tuple):
    """
    Hybrid record supporting both tuple indices for template rendering:
      ip[0] -> ip_address
      ip[1] -> attempts
    And dictionary keys for API/pipeline compatibility:
      ip['ip_address'], ip['count'], ip['attempts']
    """
    def __new__(cls, d):
        return super().__new__(cls, (d["ip_address"], d["attempts"]))

    def __init__(self, d):
        self._dict = dict(d)
        if "count" not in self._dict:
            self._dict["count"] = d["attempts"]

    def __getitem__(self, item):
        if isinstance(item, str):
            return self._dict[item]
        return super().__getitem__(item)

    def __contains__(self, key):
        return key in self._dict

    def keys(self):
        return self._dict.keys()

    def get(self, key, default=None):
        return self._dict.get(key, default)


class AlertRecord(tuple):
    """
    Hybrid record for security alerts:
      alert[0] -> ip_address
      alert[1] -> attempt_count
      alert[2] -> severity
      alert[3] -> timestamp
    """
    def __new__(cls, d):
        return super().__new__(cls, (d["ip_address"], d["attempt_count"], d["severity"], d["timestamp"]))

    def __init__(self, d):
        self._dict = dict(d)

    def __getitem__(self, item):
        if isinstance(item, str):
            return self._dict[item]
        return super().__getitem__(item)

    def __contains__(self, key):
        return key in self._dict

    def keys(self):
        return self._dict.keys()

    def get(self, key, default=None):
        return self._dict.get(key, default)


def get_connection():
    db_dir = os.path.dirname(DATABASE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema():
    """Ensure security_alerts table and all required tables and columns exist."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            severity TEXT NOT NULL DEFAULT 'HIGH',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Check for missing columns in login_events
    cursor.execute("PRAGMA table_info(login_events)")
    columns = [row[1] for row in cursor.fetchall()]
    if "source" not in columns:
        cursor.execute("ALTER TABLE login_events ADD COLUMN source TEXT DEFAULT 'PORTFOLIO'")
        cursor.execute("UPDATE login_events SET source = 'PORTFOLIO' WHERE source IS NULL")
    if "event_hash" not in columns:
        cursor.execute("ALTER TABLE login_events ADD COLUMN event_hash TEXT")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_login_events_hash ON login_events(event_hash)")

    conn.commit()
    conn.close()


# Ensure tables exist on module import
ensure_schema()


def _build_source_filter(source="all"):
    """Return SQL condition snippet and params for source filtering."""
    if not source or source == "all":
        return "", []
    s = source.lower().strip()
    if s == "portfolio":
        return " AND (source = 'PORTFOLIO' OR source IS NULL)", []
    if s in ("linux", "linux_auth_log"):
        return " AND (source = 'LINUX_AUTH_LOG' OR source = 'LINUX')", []
    return " AND source = ?", [source]


def get_cutoff_pair(time_range="all"):
    """
    Calculate (cutoff_utc, cutoff_local) strings based on requested time range:
    '15m', '1h', '24h', '7d', 'all'
    """
    if not time_range or time_range == "all":
        return None, None

    minutes_map = {
        "15m": 15,
        "1h": 60,
        "24h": 1440,
        "7d": 10080
    }
    minutes = minutes_map.get(time_range)
    if not minutes:
        return None, None

    utc_cut = (datetime.utcnow() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    loc_cut = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    return utc_cut, loc_cut


def record_security_alert(ip_address, attempt_count, severity="HIGH"):
    """Record an alert if not already logged for this IP in the last 10 minutes."""
    ensure_schema()
    conn = get_connection()
    cursor = conn.cursor()

    cutoff_utc = (datetime.utcnow() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    cutoff_loc = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT id FROM security_alerts
        WHERE ip_address = ? AND (timestamp >= ? OR timestamp >= ?)
        LIMIT 1
    """, (ip_address, cutoff_utc, cutoff_loc))
    existing = cursor.fetchone()

    if not existing:
        cursor.execute("""
            INSERT INTO security_alerts (ip_address, attempt_count, severity)
            VALUES (?, ?, ?)
        """, (ip_address, attempt_count, severity))
        conn.commit()

    conn.close()


def get_security_alerts(limit=10, time_range="all"):
    """Return recent security alerts from security_alerts table."""
    ensure_schema()
    conn = get_connection()
    cursor = conn.cursor()

    utc_cut, loc_cut = get_cutoff_pair(time_range)

    if utc_cut:
        cursor.execute("""
            SELECT id, ip_address, attempt_count, severity, timestamp
            FROM security_alerts
            WHERE (timestamp >= ? OR timestamp >= ?)
            ORDER BY id DESC
            LIMIT ?
        """, (utc_cut, loc_cut, limit))
    else:
        cursor.execute("""
            SELECT id, ip_address, attempt_count, severity, timestamp
            FROM security_alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

    rows = cursor.fetchall()
    alerts = [AlertRecord(dict(r)) for r in rows]
    conn.close()
    return alerts


def get_total_attempts(time_range="all", source="all"):
    conn = get_connection()
    cursor = conn.cursor()
    utc_cut, loc_cut = get_cutoff_pair(time_range)
    src_sql, src_params = _build_source_filter(source)

    if utc_cut:
        cursor.execute(f"""
            SELECT COUNT(*) FROM login_events
            WHERE (timestamp >= ? OR timestamp >= ?) {src_sql}
        """, [utc_cut, loc_cut] + src_params)
    else:
        cursor.execute(f"SELECT COUNT(*) FROM login_events WHERE 1=1 {src_sql}", src_params)

    result = cursor.fetchone()[0]
    conn.close()
    return result


def get_successful_attempts(time_range="all", source="all"):
    conn = get_connection()
    cursor = conn.cursor()
    utc_cut, loc_cut = get_cutoff_pair(time_range)
    src_sql, src_params = _build_source_filter(source)

    if utc_cut:
        cursor.execute(f"""
            SELECT COUNT(*) FROM login_events
            WHERE status = 'SUCCESS' AND (timestamp >= ? OR timestamp >= ?) {src_sql}
        """, [utc_cut, loc_cut] + src_params)
    else:
        cursor.execute(f"SELECT COUNT(*) FROM login_events WHERE status = 'SUCCESS' {src_sql}", src_params)

    result = cursor.fetchone()[0]
    conn.close()
    return result


def get_failed_attempts(time_range="all", source="all"):
    conn = get_connection()
    cursor = conn.cursor()
    utc_cut, loc_cut = get_cutoff_pair(time_range)
    src_sql, src_params = _build_source_filter(source)

    if utc_cut:
        cursor.execute(f"""
            SELECT COUNT(*) FROM login_events
            WHERE status = 'FAILED' AND (timestamp >= ? OR timestamp >= ?) {src_sql}
        """, [utc_cut, loc_cut] + src_params)
    else:
        cursor.execute(f"SELECT COUNT(*) FROM login_events WHERE status = 'FAILED' {src_sql}", src_params)

    result = cursor.fetchone()[0]
    conn.close()
    return result


def get_recent_events(limit=10, time_range="all", source="all"):
    conn = get_connection()
    cursor = conn.cursor()
    utc_cut, loc_cut = get_cutoff_pair(time_range)
    src_sql, src_params = _build_source_filter(source)

    if utc_cut:
        cursor.execute(f"""
            SELECT id, username, ip_address, timestamp, status, source
            FROM login_events
            WHERE (timestamp >= ? OR timestamp >= ?) {src_sql}
            ORDER BY id DESC
            LIMIT ?
        """, [utc_cut, loc_cut] + src_params + [limit])
    else:
        cursor.execute(f"""
            SELECT id, username, ip_address, timestamp, status, source
            FROM login_events
            WHERE 1=1 {src_sql}
            ORDER BY id DESC
            LIMIT ?
        """, src_params + [limit])

    rows = cursor.fetchall()
    events = [EventRecord(dict(r)) for r in rows]
    conn.close()
    return events


def get_top_ips(limit=10, time_range="all", source="all"):
    conn = get_connection()
    cursor = conn.cursor()
    utc_cut, loc_cut = get_cutoff_pair(time_range)
    src_sql, src_params = _build_source_filter(source)

    if utc_cut:
        cursor.execute(f"""
            SELECT ip_address, COUNT(*) AS attempts, COUNT(*) AS count
            FROM login_events
            WHERE (timestamp >= ? OR timestamp >= ?) {src_sql}
            GROUP BY ip_address
            ORDER BY attempts DESC
            LIMIT ?
        """, [utc_cut, loc_cut] + src_params + [limit])
    else:
        cursor.execute(f"""
            SELECT ip_address, COUNT(*) AS attempts, COUNT(*) AS count
            FROM login_events
            WHERE 1=1 {src_sql}
            GROUP BY ip_address
            ORDER BY attempts DESC
            LIMIT ?
        """, src_params + [limit])

    rows = cursor.fetchall()
    ips = [IpRecord(dict(r)) for r in rows]
    conn.close()
    return ips


def get_login_timeline(time_range="all", source="all"):
    """
    Return time-series login attempts grouped by time intervals for the line chart.
    Returns list of dicts: [{'time': '10:00', 'attempts': 5, 'success': 3, 'failed': 2}]
    """
    conn = get_connection()
    cursor = conn.cursor()
    utc_cut, loc_cut = get_cutoff_pair(time_range)
    src_sql, src_params = _build_source_filter(source)

    # Format interval depending on range (hourly for 24h/7d, 5-minute for 15m/1h/all)
    if time_range in ("24h", "7d"):
        time_format = "%m-%d %H:00"
    else:
        time_format = "%H:%M"

    bucket_expr = f"COALESCE(strftime('{time_format}', timestamp), CASE WHEN timestamp LIKE '%:%:%' THEN substr(timestamp, -8, 5) ELSE 'N/A' END)"

    if utc_cut:
        cursor.execute(f"""
            SELECT {bucket_expr} AS time_bucket,
                   COUNT(*) AS total_count,
                   SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS success_count,
                   SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed_count
            FROM login_events
            WHERE (timestamp >= ? OR timestamp >= ?) {src_sql}
            GROUP BY time_bucket
            ORDER BY timestamp ASC
            LIMIT 30
        """, [utc_cut, loc_cut] + src_params)
    else:
        cursor.execute(f"""
            SELECT {bucket_expr} AS time_bucket,
                   COUNT(*) AS total_count,
                   SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS success_count,
                   SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed_count
            FROM login_events
            WHERE 1=1 {src_sql}
            GROUP BY time_bucket
            ORDER BY timestamp ASC
            LIMIT 30
        """, src_params)

    rows = cursor.fetchall()
    timeline = []
    for r in rows:
        bucket = r[0] if r[0] else "N/A"
        timeline.append({
            "time": bucket,
            "attempts": r[1],
            "success": r[2] or 0,
            "failed": r[3] or 0
        })

    conn.close()
    return timeline


def get_dashboard_stats(time_range="all", source="all"):
    """
    Phase 5 & 7 Core Statistics:
    - successful_logins
    - failed_logins
    - suspicious_activity
    - security_alerts
    """
    ensure_schema()
    conn = get_connection()
    cursor = conn.cursor()

    successful = get_successful_attempts(time_range, source)
    failed = get_failed_attempts(time_range, source)

    # Calculate suspicious activity using detector
    try:
        from detector import detect_suspicious_ips
        suspicious_list = detect_suspicious_ips()
        suspicious_count = len(suspicious_list)
        # Record alerts for newly found suspicious activity
        for ip, count in suspicious_list:
            sev = "CRITICAL" if count >= 10 else ("HIGH" if count >= 5 else "MEDIUM")
            record_security_alert(ip, count, sev)
    except Exception:
        suspicious_count = 0

    # Total security alerts count
    utc_cut, loc_cut = get_cutoff_pair(time_range)
    if utc_cut:
        cursor.execute("""
            SELECT COUNT(*) FROM security_alerts
            WHERE (timestamp >= ? OR timestamp >= ?)
        """, (utc_cut, loc_cut))
    else:
        cursor.execute("SELECT COUNT(*) FROM security_alerts")

    alerts_count = cursor.fetchone()[0]
    conn.close()

    return {
        "successful_logins": successful,
        "failed_logins": failed,
        "suspicious_activity": suspicious_count,
        "security_alerts": alerts_count
    }


# Compatibility aliases
get_db = get_connection
get_top_source_ips = get_top_ips


def get_dashboard_data(time_range="all", source="all"):
    stats = get_dashboard_stats(time_range, source)
    total = stats["successful_logins"] + stats["failed_logins"]
    success = stats["successful_logins"]
    failed = stats["failed_logins"]
    recent = get_recent_events(10, time_range, source)
    top_ips = get_top_ips(10, time_range, source)
    alerts = get_security_alerts(10, time_range)
    timeline = get_login_timeline(time_range, source)

    success_rate = round((success / total) * 100, 1) if total > 0 else 0.0
    failure_rate = round((failed / total) * 100, 1) if total > 0 else 0.0

    return {
        "total_attempts": total,
        "successful_attempts": success,
        "failed_attempts": failed,
        "successful_logins": success,
        "failed_logins": failed,
        "suspicious_activity": stats["suspicious_activity"],
        "security_alerts": stats["security_alerts"],
        "success_rate": success_rate,
        "failure_rate": failure_rate,
        "recent_events": recent,
        "top_ips": top_ips,
        "top_source_ips": top_ips,
        "alerts": alerts,
        "timeline": timeline,
    }


def get_report_date_bounds():
    """Return earliest date and latest date of recorded login events (or today)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM login_events")
    row = cursor.fetchone()
    conn.close()

    today = datetime.now().strftime("%Y-%m-%d")
    min_date = row[0][:10] if (row and row[0] and len(row[0]) >= 10 and row[0][0].isdigit()) else today
    max_date = row[1][:10] if (row and row[1] and len(row[1]) >= 10 and row[1][0].isdigit()) else today
    return min_date, max_date


def get_events_for_report(start_date=None, end_date=None, source="all"):
    """
    Retrieve authentication events for reporting filtered by date range and source.
    Returns list of EventRecord objects chronologically (ASC).
    """
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT id, username, ip_address, timestamp, status, source FROM login_events WHERE 1=1"
    params = []

    if start_date and end_date:
        start_ts = f"{start_date.strip()} 00:00:00" if len(start_date.strip()) == 10 else start_date.strip()
        end_ts = f"{end_date.strip()} 23:59:59" if len(end_date.strip()) == 10 else end_date.strip()
        query += " AND timestamp >= ? AND timestamp <= ?"
        params.extend([start_ts, end_ts])
    elif start_date:
        start_ts = f"{start_date.strip()} 00:00:00" if len(start_date.strip()) == 10 else start_date.strip()
        query += " AND timestamp >= ?"
        params.append(start_ts)
    elif end_date:
        end_ts = f"{end_date.strip()} 23:59:59" if len(end_date.strip()) == 10 else end_date.strip()
        query += " AND timestamp <= ?"
        params.append(end_ts)

    src_sql, src_params = _build_source_filter(source)
    query += src_sql
    params.extend(src_params)

    query += " ORDER BY id ASC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    events = [EventRecord(dict(r)) for r in rows]
    conn.close()
    return events


def get_alerts_for_report(start_date=None, end_date=None):
    """
    Retrieve security alerts for reporting filtered by date range.
    Returns list of AlertRecord objects chronologically (ASC).
    """
    ensure_schema()
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT id, ip_address, attempt_count, severity, timestamp FROM security_alerts"
    params = []

    if start_date and end_date:
        start_ts = f"{start_date.strip()} 00:00:00" if len(start_date.strip()) == 10 else start_date.strip()
        end_ts = f"{end_date.strip()} 23:59:59" if len(end_date.strip()) == 10 else end_date.strip()
        query += " WHERE timestamp >= ? AND timestamp <= ?"
        params.extend([start_ts, end_ts])
    elif start_date:
        start_ts = f"{start_date.strip()} 00:00:00" if len(start_date.strip()) == 10 else start_date.strip()
        query += " WHERE timestamp >= ?"
        params.append(start_ts)
    elif end_date:
        end_ts = f"{end_date.strip()} 23:59:59" if len(end_date.strip()) == 10 else end_date.strip()
        query += " WHERE timestamp <= ?"
        params.append(end_ts)

    query += " ORDER BY id ASC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    alerts = [AlertRecord(dict(r)) for r in rows]
    conn.close()
    return alerts


def clear_all_logs():
    """
    Clear all login attempts and security alerts from the database.
    Preserves users table so user accounts remain intact.
    Also clears sample log files if present so old logs do not persist.
    """
    ensure_schema()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_events")
    cursor.execute("DELETE FROM security_alerts")
    try:
        cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('login_events', 'security_alerts')")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

    # Clear sample log files so old logs do not persist
    log_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_logs", "auth.log"),
        os.path.join(BASE_DIR, "sample_logs", "auth.log")
    ]
    for p in log_paths:
        if os.path.exists(p):
            try:
                with open(p, "w", encoding="utf-8") as f:
                    f.write("")
            except Exception:
                pass


import sqlite3
import os
from datetime import datetime, timedelta

FAILURE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# When running in Docker, the shared database volume is mounted at /app/database
if os.path.exists("/app/database") or os.environ.get("DOCKER_CONTAINER"):
    DATABASE = "/app/database/security.db"
else:
    DATABASE = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "security.db"))


def parse_event_timestamp(ts_str):
    """Parse either ISO timestamp or syslog timestamp into a datetime object."""
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            pass
    try:
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return dt.replace(year=datetime.now().year)
    except ValueError:
        pass
    return None


def detect_suspicious_ips():
    """
    Detect IP addresses with repeated authentication failures (brute force pattern).
    Threshold: 5 or more failed attempts within a 10-minute window.
    Supports both real-time stream telemetry and parsed log files.
    """
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cutoff_time = datetime.utcnow() - timedelta(minutes=TIME_WINDOW_MINUTES)
    cutoff_local = datetime.now() - timedelta(minutes=TIME_WINDOW_MINUTES)

    # 1. First check real-time failures within wall-clock window
    cursor.execute("""
        SELECT ip_address, COUNT(*) AS failure_count
        FROM login_events
        WHERE status = 'FAILED'
        AND (timestamp >= ? OR timestamp >= ?)
        GROUP BY ip_address
        HAVING COUNT(*) >= ?
        ORDER BY failure_count DESC
    """, (
        cutoff_time.strftime("%Y-%m-%d %H:%M:%S"),
        cutoff_local.strftime("%Y-%m-%d %H:%M:%S"),
        FAILURE_THRESHOLD
    ))
    rt_results = cursor.fetchall()
    detected_map = {row[0]: row[1] for row in rt_results}

    # 2. Also analyze all failed events using a 10-minute sliding window
    cursor.execute("""
        SELECT ip_address, timestamp
        FROM login_events
        WHERE status = 'FAILED'
        ORDER BY id ASC
    """)
    all_failed = cursor.fetchall()
    conn.close()

    # Group timestamps by IP
    from collections import defaultdict
    ip_events = defaultdict(list)
    for ip, ts_str in all_failed:
        dt = parse_event_timestamp(ts_str)
        if dt:
            ip_events[ip].append(dt)

    # Check 10-minute sliding window for each IP
    for ip, timestamps in ip_events.items():
        if len(timestamps) < FAILURE_THRESHOLD:
            continue
        timestamps.sort()
        # Slide window of size FAILURE_THRESHOLD (5)
        for i in range(len(timestamps) - FAILURE_THRESHOLD + 1):
            window_span = timestamps[i + FAILURE_THRESHOLD - 1] - timestamps[i]
            if window_span <= timedelta(minutes=TIME_WINDOW_MINUTES):
                count_in_window = sum(
                    1 for t in timestamps
                    if timestamps[i] <= t <= timestamps[i] + timedelta(minutes=TIME_WINDOW_MINUTES)
                )
                if ip not in detected_map or count_in_window > detected_map[ip]:
                    detected_map[ip] = count_in_window
                break

    # Format result as list of (ip_address, count) tuples sorted by count DESC
    suspicious_ips = sorted(detected_map.items(), key=lambda x: x[1], reverse=True)
    return suspicious_ips


if __name__ == "__main__":
    suspicious_ips = detect_suspicious_ips()

    print("Suspicious IPs:")

    for ip, count in suspicious_ips:
        print(
            f"IP: {ip} | "
            f"Failed attempts: {count}"
        )

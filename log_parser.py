"""
Root log_parser.py wrapper
Forwards calls to security-lab/log_parser.py for seamless CLI execution
from repository root.
"""
import os
import sys

LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security-lab")
if LAB_DIR not in sys.path:
    sys.path.insert(0, LAB_DIR)

from log_parser import (
    parse_log_line,
    parse_log_file,
    compute_event_hash,
    ensure_db_schema,
    insert_events
)

if __name__ == "__main__":
    import subprocess
    script_path = os.path.join(LAB_DIR, "log_parser.py")
    # Execute with same python interpreter
    result = subprocess.run([sys.executable, script_path], cwd=LAB_DIR)
    sys.exit(result.returncode)

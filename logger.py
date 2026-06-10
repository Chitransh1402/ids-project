import os
from datetime import datetime

LOG_FILE = os.environ.get("LOG_FILE", "alerts.log")


def log_attack(protocol: str, service: str, flag: str, prediction: str = "attack"):
    """Append a timestamped attack entry to the log file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = (
        f"[{timestamp}] ATTACK DETECTED | "
        f"protocol={protocol} | service={service} | flag={flag} | prediction={prediction}\n"
    )
    with open(LOG_FILE, 'a') as f:
        f.write(line)


def read_log() -> str:
    """Return full log contents, or empty string if file doesn't exist."""
    if not os.path.exists(LOG_FILE):
        return ""
    with open(LOG_FILE, 'r') as f:
        return f.read()


def clear_log():
    """Wipe the log file."""
    open(LOG_FILE, 'w').close()

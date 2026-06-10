import os
from datetime import datetime

LOG_FILE = 'alerts.log'

def log_attack(service, protocol, flag, prediction):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{timestamp}] ATTACK DETECTED | protocol={protocol} | service={service} | flag={flag} | prediction={prediction}\n"
    with open(LOG_FILE, 'a') as f:
        f.write(line)
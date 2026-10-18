import re
import pandas as pd

PATTERN = re.compile(
    r"^(?P<timestamp>\S+\s+\S+)\s+"
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<event_type>[A-Z_]+)"
    r"(?:\s+(?P<details>.*))?$"
)

def parse_line(line):
    line = line.strip()
    if not line:
        return None

    m = PATTERN.match(line)
    if not m:
        return None

    row = m.groupdict()
    details = row.get("details") or ""

    user = None
    port = None
    status = None

    user_m = re.search(r"user=([^\s]+)", details)
    port_m = re.search(r"port=(\d+)", details)
    status_m = re.search(r"status=(\d+)", details)

    if user_m:
        user = user_m.group(1)
    if port_m:
        port = int(port_m.group(1))
    if status_m:
        status = int(status_m.group(1))

    row["user"] = user
    row["port"] = port
    row["status"] = status
    row["details"] = details
    return row

def parse_log_text(text):
    rows = [parse_line(line) for line in text.splitlines()]
    rows = [r for r in rows if r]
    if not rows:
        return pd.DataFrame(columns=["timestamp","source_ip","event_type","user","port","status","details"])
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)

def parse_log_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return parse_log_text(f.read())

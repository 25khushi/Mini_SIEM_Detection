import sqlite3
import pandas as pd

DB = "data/siem.db"

def init_db():
    con = sqlite3.connect(DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS events (
            timestamp TEXT, source_ip TEXT, event_type TEXT,
            user TEXT, port INTEGER, status INTEGER, details TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            timestamp TEXT, source_ip TEXT, alert_type TEXT,
            severity TEXT, description TEXT, evidence TEXT
        )
    """)
    con.commit()
    con.close()

def save_events(df):
    if df.empty:
        return
    out = df.copy()
    out["timestamp"] = out["timestamp"].astype(str)
    con = sqlite3.connect(DB)
    out.to_sql("events", con, if_exists="append", index=False)
    con.close()

def save_alerts(df):
    if df.empty:
        return
    out = df.copy()
    out["timestamp"] = out["timestamp"].astype(str)
    con = sqlite3.connect(DB)
    out.to_sql("alerts", con, if_exists="append", index=False)
    con.close()

def load_events():
    con = sqlite3.connect(DB)
    df = pd.read_sql_query("SELECT * FROM events ORDER BY timestamp", con)
    con.close()
    return df

def load_alerts():
    con = sqlite3.connect(DB)
    df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", con)
    con.close()
    return df

def clear_db():
    con = sqlite3.connect(DB)
    con.execute("DELETE FROM events")
    con.execute("DELETE FROM alerts")
    con.commit()
    con.close()

import streamlit as st
import pandas as pd
from src.database import init_db, save_events, save_alerts, load_events, load_alerts, clear_db
from src.parser import parse_log_file, parse_log_text
from src.detector import detect_alerts

st.set_page_config(page_title="Mini SIEM", page_icon="🛡️", layout="wide")
init_db()

st.title("🛡️ Mini SIEM – Security Log Monitoring & Threat Detection")
st.caption("Educational SOC-style dashboard for authorized security monitoring.")

with st.sidebar:
    st.header("Controls")
    source = st.radio("Log source", ["Sample logs", "Upload log file", "Paste logs"])
    if st.button("Clear database", type="secondary"):
        clear_db()
        st.success("Database cleared.")
        st.rerun()

def process_logs(df):
    if df.empty:
        st.warning("No valid log events were found.")
        return
    alerts = detect_alerts(df)
    save_events(df)
    save_alerts(alerts)
    st.success(f"Processed {len(df)} events and generated {len(alerts)} alerts.")

if source == "Sample logs":
    if st.button("Load sample attack logs", type="primary"):
        with open("data/sample_logs.txt", "r", encoding="utf-8") as f:
            df = parse_log_text(f.read())
        process_logs(df)

elif source == "Upload log file":
    uploaded = st.file_uploader("Upload .txt or .log file", type=["txt", "log"])
    if uploaded and st.button("Analyze uploaded logs", type="primary"):
        text = uploaded.getvalue().decode("utf-8", errors="ignore")
        process_logs(parse_log_text(text))

else:
    text = st.text_area("Paste security logs", height=250, placeholder="2026-10-18 20:01:10 192.168.1.10 LOGIN_FAILED user=admin")
    if st.button("Analyze pasted logs", type="primary"):
        process_logs(parse_log_text(text))

events = load_events()
alerts = load_alerts()

st.divider()
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events", len(events))
c2.metric("Total Alerts", len(alerts))
c3.metric("High/Critical", int(alerts["severity"].isin(["HIGH", "CRITICAL"]).sum()) if not alerts.empty else 0)
c4.metric("Unique Source IPs", events["source_ip"].nunique() if not events.empty else 0)

if not alerts.empty:
    st.subheader("🚨 Security Alerts")
    sev = st.multiselect("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=["LOW","MEDIUM","HIGH","CRITICAL"])
    filtered = alerts[alerts["severity"].isin(sev)].copy()
    st.dataframe(filtered, use_container_width=True, hide_index=True)

    st.subheader("Alert Distribution")
    st.bar_chart(alerts["alert_type"].value_counts())

if not events.empty:
    st.subheader("📋 Security Events")
    st.dataframe(events.tail(200), use_container_width=True, hide_index=True)

    st.subheader("Events by Source IP")
    st.bar_chart(events["source_ip"].value_counts().head(10))

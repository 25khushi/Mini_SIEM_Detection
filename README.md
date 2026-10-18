# Mini SIEM – Security Log Monitoring & Threat Detection

Educational SOC-style project built with Python, Streamlit, Pandas and SQLite.

## Features
- Security log parsing
- SQLite event storage
- Brute-force detection
- Port-scan detection
- HTTP error spike detection
- Privileged login detection
- Privilege escalation alerts
- Severity classification
- Interactive Streamlit dashboard
- Upload/paste custom logs
- Sample attack dataset

## Run

```bash
python -m venv venv
```

Windows:
```bash
venv\Scripts\activate
```

Install:
```bash
pip install -r requirements.txt
```

Start:
```bash
streamlit run app.py
```

Then click **Load sample attack logs**.

## Log format

```text
YYYY-MM-DD HH:MM:SS SOURCE_IP EVENT_TYPE key=value
```

Examples:

```text
2026-10-18 20:00:01 192.168.1.10 LOGIN_FAILED user=admin
2026-10-18 20:01:00 10.0.0.25 CONNECTION_ATTEMPT port=22
2026-10-18 20:02:00 172.16.0.50 LOGIN_SUCCESS user=admin
2026-10-18 20:03:00 172.16.0.60 PRIVILEGE_ESCALATION user=guest
```

## Detection logic

- 5+ failed authentication attempts from one IP → HIGH Brute Force
- 5+ distinct connection ports from one IP → HIGH Port Scan
- 10+ HTTP 4xx/5xx events from one IP → MEDIUM HTTP Error Spike
- Admin/root login → MEDIUM Privileged Login
- Privilege escalation event → CRITICAL

Use only logs and systems you are authorized to monitor.

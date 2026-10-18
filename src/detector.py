import pandas as pd

def _alert(ts, ip, alert_type, severity, description, evidence):
    return {
        "timestamp": ts,
        "source_ip": ip,
        "alert_type": alert_type,
        "severity": severity,
        "description": description,
        "evidence": evidence,
    }

def detect_alerts(df, failed_login_threshold=5, scan_port_threshold=5, http_error_threshold=10):
    alerts = []

    if df.empty:
        return pd.DataFrame(columns=[
            "timestamp","source_ip","alert_type","severity","description","evidence"
        ])

    # 1. Brute-force detection
    failed = df[df["event_type"].isin(["LOGIN_FAILED", "AUTH_FAILED"])].copy()
    for ip, group in failed.groupby("source_ip"):
        if len(group) >= failed_login_threshold:
            alerts.append(_alert(
                group["timestamp"].max(), ip, "Brute Force", "HIGH",
                f"{len(group)} failed authentication attempts detected.",
                f"threshold={failed_login_threshold}, attempts={len(group)}"
            ))

    # 2. Port scan detection
    scans = df[df["event_type"].isin(["PORT_SCAN", "CONNECTION_ATTEMPT"])].copy()
    for ip, group in scans.groupby("source_ip"):
        ports = group["port"].dropna().nunique()
        if ports >= scan_port_threshold:
            alerts.append(_alert(
                group["timestamp"].max(), ip, "Port Scan", "HIGH",
                f"Connection attempts against {ports} distinct ports detected.",
                f"ports={sorted(group['port'].dropna().astype(int).unique().tolist())}"
            ))

    # 3. HTTP error spike
    http_errors = df[(df["event_type"] == "HTTP_ERROR") & (df["status"].fillna(0) >= 400)]
    for ip, group in http_errors.groupby("source_ip"):
        if len(group) >= http_error_threshold:
            alerts.append(_alert(
                group["timestamp"].max(), ip, "HTTP Error Spike", "MEDIUM",
                f"{len(group)} HTTP error responses detected.",
                f"threshold={http_error_threshold}"
            ))

    # 4. Suspicious admin login
    admin = df[
        (df["event_type"] == "LOGIN_SUCCESS") &
        (df["user"].fillna("").str.lower().isin(["admin", "root"]))
    ]
    for _, row in admin.iterrows():
        alerts.append(_alert(
            row["timestamp"], row["source_ip"], "Privileged Login", "MEDIUM",
            f"Privileged account login detected for user={row['user']}.",
            row["details"]
        ))

    # 5. Possible privilege escalation
    pe = df[df["event_type"].isin(["PRIVILEGE_ESCALATION", "SUDO_USED"])]
    for _, row in pe.iterrows():
        alerts.append(_alert(
            row["timestamp"], row["source_ip"], "Privilege Escalation", "CRITICAL",
            "Privilege escalation activity was reported by the log source.",
            row["details"]
        ))

    result = pd.DataFrame(alerts)
    if result.empty:
        return pd.DataFrame(columns=[
            "timestamp","source_ip","alert_type","severity","description","evidence"
        ])

    return result.sort_values("timestamp", ascending=False).reset_index(drop=True)

import time
import datetime
from backend.database import get_db, get_community_intel_for_domain
from backend.scanners.certificate import inspect_tls_certificate

def check_single_watchlist_item(item: dict) -> list[dict]:
    """
    Check a single watchlisted domain for:
    1. Certificate expiration <= 14 days
    2. Certificate replacement / serial change
    3. Community threat reports
    Returns list of newly generated alerts.
    """
    domain = item["domain"]
    user_id = item["user_id"]
    watchlist_id = item["id"]
    last_serial = item.get("last_cert_serial")

    alerts_generated = []
    now = int(time.time())

    # 1. TLS Certificate check
    cert_data = inspect_tls_certificate(f"https://{domain}")
    new_serial = None
    status = "HEALTHY"

    if cert_data.get("has_ssl") and cert_data.get("chain"):
        leaf = cert_data["chain"][0]
        new_serial = leaf.get("serial_number")
        days_left = leaf.get("days_until_expiry", 999)

        # Alert: Certificate expiring soon (<= 14 days)
        if item.get("alert_cert_expiry", 1) and days_left <= 14:
            status = "EXPIRING_SOON"
            alerts_generated.append({
                "user_id": user_id,
                "watchlist_id": watchlist_id,
                "domain": domain,
                "title": "Certificate Expiring Soon",
                "message": f"SSL/TLS certificate for '{domain}' expires in {days_left} day(s) on {leaf.get('valid_to')}.",
                "severity": "WARN"
            })

        # Alert: Certificate serial changed
        if item.get("alert_cert_changed", 1) and last_serial and last_serial != new_serial:
            alerts_generated.append({
                "user_id": user_id,
                "watchlist_id": watchlist_id,
                "domain": domain,
                "title": "Certificate Replaced / Changed",
                "message": f"A new certificate was detected for '{domain}' (Serial: {new_serial[:16]}...). Issuer: {leaf.get('issuer', {}).get('common_name', 'Unknown')}.",
                "severity": "INFO"
            })

        # Alert: CT Monitor (Unexpected certificate / wildcard logged in Certificate Transparency)
        ct_entries = cert_data.get("ct_timeline", [])
        if ct_entries and item.get("alert_ct_monitor", 1):
            latest_ct = ct_entries[0]
            if latest_ct.get("is_wildcard"):
                alerts_generated.append({
                    "user_id": user_id,
                    "watchlist_id": watchlist_id,
                    "domain": domain,
                    "title": "CT Monitor: Wildcard Certificate Logged",
                    "message": f"Certificate Transparency monitor detected a wildcard issuance for '*.{domain}' from CA '{latest_ct.get('issuer')}'.",
                    "severity": "WARN"
                })
    else:
        status = "NO_SSL"
        alerts_generated.append({
            "user_id": user_id,
            "watchlist_id": watchlist_id,
            "domain": domain,
            "title": "TLS Connection Failure",
            "message": f"Unable to establish TLS connection with '{domain}': {cert_data.get('error', 'Unknown')}",
            "severity": "CRITICAL"
        })

    # 2. Check community threat reports
    if item.get("alert_reported", 1):
        comm_intel = get_community_intel_for_domain(domain)
        if comm_intel["is_verified"]:
            status = "MALICIOUS_THREAT"
            alerts_generated.append({
                "user_id": user_id,
                "watchlist_id": watchlist_id,
                "domain": domain,
                "title": "Domain Flagged as Threat",
                "message": f"Watchlisted domain '{domain}' has been verified by the community as a malicious phishing or fraud site ({comm_intel['report_count']} reports).",
                "severity": "CRITICAL"
            })
        elif comm_intel["report_count"] > 0:
            alerts_generated.append({
                "user_id": user_id,
                "watchlist_id": watchlist_id,
                "domain": domain,
                "title": "Suspicious Community Report",
                "message": f"'{domain}' was recently reported by community users ({comm_intel['report_count']} active reports).",
                "severity": "WARN"
            })

    # Update database record
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE watchlist
        SET last_checked = ?, last_status = ?, last_cert_serial = ?
        WHERE id = ?
    """, (now, status, new_serial or last_serial, watchlist_id))

    # Insert newly created alerts
    for a in alerts_generated:
        cursor.execute("""
            INSERT INTO alerts (user_id, watchlist_id, domain, title, message, severity, is_read, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
        """, (a["user_id"], a["watchlist_id"], a["domain"], a["title"], a["message"], a["severity"], now))

    conn.commit()
    conn.close()

    return alerts_generated

def run_watchlist_check_cycle(user_id: int = None) -> dict:
    """Run check cycle across all watchlists (or for a specific user)."""
    conn = get_db()
    cursor = conn.cursor()
    if user_id:
        cursor.execute("SELECT * FROM watchlist WHERE user_id = ?", (user_id,))
    else:
        cursor.execute("SELECT * FROM watchlist")
    items = [dict(r) for r in cursor.fetchall()]
    conn.close()

    total_alerts = 0
    checked_count = 0
    for item in items:
        new_alerts = check_single_watchlist_item(item)
        total_alerts += len(new_alerts)
        checked_count += 1

    return {
        "domains_checked": checked_count,
        "new_alerts_created": total_alerts,
        "timestamp": int(time.time())
    }

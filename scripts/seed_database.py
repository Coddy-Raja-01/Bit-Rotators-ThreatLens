import sys
import time
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.database import (
    init_db, get_db, create_user,
    submit_community_report, vote_on_report, add_to_watchlist
)

def seed():
    print("Initializing SQLite database...")
    init_db()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] > 0:
        print("Database already contains data. Skipping re-seed.")
        conn.close()
        return
    conn.close()

    print("Creating demo user account...")
    try:
        user = create_user("sec_analyst", "analyst@threatlens.local", "ThreatLens2026!")
        print(f"Created demo user: {user['username']} (ID: {user['id']})")
    except Exception as e:
        print(f"User creation note: {e}")
        user = {"id": 1}

    print("Seeding community threat reports...")
    sample_reports = [
        {
            "url": "http://chase-security-verify-auth.net/login.php",
            "category": "banking",
            "description": "SMS phishing message claiming urgent card suspension. Form directs to phishing credential harvester.",
            "confirms": 5,
            "disputes": 0
        },
        {
            "url": "http://remote-google-recruitment-careers.site/apply",
            "category": "fake job offer",
            "description": "WhatsApp and Telegram contact impersonating HR director. Demanded $150 equipment background fee via crypto.",
            "confirms": 4,
            "disputes": 0
        },
        {
            "url": "http://usps-tracking-redelivery-fee.top/parcel",
            "category": "payment link",
            "description": "Fake postal delivery notice demanding $1.85 redelivery charge to steal credit card details.",
            "confirms": 6,
            "disputes": 1
        },
        {
            "url": "http://irs-tax-refund-direct-deposit.info/claim",
            "category": "university/government impersonation",
            "description": "Impersonates US Internal Revenue Service claiming recalculation refund of $1,420. Asks for SSN and bank login.",
            "confirms": 3,
            "disputes": 0
        },
        {
            "url": "http://paypa1-resolution-center.com/dispute",
            "category": "payment link",
            "description": "Classic lookalike domain using numeral '1' instead of letter 'l'. Displays stolen PayPal CSS styles.",
            "confirms": 8,
            "disputes": 0
        },
        {
            "url": "http://stanford-alumni-portal-login.space/auth",
            "category": "university/government impersonation",
            "description": "Phishing spear-mail targeted at researchers. Steals SSO credentials.",
            "confirms": 1,
            "disputes": 0
        }
    ]

    for rep in sample_reports:
        rep_id = submit_community_report(
            url=rep["url"],
            category=rep["category"],
            description=rep["description"],
            reporter_ip="198.51.100.1"
        )
        # Add confirmations to simulate community consensus
        for i in range(rep["confirms"] - 1):
            vote_on_report(rep_id, f"198.51.100.{10 + i}", "confirm")
        for i in range(rep["disputes"]):
            vote_on_report(rep_id, f"198.51.100.{50 + i}", "dispute")

    print("Seeding sample watchlist items...")
    add_to_watchlist(user["id"], "chase.com")
    add_to_watchlist(user["id"], "paypal.com")
    add_to_watchlist(user["id"], "chase-security-verify-auth.net")

    # Add an alert for the demo user
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (user_id, watchlist_id, domain, title, message, severity, is_read, created_at)
        VALUES (?, 3, 'chase-security-verify-auth.net', 'Community Threat Alert',
                'Domain on your watchlist was flagged and verified as a malicious banking phishing lure.',
                'CRITICAL', 0, ?)
    """, (user["id"], int(time.time())))
    conn.commit()
    conn.close()

    print("Database seeding completed successfully.")

if __name__ == "__main__":
    seed()

import os
import sqlite3
import json
import time
import uuid
import hashlib
from pathlib import Path
import bcrypt

DB_PATH = Path(os.getenv("THREATLENS_DB_PATH", Path(__file__).resolve().parent.parent / "threatlens.db"))

def get_db():
    """Get SQLite connection with dictionary row factory."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if they do not exist."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key_prefix TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    DROP TABLE IF EXISTS scans;

    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        domain TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        reporter_ip TEXT NOT NULL,
        confirmations INTEGER DEFAULT 1,
        disputes INTEGER DEFAULT 0,
        is_verified INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS report_votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id INTEGER NOT NULL,
        voter_ip TEXT NOT NULL,
        vote_type TEXT NOT NULL, -- 'confirm' or 'dispute'
        created_at INTEGER NOT NULL,
        UNIQUE(report_id, voter_ip),
        FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        domain TEXT NOT NULL,
        last_checked INTEGER,
        last_status TEXT DEFAULT 'PENDING',
        last_cert_serial TEXT,
        alert_cert_expiry INTEGER DEFAULT 1,
        alert_cert_changed INTEGER DEFAULT 1,
        alert_reported INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL,
        UNIQUE(user_id, domain),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        watchlist_id INTEGER,
        domain TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        severity TEXT NOT NULL, -- 'INFO', 'WARN', 'CRITICAL'
        is_read INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS assessments (
        report_id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        domain TEXT NOT NULL,
        classification TEXT NOT NULL,
        score INTEGER NOT NULL,
        report_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS chain_registry (
        on_chain_id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT NOT NULL,
        report_hash TEXT UNIQUE NOT NULL,
        domain_hash TEXT NOT NULL,
        category INTEGER NOT NULL,
        evidence_ref TEXT NOT NULL,
        reporter_address TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        block_number INTEGER NOT NULL,
        revision INTEGER DEFAULT 0,
        status TEXT DEFAULT 'Active',
        confirmations INTEGER DEFAULT 1,
        disputes INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS chain_votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        on_chain_id INTEGER NOT NULL,
        voter_address TEXT NOT NULL,
        vote_type TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        UNIQUE(on_chain_id, voter_address)
    );

    CREATE TABLE IF NOT EXISTS chain_revisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        on_chain_id INTEGER NOT NULL,
        old_hash TEXT NOT NULL,
        new_hash TEXT NOT NULL,
        note TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports(domain);
    CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_assessments_domain ON assessments(domain);
    CREATE INDEX IF NOT EXISTS idx_assessments_created ON assessments(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_chain_report_hash ON chain_registry(report_hash);
    CREATE INDEX IF NOT EXISTS idx_chain_domain_hash ON chain_registry(domain_hash);
    """)

    conn.commit()
    conn.close()

# ----------------- User & Auth Helpers -----------------

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed.encode("utf-8"))

def create_user(username: str, email: str, password: str) -> dict:
    conn = get_db()
    cursor = conn.cursor()
    pwd_hash = hash_password(password)
    now = int(time.time())
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username.strip(), email.strip().lower(), pwd_hash, now)
        )
        user_id = cursor.lastrowid
        conn.commit()
        return {"id": user_id, "username": username, "email": email}
    finally:
        conn.close()

def authenticate_user(username_or_email: str, password: str) -> dict | None:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username_or_email.strip(), username_or_email.strip().lower())
        )
        row = cursor.fetchone()
        if not row:
            return None
        if verify_password(password, row["password_hash"]):
            return {"id": row["id"], "username": row["username"], "email": row["email"]}
        return None
    finally:
        conn.close()

# ----------------- API Key Helpers -----------------

def generate_api_key(user_id: int, name: str) -> tuple[str, str]:
    """Generates a secure API key: tl_live_<random_32_chars>. Returns (raw_key, prefix)."""
    raw_token = uuid.uuid4().hex + uuid.uuid4().hex[:16]
    raw_key = f"tl_live_{raw_token}"
    prefix = raw_key[:12] + "..."
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO api_keys (user_id, key_prefix, key_hash, name, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, prefix, key_hash, name.strip(), int(time.time()))
        )
        conn.commit()
        return raw_key, prefix
    finally:
        conn.close()

def verify_api_key(raw_key: str) -> dict | None:
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT k.id, k.user_id, k.name, u.username, u.email
            FROM api_keys k
            JOIN users u ON k.user_id = u.id
            WHERE k.key_hash = ?
        """, (key_hash,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

# ----------------- Community Threat DB Helpers -----------------

def submit_community_report(url: str, category: str, description: str, reporter_ip: str) -> int:
    from urllib.parse import urlparse
    clean_url = url.strip()
    if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
        clean_url = "https://" + clean_url
    domain = (urlparse(clean_url).hostname or clean_url).lower()

    now = int(time.time())
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO reports (url, domain, category, description, reporter_ip, confirmations, disputes, is_verified, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, 0, 0, ?, ?)
        """, (clean_url, domain, category, description.strip(), reporter_ip, now, now))
        report_id = cursor.lastrowid
        # Record initial reporter vote
        cursor.execute("""
            INSERT INTO report_votes (report_id, voter_ip, vote_type, created_at)
            VALUES (?, ?, 'confirm', ?)
        """, (report_id, reporter_ip, now))
        conn.commit()
        return report_id
    finally:
        conn.close()

def vote_on_report(report_id: int, voter_ip: str, vote_type: str) -> dict:
    """Vote 'confirm' or 'dispute'. Returns updated counts and is_verified status."""
    if vote_type not in ("confirm", "dispute"):
        raise ValueError("Invalid vote_type. Must be 'confirm' or 'dispute'.")

    now = int(time.time())
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Check existing vote
        cursor.execute("SELECT vote_type FROM report_votes WHERE report_id = ? AND voter_ip = ?", (report_id, voter_ip))
        existing = cursor.fetchone()
        if existing:
            return {"error": "You have already voted on this threat report."}

        # Record vote
        cursor.execute(
            "INSERT INTO report_votes (report_id, voter_ip, vote_type, created_at) VALUES (?, ?, ?, ?)",
            (report_id, voter_ip, vote_type, now)
        )

        # Update report count
        if vote_type == "confirm":
            cursor.execute("UPDATE reports SET confirmations = confirmations + 1, updated_at = ? WHERE id = ?", (now, report_id))
        else:
            cursor.execute("UPDATE reports SET disputes = disputes + 1, updated_at = ? WHERE id = ?", (now, report_id))

        # Check if verified (net confirmations >= 3)
        cursor.execute("SELECT confirmations, disputes FROM reports WHERE id = ?", (report_id,))
        rep = cursor.fetchone()
        confirmations = rep["confirmations"]
        disputes = rep["disputes"]
        is_verified = 1 if (confirmations - disputes) >= 3 else 0

        cursor.execute("UPDATE reports SET is_verified = ? WHERE id = ?", (is_verified, report_id))
        conn.commit()

        return {
            "success": True,
            "report_id": report_id,
            "confirmations": confirmations,
            "disputes": disputes,
            "is_verified": bool(is_verified)
        }
    finally:
        conn.close()

def get_community_intel_for_domain(domain: str) -> dict:
    """Used by the scanner coordinator to factor community consensus into risk score."""
    clean_domain = domain.lower()
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT id, url, category, description, confirmations, disputes, is_verified, created_at
            FROM reports
            WHERE domain = ? OR domain = ? OR domain LIKE ?
            ORDER BY created_at DESC LIMIT 5
        """, (clean_domain, f"www.{clean_domain}", f"%{clean_domain}%"))
        rows = cursor.fetchall()
        
        report_count = len(rows)
        total_confirms = sum(r["confirmations"] for r in rows)
        total_disputes = sum(r["disputes"] for r in rows)
        any_verified = any(r["is_verified"] == 1 for r in rows)

        return {
            "report_count": report_count,
            "confirmations": total_confirms,
            "disputes": total_disputes,
            "is_verified": any_verified,
            "recent_reports": [dict(r) for r in rows]
        }
    finally:
        conn.close()

def list_community_reports(category: str = None, verified_only: bool = False, search: str = None, limit: int = 50) -> list[dict]:
    conn = get_db()
    cursor = conn.cursor()
    try:
        query = "SELECT * FROM reports WHERE 1=1"
        params = []
        if category and category != "all":
            query += " AND category = ?"
            params.append(category)
        if verified_only:
            query += " AND is_verified = 1"
        if search:
            query += " AND (domain LIKE ? OR url LIKE ? OR description LIKE ?)"
            s = f"%{search.strip()}%"
            params.extend([s, s, s])
        query += " ORDER BY (confirmations - disputes) DESC, created_at DESC LIMIT ?"
        params.append(limit)
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

# ----------------- Watchlist & Alerts Helpers -----------------

def add_to_watchlist(user_id: int, domain: str) -> dict:
    from urllib.parse import urlparse
    clean_domain = domain.strip().lower()
    if clean_domain.startswith("http://") or clean_domain.startswith("https://"):
        clean_domain = urlparse(clean_domain).hostname or clean_domain
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    conn = get_db()
    cursor = conn.cursor()
    now = int(time.time())
    try:
        cursor.execute("""
            INSERT INTO watchlist (user_id, domain, last_checked, last_status, created_at)
            VALUES (?, ?, ?, 'PENDING', ?)
        """, (user_id, clean_domain, now, now))
        wid = cursor.lastrowid
        conn.commit()
        return {"id": wid, "user_id": user_id, "domain": clean_domain, "status": "PENDING"}
    except sqlite3.IntegrityError:
        return {"error": "Domain is already on your watchlist."}
    finally:
        conn.close()

def get_user_watchlist(user_id: int) -> list[dict]:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT w.*, (SELECT COUNT(*) FROM alerts a WHERE a.watchlist_id = w.id AND a.is_read = 0) as unread_alerts
            FROM watchlist w
            WHERE w.user_id = ?
            ORDER BY w.created_at DESC
        """, (user_id,))
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

def remove_from_watchlist(user_id: int, watchlist_id: int) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM watchlist WHERE id = ? AND user_id = ?", (watchlist_id, user_id))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()

def get_user_alerts(user_id: int, unread_only: bool = False) -> list[dict]:
    conn = get_db()
    cursor = conn.cursor()
    try:
        query = "SELECT * FROM alerts WHERE user_id = ?"
        params = [user_id]
        if unread_only:
            query += " AND is_read = 0"
        query += " ORDER BY created_at DESC"
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

def mark_alerts_read(user_id: int, alert_id: int = None) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    try:
        if alert_id:
            cursor.execute("UPDATE alerts SET is_read = 1 WHERE id = ? AND user_id = ?", (alert_id, user_id))
        else:
            cursor.execute("UPDATE alerts SET is_read = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()

def get_global_stats() -> dict:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM reports")
        total_reports = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM reports WHERE is_verified = 1")
        verified_threats = cursor.fetchone()[0]

        return {
            "total_reports": total_reports,
            "verified_threats": verified_threats
        }
    finally:
        conn.close()

# ----------------- Assessment Storage Helpers -----------------

def save_assessment(report_id: str, target_url: str, domain: str, classification: str, score: int, report_dict: dict) -> None:
    """Store complete RiskAssessment as canonical JSON in SQLite with stable report_id."""
    conn = get_db()
    cursor = conn.cursor()
    now = int(time.time())
    report_json_str = json.dumps(report_dict, ensure_ascii=False)
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO assessments (report_id, target_url, domain, classification, score, report_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (report_id, target_url, domain.lower(), classification, score, report_json_str, now))
        conn.commit()
    finally:
        conn.close()

def get_assessment(report_id: str) -> dict | None:
    """Retrieve full RiskAssessment by report_id."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT report_json FROM assessments WHERE report_id = ?", (report_id,))
        row = cursor.fetchone()
        if row and row["report_json"]:
            return json.loads(row["report_json"])
        return None
    finally:
        conn.close()

def list_recent_assessments(limit: int = 20) -> list[dict]:
    """Retrieve recent scan assessments metadata."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT report_id, target_url, domain, classification, score, created_at
            FROM assessments
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

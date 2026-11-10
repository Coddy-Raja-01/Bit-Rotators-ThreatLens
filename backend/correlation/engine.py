import time
import hashlib
from collections import defaultdict
from backend.database import get_db, save_assessment
from backend.correlation.simhash import compute_simhash

def init_correlation_db():
    """Ensure correlation schema exists."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        UNIQUE(type, value)
    );

    CREATE TABLE IF NOT EXISTS report_indicators (
        report_id TEXT NOT NULL,
        indicator_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY(report_id, indicator_id),
        FOREIGN KEY(indicator_id) REFERENCES indicators(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_indicators_type_val ON indicators(type, value);
    CREATE INDEX IF NOT EXISTS idx_rep_ind_report ON report_indicators(report_id);
    CREATE INDEX IF NOT EXISTS idx_rep_ind_indicator ON report_indicators(indicator_id);
    """)
    conn.commit()
    conn.close()

def extract_indicators_from_report(report: dict) -> list[tuple[str, str]]:
    """Extract atomic indicator tuples (type, value) from a scan report."""
    indicators = set()
    target = report.get("target", {})
    hostname = target.get("hostname", "").lower().strip()
    if hostname:
        indicators.add(("domain", hostname))

    for ip in target.get("resolved_ips", []):
        if ip and ip != "blocked":
            indicators.add(("ip", ip.strip()))

    # Nameservers and DNS
    dns_records = report.get("dns_characteristics", {}).get("records", {})
    for ns in dns_records.get("NS", []):
        clean_ns = ns.rstrip(".").lower()
        if clean_ns:
            indicators.add(("nameserver", clean_ns))

    # Certificate details
    cert_data = report.get("certificate_validation", {})
    chain = cert_data.get("chain", [])
    if chain:
        leaf = chain[0]
        serial = leaf.get("serial_number")
        if serial:
            indicators.add(("cert_serial", serial))
        issuer = leaf.get("issuer", {}).get("common_name")
        if issuer:
            indicators.add(("cert_issuer", issuer))
        # Compute SHA-256 fingerprint if not present
        fp = leaf.get("modulus_sample") or serial or ""
        if fp:
            fp_sha = hashlib.sha256(fp.encode("utf-8")).hexdigest()[:16]
            indicators.add(("cert_fingerprint", fp_sha))

    # Redirect target
    final_url = target.get("final_url", "")
    norm_url = target.get("normalized_url", "")
    if final_url and final_url != norm_url:
        final_host = target.get("hostname", "")
        if final_host:
            indicators.add(("redirect_destination", final_url))

    # Content & extracted identifiers
    content = report.get("threat_analysis", {}).get("content", {})
    forms = content.get("cross_domain_forms", [])
    for f in forms:
        action_dom = f.get("action_domain")
        if action_dom:
            indicators.add(("credential_drop_host", action_dom.lower()))

    # Simhash of page content
    page_title = content.get("title", "")
    form_str = "".join([f.get("action", "") for f in forms])
    combined_sig = f"{page_title}::{form_str}"
    if len(combined_sig) > 5:
        sh = compute_simhash(combined_sig)
        indicators.add(("content_simhash", sh))

    return list(indicators)

def record_report_indicators(report_id: str, report: dict) -> None:
    """Stores extracted indicators and links them to the report_id."""
    init_correlation_db()
    tuples = extract_indicators_from_report(report)
    if not tuples:
        return

    conn = get_db()
    cursor = conn.cursor()
    now = int(time.time())
    try:
        for itype, ivalue in tuples:
            cursor.execute(
                "INSERT OR IGNORE INTO indicators (type, value) VALUES (?, ?)",
                (itype, ivalue)
            )
            cursor.execute(
                "SELECT id FROM indicators WHERE type = ? AND value = ?",
                (itype, ivalue)
            )
            row = cursor.fetchone()
            if row:
                ind_id = row["id"]
                cursor.execute(
                    "INSERT OR IGNORE INTO report_indicators (report_id, indicator_id, created_at) VALUES (?, ?, ?)",
                    (report_id, ind_id, now)
                )
        conn.commit()
    finally:
        conn.close()

def get_correlation_graph(focus_report_id: str | None = None) -> dict:
    """
    Returns graph representation {nodes: [...], edges: [...], evidence_for_each_edge: [...]}.
    Nodes represent reports and shared infrastructure indicators.
    """
    init_correlation_db()
    conn = get_db()
    cursor = conn.cursor()
    try:
        if focus_report_id:
            # Get indicators for this report
            cursor.execute("""
                SELECT i.id, i.type, i.value
                FROM indicators i
                JOIN report_indicators ri ON i.id = ri.indicator_id
                WHERE ri.report_id = ?
            """, (focus_report_id,))
            ind_rows = cursor.fetchall()
            ind_ids = [r["id"] for r in ind_rows]

            if not ind_ids:
                return {"nodes": [], "edges": [], "evidence_for_each_edge": []}

            # Get all reports sharing these indicators
            placeholders = ",".join("?" * len(ind_ids))
            cursor.execute(f"""
                SELECT ri.report_id, ri.indicator_id, i.type, i.value, a.domain, a.classification, a.score
                FROM report_indicators ri
                JOIN indicators i ON ri.indicator_id = i.id
                LEFT JOIN assessments a ON ri.report_id = a.report_id
                WHERE ri.indicator_id IN ({placeholders})
            """, ind_ids)
            links = cursor.fetchall()
        else:
            # Global correlation graph (shared indicators linked to >= 2 reports)
            cursor.execute("""
                SELECT ri.report_id, ri.indicator_id, i.type, i.value, a.domain, a.classification, a.score
                FROM report_indicators ri
                JOIN indicators i ON ri.indicator_id = i.id
                LEFT JOIN assessments a ON ri.report_id = a.report_id
                WHERE i.id IN (
                    SELECT indicator_id FROM report_indicators GROUP BY indicator_id HAVING COUNT(report_id) >= 2
                )
                LIMIT 200
            """)
            links = cursor.fetchall()

        nodes_map = {}
        edges = []
        evidence_list = []

        for row in links:
            rep_id = row["report_id"]
            ind_id = f"ind_{row['indicator_id']}"
            domain = row["domain"] or rep_id[:8]
            classification = row["classification"] or "Unknown"

            # Report node
            if rep_id not in nodes_map:
                nodes_map[rep_id] = {
                    "id": rep_id,
                    "label": domain,
                    "kind": "report",
                    "classification": classification,
                    "score": row["score"] or 0,
                    "is_focus": (rep_id == focus_report_id)
                }

            # Indicator node
            if ind_id not in nodes_map:
                nodes_map[ind_id] = {
                    "id": ind_id,
                    "label": f"{row['type']}: {row['value'][:25]}",
                    "kind": "indicator",
                    "indicator_type": row["type"],
                    "value": row["value"]
                }

            # Edge
            edge_id = f"{rep_id}->{ind_id}"
            edges.append({
                "id": edge_id,
                "source": rep_id,
                "target": ind_id,
                "relationship": f"shares_{row['type']}",
                "evidence": f"Report '{domain}' observed infrastructure indicator {row['type']}='{row['value']}'"
            })
            evidence_list.append({
                "report_id": rep_id,
                "domain": domain,
                "indicator_type": row["type"],
                "indicator_value": row["value"]
            })

        return {
            "nodes": list(nodes_map.values()),
            "edges": edges,
            "evidence_for_each_edge": evidence_list,
            "total_nodes": len(nodes_map),
            "total_edges": len(edges)
        }
    finally:
        conn.close()

def get_campaigns() -> list[dict]:
    """
    Identifies infrastructure clusters (campaigns) by finding connected components of shared indicators.
    """
    init_correlation_db()
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Find indicators shared by >= 2 reports
        cursor.execute("""
            SELECT i.id, i.type, i.value, ri.report_id, a.domain, a.classification, a.score
            FROM indicators i
            JOIN report_indicators ri ON i.id = ri.indicator_id
            LEFT JOIN assessments a ON ri.report_id = a.report_id
            WHERE i.id IN (
                SELECT indicator_id FROM report_indicators GROUP BY indicator_id HAVING COUNT(report_id) >= 2
            )
        """)
        rows = cursor.fetchall()
        if not rows:
            return []

        # Build graph for clustering
        indicator_to_reports = defaultdict(set)
        report_to_indicators = defaultdict(set)
        report_metadata = {}

        for r in rows:
            rep_id = r["report_id"]
            ind_desc = (r["type"], r["value"])
            indicator_to_reports[ind_desc].add(rep_id)
            report_to_indicators[rep_id].add(ind_desc)
            if rep_id not in report_metadata:
                report_metadata[rep_id] = {
                    "domain": r["domain"] or rep_id[:8],
                    "classification": r["classification"] or "Unknown",
                    "score": r["score"] or 0
                }

        # Connected component traversal
        visited_reports = set()
        campaigns = []
        cluster_index = 1

        for rep_id in list(report_to_indicators.keys()):
            if rep_id in visited_reports:
                continue

            # BFS / DFS
            queue = [rep_id]
            visited_reports.add(rep_id)
            cluster_reports = set()
            cluster_indicators = set()

            while queue:
                curr_rep = queue.pop(0)
                cluster_reports.add(curr_rep)
                for ind in report_to_indicators.get(curr_rep, []):
                    cluster_indicators.add(ind)
                    for linked_rep in indicator_to_reports.get(ind, []):
                        if linked_rep not in visited_reports:
                            visited_reports.add(linked_rep)
                            queue.append(linked_rep)

            if len(cluster_reports) >= 2:
                # Build summary
                shared_summary = []
                for itype, ival in list(cluster_indicators)[:3]:
                    shared_summary.append(f"{itype} '{ival}'")

                domains = [report_metadata[r]["domain"] for r in cluster_reports if r in report_metadata]
                name = f"Campaign-Cluster-0{cluster_index}: " + (domains[0].split(".")[0].upper() + " Group" if domains else "Fraud Network")

                campaigns.append({
                    "campaign_id": f"CAMP-{cluster_index:03d}",
                    "name": name,
                    "report_count": len(cluster_reports),
                    "reports": [
                        {"report_id": r, **report_metadata.get(r, {})}
                        for r in cluster_reports
                    ],
                    "shared_indicators": [
                        {"type": itype, "value": ival}
                        for itype, ival in cluster_indicators
                    ],
                    "summary": f"{len(cluster_reports)} distinct reports share underlying infrastructure: {', '.join(shared_summary)}."
                })
                cluster_index += 1

        return campaigns
    finally:
        conn.close()

def seed_demo_campaigns():
    """Seeds demo database with 2 realistic multi-domain phishing infrastructure campaigns."""
    init_correlation_db()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM report_indicators")
    count = cursor.fetchone()[0]
    conn.close()

    if count > 0:
        return # Already seeded

    # Campaign 1: FinPhish Infrastructure Cluster (3 banking lookalikes sharing IP, nameserver, cert issuer, and payment handle)
    c1_reports = [
        {
            "report_id": "demo-finphish-01",
            "url": "http://chase-security-verify-auth.net/login.php",
            "domain": "chase-security-verify-auth.net",
            "classification": "Confirmed Malicious",
            "score": 92,
            "ips": ["198.51.100.42"],
            "ns": ["ns1.bulletproof-dns.top"],
            "issuer": "Let's Encrypt Authority X3",
            "upi": "fraud-ops@okaxis",
            "simhash": "a4f21098b67d510c"
        },
        {
            "report_id": "demo-finphish-02",
            "url": "http://wellsfargo-secure-login-alert.net/auth",
            "domain": "wellsfargo-secure-login-alert.net",
            "classification": "Confirmed Malicious",
            "score": 88,
            "ips": ["198.51.100.42"],
            "ns": ["ns1.bulletproof-dns.top"],
            "issuer": "Let's Encrypt Authority X3",
            "upi": "fraud-ops@okaxis",
            "simhash": "a4f21098b67d510c"
        },
        {
            "report_id": "demo-finphish-03",
            "url": "http://secure-login-bankofamerica.top/index",
            "domain": "secure-login-bankofamerica.top",
            "classification": "Confirmed Malicious",
            "score": 90,
            "ips": ["198.51.100.42"],
            "ns": ["ns1.bulletproof-dns.top"],
            "issuer": "Let's Encrypt Authority X3",
            "upi": "fraud-ops@okaxis",
            "simhash": "a4f21098b67d510c"
        }
    ]

    # Campaign 2: Crypto Wallet Drainer Syndicate (2 domains sharing wallet and simhash)
    c2_reports = [
        {
            "report_id": "demo-crypto-01",
            "url": "http://metamask-sync-wallet-restore.io/seed.html",
            "domain": "metamask-sync-wallet-restore.io",
            "classification": "Confirmed Malicious",
            "score": 96,
            "ips": ["203.0.113.88"],
            "ns": ["ns1.offshore-cloud.cc"],
            "crypto_wallet": "0x71C67Ed4F550261cb87751B297426c71286B129b",
            "simhash": "bb09413284ff0123"
        },
        {
            "report_id": "demo-crypto-02",
            "url": "http://wallet-connect-ledger-resolve.info/connect",
            "domain": "wallet-connect-ledger-resolve.info",
            "classification": "Confirmed Malicious",
            "score": 94,
            "ips": ["203.0.113.88"],
            "ns": ["ns1.offshore-cloud.cc"],
            "crypto_wallet": "0x71C67Ed4F550261cb87751B297426c71286B129b",
            "simhash": "bb09413284ff0123"
        }
    ]

    for item in c1_reports + c2_reports:
        rep_dict = {
            "success": True,
            "report_id": item["report_id"],
            "target": {
                "input_url": item["url"],
                "normalized_url": item["url"],
                "final_url": item["url"],
                "hostname": item["domain"],
                "resolved_ips": item["ips"]
            },
            "scan_timestamp": int(time.time()) - 3600,
            "unified_scoring": {
                "classification": item["classification"],
                "score": item["score"],
                "verdict": item["classification"],
                "verdict_color": "red",
                "summary": f"Known hostile campaign node in {item['domain']}.",
                "disclaimer": "Absence of known threats is not proof of safety.",
                "threat_indicators": [f"Shared hostile infrastructure ({item['ips'][0]})"],
                "findings": [
                    {
                        "id": "CAMP-01",
                        "module": "correlation",
                        "title": "Campaign Infrastructure Overlap",
                        "severity": "critical",
                        "technical_evidence": {"ip": item["ips"][0], "domain": item["domain"]},
                        "impact": "Shared bulletproof hosting and command-and-control nexus.",
                        "source": "ThreatLens Correlation Engine",
                        "confidence": 1.0,
                        "recommendation": "Block IP and domain ranges immediately."
                    }
                ],
                "evidence_breakdown": []
            },
            "threat_analysis": {
                "content": {"title": item["domain"], "cross_domain_forms": []},
                "redirects": {"hops": []},
                "external_intel": {"intel_flagged": True}
            },
            "web_security": {},
            "certificate_validation": {
                "has_ssl": True,
                "chain": [{"issuer": {"common_name": item.get("issuer", "Unknown CA")}, "serial_number": "123456789"}]
            },
            "community_intelligence": {"report_count": 3, "is_verified": True}
        }
        # Save assessment to SQLite
        save_assessment(
            item["report_id"],
            item["url"],
            item["domain"],
            item["classification"],
            item["score"],
            rep_dict
        )
        # Record indicators directly
        tuples = [
            ("domain", item["domain"]),
            ("ip", item["ips"][0]),
            ("nameserver", item["ns"][0]),
            ("content_simhash", item["simhash"])
        ]
        if "issuer" in item:
            tuples.append(("cert_issuer", item["issuer"]))
        if "upi" in item:
            tuples.append(("payment_upi", item["upi"]))
        if "crypto_wallet" in item:
            tuples.append(("crypto_wallet", item["crypto_wallet"]))

        conn = get_db()
        cursor = conn.cursor()
        now = int(time.time())
        for itype, ival in tuples:
            cursor.execute("INSERT OR IGNORE INTO indicators (type, value) VALUES (?, ?)", (itype, ival))
            cursor.execute("SELECT id FROM indicators WHERE type = ? AND value = ?", (itype, ival))
            row = cursor.fetchone()
            if row:
                cursor.execute(
                    "INSERT OR IGNORE INTO report_indicators (report_id, indicator_id, created_at) VALUES (?, ?, ?)",
                    (item["report_id"], row["id"], now)
                )
        conn.commit()
        conn.close()


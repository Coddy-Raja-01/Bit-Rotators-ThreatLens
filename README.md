# ThreatLens

A phishing and malicious website detection platform that combines threat analysis, web security headers, certificate validation, and community intelligence into a unified report.

---

## 1. Problem Statement

The internet relies on trust in Certificate Authorities and secure transport. However, having a green padlock or active HTTPS does not prove a site is legitimate:
- Phishing sites routinely obtain free TLS certificates.
- Historical incidents—such as the eMudhra TLS certificate key-generation flaw—demonstrate that implementation bugs and weak random number generators can undermine encryption.
- Existing tools are fragmented: an analyst must check one tool for DNS and typosquatting, another for HTTP security headers, a third for Certificate Transparency logs, and another for threat feeds.

ThreatLens brings all four pillars into one unified assessment and produces a plain-English score and evidence breakdown.

---

## 2. Key Features

1. **Unified Risk Score (0–100)**: Combines all four modules into a single score with a "Why this verdict" list explaining each piece of evidence and its score contribution.
2. **Lookalike Domain & Homoglyph Detector**: Detects typosquatting, character omissions, visual substitutions (e.g. `rn` vs `m`, `0` vs `o`), and Unicode/Cyrillic homoglyphs against an offline database of 120+ top banks, payment processors, universities, and government portals. Displays side-by-side comparisons with differing characters highlighted.
3. **Certificate Transparency (CT) Timeline**: Queries public CT logs for historical issuances and flags sudden spikes, wildcard certificates, and unexpected Certificate Authorities.
4. **Weak Key & Algorithm Check**: Flags RSA keys smaller than 2048 bits, deprecated MD5/SHA-1 signatures, and warns about known shared-prime / weak-RNG failure patterns (eMudhra incident).
5. **Redirect Chain Tracer**: Safely traces HTTP redirect hops, detects protocol downgrades (HTTPS -> HTTP), tracks cross-domain hops, and provides a 3D spatial path view.
6. **Static Content Inspector**: Parses server-side HTML (without running untrusted JavaScript) to detect forms posting passwords to external domains, hidden 0-pixel iframes, obfuscated JavaScript, and social engineering text.
7. **Security Header & TLS Grade**: Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and cookie flags to assign an A–F grade.
8. **Technology Fingerprinting**: Identifies server and CMS versions and cross-references them against a local list of known unpatched vulnerabilities (CVEs).
9. **Collaborative Threat Intelligence**: Community members report suspicious URLs. Reports with net 3 confirmations become verified, which automatically elevates the domain's risk score.
10. **Public Threat Database**: Searchable and filterable registry of reported and verified phishing domains with direct "Scan" capabilities.
11. **Watchlist & Automated Alerts**: Monitors user-specified domains on a schedule and notifies when certificates change, expire soon (<=14 days), or get reported.
12. **Downloadable Reports**: Export any scan result as an executive PDF document (via ReportLab) or raw JSON.
13. **Functional 3D Views**: Interactive 3D Trust Chain Explorer and 3D Redirect Path visualizer using locally bundled Three.js with flat utilitarian styling and 2D accessible table fallbacks.
14. **Public REST API**: Programmatic endpoints with API key authentication, rate limits, and interactive Swagger documentation.

---

## 3. Project Structure

```
threatlens/
├── README.md                  # Complete documentation and run instructions
├── .env.example               # Environment variables template
├── requirements.txt           # Python dependency requirements
├── threatlens.db              # SQLite database (auto-created on startup)
├── backend/
│   ├── main.py                # FastAPI application and REST endpoints
│   ├── database.py            # SQLite schema, queries, and auth helpers
│   ├── scheduler.py           # Watchlist monitoring and alert engine
│   ├── scanners/
│   │   ├── ssrf.py            # Strict SSRF guard and DNS resolver
│   │   ├── lookalike.py       # Typosquatting and homoglyph detector
│   │   ├── redirects.py       # Safe hop tracer with protocol checks
│   │   ├── content.py         # Static HTML/DOM/script analyzer
│   │   ├── security_headers.py# Header evaluator and A-F grading
│   │   ├── certificate.py     # TLS chain, weak key, and CT log inspector
│   │   ├── fingerprint.py     # Server version & CVE matcher
│   │   ├── intel.py           # External threat feed aggregator
│   │   ├── scoring.py         # Unified 0-100 risk score engine
│   │   └── coordinator.py     # Multi-module scan coordinator
│   ├── ml/
│   │   ├── features.py        # 15 lexical and structural URL features
│   │   ├── classifier.py      # Random Forest classifier + rule fallback
│   │   ├── train.py           # Model training pipeline
│   │   └── model.joblib       # SHA-256 verified scikit-learn model
│   ├── reports/
│   │   └── exporter.py        # ReportLab PDF report generator
│   └── tests/
│       └── test_all.py        # Complete automated test suite
├── frontend/
│   ├── index.html             # Human-crafted HTML shell
│   ├── css/
│   │   └── style.css          # Utilitarian CSS (0 gradients, 5 colors)
│   └── js/
│       ├── app.js             # Client controller, navigation, routing
│       ├── vendor/
│       │   ├── three.min.js   # Three.js bundled locally (no CDN)
│       └── modules/
│           ├── scanner.js     # Scan tab renderer and evidence tables
│           ├── trust_chain_3d.js # 3D Trust Chain Explorer + 2D fallback
│           ├── redirect_3d.js # 3D Redirect Path view + 2D fallback
│           ├── database_view.js # Threat database and voting interface
│           └── watchlist.js   # Watchlist management and alert list
├── data/
│   ├── brands.json            # 50+ canonical brand identities
│   ├── sample_urls.csv        # 475 labeled URLs for ML training
│   └── vulnerable_versions.json # Known vulnerable server & CMS versions
└── scripts/
    ├── run_server.py          # One-command startup script
    ├── seed_database.py       # Seeds demo user and sample reports
    └── train_model.py         # Retrains the Random Forest classifier
```

---

## 4. Setup & Run Instructions

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- A modern web browser (Chrome, Firefox, Edge, Safari)
- Docker Desktop (for the app-integrated local Ethereum chain)

### Step 1: Install Dependencies
Open your terminal inside the `threatlens/` folder:

**Windows (PowerShell or Command Prompt):**
```powershell
python -m pip install -r requirements.txt
```

**macOS / Linux:**
```bash
python3 -m pip install -r requirements.txt
```

### Step 2: Initialize Database and Seed Sample Data (Optional)
To pre-populate demo community threat reports, a sample watchlist, and a demo security analyst account:
```bash
python scripts/seed_database.py
```
*Demo credentials: Username: `sec_analyst` | Password: `ThreatLens2026!`*

### Step 3: Run the Application
Start the app and local Anvil chain. The app deploys `ThreatRegistry.sol` automatically:
```bash
docker compose up --build
```
To run only the HTTP app without the chain, use `python scripts/run_server.py`; the integrity endpoints require a configured and deployed RPC contract.

Open your browser to:
- **Web Application**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive REST API Docs (Swagger)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 5. Environment Configuration (.env)

ThreatLens runs fully offline using local heuristics, trained models, and local datasets. To enable optional live external intelligence feeds:

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Add your API keys:
   - `VIRUSTOTAL_API_KEY`: API key from VirusTotal.
   - `SAFE_BROWSING_API_KEY`: API key for Google Safe Browsing v4.
   - `PORT`: Change port if `8000` is in use.

If left empty, ThreatLens degrades gracefully and performs all inspections with internal detectors.
OpenPhish refreshes a disk cache at most hourly and falls back to the bundled CSV feed. Set `PHISHTANK_API_KEY` to enable the optional PhishTank check.

---

## 6. Training the ML Model

The Random Forest model is trained on structural and lexical features from `data/sample_urls.csv`. To retrain the model on new data:

1. Add your new labeled samples to `data/sample_urls.csv` (format: `url,label` where 1 = phishing, 0 = benign).
2. Run the training script:
   ```bash
   python scripts/train_model.py
   ```
3. The script evaluates training accuracy and writes `backend/ml/model.joblib` with a `.sha256` sidecar. If the artifact is missing or fails integrity validation, ThreatLens falls back to its built-in rule-based heuristic engine.

Redirect-chain and HTML-content inspection are skipped unless the scanner form's authorization checkbox is selected. DNS, lexical analysis, threat intelligence, HTTP headers, and TLS inspection continue without that consent.

---

## 7. How the Risk Score is Calculated

The Unified Risk Score is a cumulative 0–100 index used alongside a five-class evidence assessment: **Low Risk**, **Suspicious**, **High Risk**, **Confirmed Malicious**, or **Inconclusive**. A low score does not establish that a website is legitimate.

### Point Contributions:
| Module | Detection Signal | Penalty |
|---|---|---|
| **Threat Analysis** | Machine Learning Phishing Probability >= 85% | +35 pts |
| **Threat Analysis** | Lookalike Brand Impersonation / Homoglyph | +35 pts |
| **Threat Analysis** | Password form submitting to foreign domain | +30 pts |
| **Threat Analysis** | Insecure Protocol Downgrade (HTTPS -> HTTP) | +20 pts |
| **Threat Analysis** | Obfuscated Client JavaScript (`eval`, hex array) | +15 pts |
| **Threat Analysis** | Title Brand Mismatch (Title claims brand, domain differs) | +25 pts |
| **Web Security** | Missing critical security headers (Grade 'F') | +20 pts |
| **Web Security** | Outdated software with critical unpatched CVEs | +25 pts |
| **Certificate** | No TLS / Plaintext HTTP | +30 pts |
| **Certificate** | Weak RSA Key (< 2048-bit) or SHA-1 signature | +20 pts |
| **Certificate** | Self-signed or expired certificate | +25 pts |
| **Community Intel** | Verified by community consensus (>= 3 confirms) | +30 pts |
| **External Feeds** | Flagged by VirusTotal / Safe Browsing / URLhaus | +30 pts |

Every point added is listed explicitly in the report's **"Why this verdict"** evidence table.

---

## 8. REST API Reference

All requests accept and return JSON. Authenticated endpoints accept `Authorization: Bearer <token_or_api_key>` or session cookies.

### 1. Run a Scan
- **Endpoint**: `POST /api/scan`
- **Body**: `{"url": "https://example.com", "authorized_target": false}`
- Complete reports, including coverage and limitations, are retained by report ID and are available from `GET /api/scan/{report_id}`.
- **Example**:
  ```bash
  curl -X POST "http://127.0.0.1:8000/api/scan" \
       -H "Content-Type: application/json" \
       -d '{"url": "http://rnicrosoft-login.net"}'
  ```

### 2. Export Scan Report
- **PDF Export**: `POST /api/scan/export/pdf` with the scan report as the JSON body.
- **JSON Export**: The web UI downloads the scan report locally.

### 3. Lookalike Domain Check
- **Endpoint**: `GET /api/lookalike?domain=paypa1.com`
- **Returns**: Suspicious domain, matched brand, canonical domain, diff segments, and similarity score.

### 4. Community Threat Reports
- **List Reports**: `GET /api/reports?category=banking&verified_only=true`
- **Submit Report**: `POST /api/reports`
  ```bash
  curl -X POST "http://127.0.0.1:8000/api/reports" \
       -H "Content-Type: application/json" \
       -d '{"url": "http://bad-link.com", "category": "banking", "description": "SMS phishing card lockout"}'
  ```
- **Vote on Report**: `POST /api/reports/{id}/vote` with `{"vote_type": "confirm"}` or `{"vote_type": "dispute"}`

### 5. Watchlist & Alerts
- **List Watched Domains**: `GET /api/watchlist`
- **Add Domain**: `POST /api/watchlist` with `{"domain": "mybank.com"}`
- **Delete Domain**: `DELETE /api/watchlist/{id}`
- **Trigger Immediate Re-audit**: `POST /api/watchlist/check-now`
- **Get Alerts**: `GET /api/alerts?unread_only=true`

---

## 9. Platform Security Controls

To ensure ThreatLens itself is not exploited when analyzing untrusted websites:
1. **SSRF Guard**:
   - The scanner refuses connections to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `0.0.0.0`, `::1`, and cloud metadata hosts (`metadata.google.internal`).
   - DNS resolution is performed first, and every returned IP is checked against disallow-lists before connection and after every authorized HTTP redirect. Target requests are pinned to the validated IP.
2. **No Untrusted JavaScript Execution**:
   - Webpages are fetched as static text payloads with strict timeouts (5 seconds) and strict size limits (2MB).
   - Scripts are never executed or rendered in a browser engine. Static regex and DOM analysis inspects code structure safely.
3. **Application Hardening**:
   - Parameterized SQL queries prevent SQL injection.
   - Passwords hashed with `bcrypt` (12 rounds).
   - API keys are hashed with SHA-256 before storage.
   - HTTP response headers on the platform: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and strict `Referrer-Policy`.

---

## 10. Automated Testing

Run the automated test suite and Python compile check:

```powershell
.\scripts\check_all.ps1
```

Alternatively:
```powershell
python -m unittest backend.tests.test_all
python -m compileall -q backend scripts
```

The suite covers SSRF protection, pinned connections, scan authorization, lookalike detection, ML features, risk scoring, and community consensus.

## 11. Browser Extension

Load the `extension/` folder as an unpacked Manifest V3 extension in Chrome or Edge. Start ThreatLens locally, enter the URL in the popup, and inspect the evidence summary. The extension sends requests only to `127.0.0.1:8000`; redirect and page-content inspection remain opt-in.

## 12. Docker

Run the app and its local Anvil chain; the app waits for the chain, deploys `ThreatRegistry.sol` if needed, and starts only after the deployed bytecode is verified:
```powershell
docker compose up --build
```

The app is available at `http://127.0.0.1:8000`; Anvil JSON-RPC is available at `http://127.0.0.1:8545`. Check the live contract with `GET /api/chain/status`. Contract transactions are recorded on the local chain; this local chain is ephemeral unless you configure persistent Anvil state.

To compile the Solidity source and regenerate its ABI/bytecode artifact:
```powershell
python scripts/compile_contract.py
```

To deploy manually to another unlocked development RPC:
```powershell
$env:WEB3_PROVIDER_URI="http://127.0.0.1:8545"
python scripts/deploy_contract.py
```
For a public network, set `THREAT_REGISTRY_ADDRESS` and `WEB3_RELAYER_PRIVATE_KEY` securely outside source control. The contract stores hashes and opaque report IDs only; it does not establish whether the report is true.

## 13. Troubleshooting

- **Port 8000 already in use**:
  Set the `PORT` environment variable before starting:
  ```powershell
  $env:PORT="8080"; python scripts/run_server.py
  ```
- **Domain shows "No active DNS resolution"**:
  If a phishing domain was suspended by its registrar, ThreatLens gracefully marks the host as offline while still evaluating its lexical markers, lookalike properties, and community reports.
- **3D Canvas displays fallback table**:
  If your browser or virtual environment does not support WebGL, ThreatLens automatically renders the structured 2D comparison table.

---

## 14. Limitations & Future Improvements

- **Limitations**:
  - Static analysis cannot detect payloads rendered solely through client-side React/Vue SPAs that make dynamic authenticated AJAX calls after execution.
  - RDAP and live threat-feed checks depend on external service availability; offline bundled threat indicators remain available when those services cannot be reached.
- **Future Improvements**:
  - Sandboxed headless browser screenshot generator running inside an isolated container with no LAN access.
  - Automated BGP prefix hijacking and DNS route leak detection.
  - Passive DNS historical query integration.

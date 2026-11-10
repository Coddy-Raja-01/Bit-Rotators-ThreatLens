import os
import time
from pathlib import Path
from fastapi import FastAPI, Request, Response, HTTPException, Depends, Header, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from backend.database import (
    init_db, get_db, create_user, authenticate_user, generate_api_key,
    verify_api_key,
    submit_community_report, vote_on_report, list_community_reports,
    get_community_intel_for_domain, add_to_watchlist, get_user_watchlist,
    remove_from_watchlist, get_user_alerts, mark_alerts_read, get_global_stats,
    save_assessment, get_assessment, list_recent_assessments
)
from backend.scanners.coordinator import execute_full_scan
from backend.scanners.lookalike import check_lookalike, generate_lookalike_monitoring
from backend.scanners.intel import get_intelligence_source_status
from backend.reports.exporter import generate_pdf_report
from backend.scheduler import run_watchlist_check_cycle
from backend.ai.explainer import generate_ai_explanation
from backend.ai.provider import get_ai_mode_status
from backend.ai.scam_analyzer import analyze_scam_message, decode_qr_code_from_bytes
from backend.correlation.engine import get_correlation_graph, get_campaigns, seed_demo_campaigns
from backend.web3_service import (
    RegistryUnavailable,
    get_registry_status,
    submit_report_commitment,
    verify_report_integrity,
    list_chain_registry,
    get_chain_report_details,
)

# Initialize database on module load
init_db()
seed_demo_campaigns()

def rate_limit_key(request: Request) -> str:
    """Rate limit key based on API Key if present, otherwise client IP."""
    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        token = auth[7:].strip()
        if token.startswith("tl_live_"):
            return f"key:{token[:16]}"
    return get_remote_address(request)

limiter = Limiter(key_func=rate_limit_key, default_limits=["120/minute"])

app = FastAPI(
    title="ThreatLens API",
    description="Unified Phishing and Malicious Website Detection Platform",
    version="1.0.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

def registry_unavailable_handler(request: Request, exc: RegistryUnavailable):
    return JSONResponse(status_code=503, content={"detail": str(exc)})

app.add_exception_handler(RegistryUnavailable, registry_unavailable_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers middleware on the platform itself
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ----------------- Auth Dependency -----------------

def get_current_user_optional(request: Request, authorization: str = Header(None)):
    """Authenticate via Authorization: Bearer <key_or_token> or Cookie."""
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    elif "tl_session" in request.cookies:
        token = request.cookies["tl_session"]

    if not token:
        return None

    # Check if API key
    if token.startswith("tl_live_"):
        key_data = verify_api_key(token)
        if key_data:
            return {"id": key_data["user_id"], "username": key_data["username"], "email": key_data["email"]}

    # Check simple session format (user_id:username:hash or integer id)
    try:
        if ":" in token:
            parts = token.split(":")
            user_id = int(parts[0])
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return dict(row)
        else:
            user_id = int(token)
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return dict(row)
    except Exception:
        pass

    return None

def get_current_user_required(user = Depends(get_current_user_optional)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required. Please log in or provide an API key.")
    return user

# ----------------- Pydantic Models -----------------

class ScanRequest(BaseModel):
    url: str
    authorized_target: bool = False

class ReportRequest(BaseModel):
    url: str
    category: str
    description: str

class VoteRequest(BaseModel):
    vote_type: str  # 'confirm' or 'dispute'

class WatchlistRequest(BaseModel):
    domain: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class ApiKeyRequest(BaseModel):
    name: str

class ScamAnalysisRequest(BaseModel):
    text: str
    include_ai_explanation: bool = True

class ExplainRequest(BaseModel):
    report_id: str | None = None
    report: dict | None = None


# ----------------- Scan Endpoints -----------------

@app.post("/api/scan")
@limiter.limit("45/minute")
def run_scan(req: ScanRequest, request: Request):
    """Run full unified threat scan on a target URL."""
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    report = execute_full_scan(
        url,
        db_community_getter=get_community_intel_for_domain,
        authorized_target=req.authorized_target
    )
    
    if not report.get("success"):
        return JSONResponse(status_code=400, content=report)

    return report


@app.get("/api/intel/sources")
def get_intel_sources():
    """Return configured intelligence sources and local feed freshness."""
    return {"sources": get_intelligence_source_status()}


@app.get("/api/scan/{report_id}")
def get_persisted_scan(report_id: str):
    """Retrieve persistent threat assessment report by report_id."""
    report = get_assessment(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Threat assessment report not found")
    return report

@app.get("/api/scans/recent")
def get_recent_scans():
    """Retrieve index of recent threat assessments."""
    return list_recent_assessments(limit=25)

@app.post("/api/scan/export/pdf")
def download_scan_pdf(report: dict):
    """Download a client-supplied scan report as an executive PDF document."""
    pdf_bytes = generate_pdf_report(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=threatlens-report.pdf"}
    )

@app.get("/api/lookalike")
def test_lookalike(domain: str = Query(..., description="Domain or URL to inspect for brand impersonation")):
    """Standalone lookalike domain and typosquatting inspection endpoint."""
    return check_lookalike(domain)

@app.get("/api/lookalike/monitor")
def monitor_brand_lookalikes(domain: str = Query(..., description="Brand domain to generate homoglyphs and typosquat variants")):
    """Generate typosquat and confusable lookalike monitoring variants with live DNS status."""
    return generate_lookalike_monitoring(domain)

# ----------------- AI Layer Endpoints -----------------

@app.get("/api/ai/status")
def ai_status():
    return get_ai_mode_status()


@app.post("/api/ai/explain")
def explain_report(req: ExplainRequest):
    """Generate evidence-grounded AI explanation citing specific Finding IDs."""
    report_data = req.report
    if not report_data and req.report_id:
        report_data = get_assessment(req.report_id)

    if not report_data:
        raise HTTPException(status_code=400, detail="Must provide either report_id or report object.")

    return generate_ai_explanation(report_data)

@app.post("/api/ai/analyze-scam")
@limiter.limit("60/minute")
def analyze_scam(req: ScamAnalysisRequest, request: Request):
    """
    Analyze message, email, or notification text for social engineering,
    urgency tactics, payment handles (UPI, crypto, bank accounts), and deceptive links.
    """
    res = analyze_scam_message(req.text)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])

    # Optionally enrich with LLM explanation
    if req.include_ai_explanation and not res.get("injection_attempt_detected"):
        summary_query = f"{res['classification']} scam: " + ", ".join(res.get("verified_fraud_evidence", []) + res.get("suspicious_language_signals", []))
        rag_snippets = query_knowledge(summary_query, top_k=2)
        res["rag_guidance"] = rag_snippets

    return res

class ImageScanRequest(BaseModel):
    image_base64: str
    authorized_target: bool = False

@app.post("/api/ai/scan-image")
def scan_image_qr(req: ImageScanRequest):
    """Analyze base64-encoded screenshot/image, decode QR code to URL, and run threat assessment safely."""
    import base64
    raw_b64 = req.image_base64
    if "," in raw_b64:
        raw_b64 = raw_b64.split(",", 1)[1]

    try:
        image_bytes = base64.b64decode(raw_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 image payload: {e}")

    decoded_url = decode_qr_code_from_bytes(image_bytes)
    if not decoded_url:
        return {
            "has_qr_code": False,
            "message": "No decodable QR code detected in uploaded image.",
            "url": None,
            "report": None
        }

    # Safe analysis of extracted URL
    report = execute_full_scan(
        decoded_url,
        db_community_getter=get_community_intel_for_domain,
        authorized_target=req.authorized_target
    )
    return {
        "has_qr_code": True,
        "url": decoded_url,
        "message": f"Successfully extracted QR destination: {decoded_url}",
        "report": report
    }

# ----------------- Correlation & Campaigns Endpoints -----------------

@app.get("/api/correlation/{report_id}")
def get_report_correlation(report_id: str):
    """Retrieve infrastructure correlation sub-graph for a specific report."""
    return get_correlation_graph(focus_report_id=report_id)

@app.get("/api/correlation")
def get_global_correlation():
    """Retrieve global infrastructure correlation graph."""
    return get_correlation_graph(focus_report_id=None)

@app.get("/api/campaigns")
def list_campaigns():
    """Retrieve clustered fraud campaigns sharing infrastructure."""
    return get_campaigns()

@app.post("/api/chain/commit/{report_id}")
def commit_report_integrity(report_id: str):
    """Record a local integrity commitment for a persisted assessment."""
    report = get_assessment(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Threat assessment report not found")
    return submit_report_commitment(report)

@app.get("/api/chain/status")
def chain_status():
    """Report the live RPC and deployed ThreatRegistry contract status."""
    return get_registry_status()

@app.post("/api/chain/verify/{report_id}")
def verify_report_commitment(report_id: str, simulated_tampering: bool = Query(False)):
    """Verify a local report commitment, optionally demonstrating tamper detection."""
    report = get_assessment(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Threat assessment report not found")
    return verify_report_integrity(report, simulated_tampering=simulated_tampering)

@app.get("/api/chain/registry")
def get_integrity_registry(limit: int = Query(50, ge=1, le=100)):
    """List local integrity ledger entries."""
    return list_chain_registry(limit)

@app.get("/api/chain/registry/{on_chain_id}")
def get_integrity_record(on_chain_id: int):
    """Get local integrity record details and revision history."""
    record = get_chain_report_details(on_chain_id)
    if not record:
        raise HTTPException(status_code=404, detail="Integrity record not found")
    return record




# ----------------- Community Threat DB Endpoints -----------------

@app.get("/api/reports")
def get_reports(
    category: str = Query(None),
    verified_only: bool = Query(False),
    search: str = Query(None),
    limit: int = Query(50, ge=1, le=100)
):
    """List, search, and filter community threat reports."""
    return list_community_reports(category, verified_only, search, limit)

@app.post("/api/reports")
def submit_report(req: ReportRequest, request: Request):
    """Submit a suspicious URL to the public threat database."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    report_id = submit_community_report(
        url=req.url,
        category=req.category,
        description=req.description,
        reporter_ip=client_ip
    )
    return {"success": True, "report_id": report_id, "message": "Threat report submitted successfully."}

@app.post("/api/reports/{report_id}/vote")
def vote_report(report_id: int, req: VoteRequest, request: Request):
    """Confirm or dispute a community threat report."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    res = vote_on_report(report_id, client_ip, req.vote_type)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    return res

# ----------------- Watchlist & Alerts Endpoints -----------------

@app.get("/api/watchlist")
def list_watchlist(user = Depends(get_current_user_required)):
    """Retrieve watchlisted domains for the authenticated user."""
    return get_user_watchlist(user["id"])

@app.post("/api/watchlist")
def add_watchlist(req: WatchlistRequest, user = Depends(get_current_user_required)):
    """Add a domain to the user's automated monitor watchlist."""
    res = add_to_watchlist(user["id"], req.domain)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    # Run immediate initial check
    run_watchlist_check_cycle(user["id"])
    return res

@app.delete("/api/watchlist/{watchlist_id}")
def delete_watchlist(watchlist_id: int, user = Depends(get_current_user_required)):
    """Remove a domain from watchlist."""
    success = remove_from_watchlist(user["id"], watchlist_id)
    if not success:
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    return {"success": True}

@app.post("/api/watchlist/check-now")
def trigger_watchlist_check(user = Depends(get_current_user_required)):
    """Trigger an immediate re-audit of all watchlisted domains."""
    return run_watchlist_check_cycle(user["id"])

@app.get("/api/alerts")
def list_alerts(unread_only: bool = Query(False), user = Depends(get_current_user_required)):
    """Get security alerts for user's watched domains."""
    return get_user_alerts(user["id"], unread_only)

@app.post("/api/alerts/read")
def read_alerts(alert_id: int = Query(None), user = Depends(get_current_user_required)):
    """Mark alerts as read."""
    mark_alerts_read(user["id"], alert_id)
    return {"success": True}

# ----------------- Auth & Keys Endpoints -----------------

@app.post("/api/auth/register")
def register(req: RegisterRequest, response: Response):
    """Create new account and set session cookie."""
    try:
        user = create_user(req.username, req.email, req.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Username or email already in use.")
    
    session_token = f"{user['id']}:{user['username']}"
    response.set_cookie(key="tl_session", value=session_token, httponly=True, samesite="lax")
    return {"success": True, "user": user, "token": session_token}

@app.post("/api/auth/login")
def login(req: LoginRequest, response: Response):
    """Authenticate and obtain session token."""
    user = authenticate_user(req.username_or_email, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username/email or password.")
    
    session_token = f"{user['id']}:{user['username']}"
    response.set_cookie(key="tl_session", value=session_token, httponly=True, samesite="lax")
    return {"success": True, "user": user, "token": session_token}

@app.post("/api/auth/logout")
def logout(response: Response):
    """Clear session cookie."""
    response.delete_cookie("tl_session")
    return {"success": True}

@app.get("/api/auth/me")
def get_me(user = Depends(get_current_user_optional)):
    """Current authenticated user profile or null."""
    return {"user": user}

@app.get("/api/keys")
def list_keys(user = Depends(get_current_user_required)):
    """List active API keys."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, key_prefix, name, created_at FROM api_keys WHERE user_id = ?", (user["id"],))
    keys = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return keys

@app.post("/api/keys")
def create_key(req: ApiKeyRequest, user = Depends(get_current_user_required)):
    """Generate a new API key."""
    raw_key, prefix = generate_api_key(user["id"], req.name)
    return {
        "api_key": raw_key,
        "key_prefix": prefix,
        "name": req.name,
        "message": "Store this API key safely; it will not be shown again in full."
    }

@app.get("/api/stats")
def get_stats():
    """Platform statistics counter."""
    return get_global_stats()

# ----------------- Static Frontend Mounting -----------------

frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/{full_path:path}")
    def serve_frontend(full_path: str):
        # Serve index.html for root or SPA routing
        if not full_path or full_path == "":
            index_path = frontend_dir / "index.html"
            if index_path.exists():
                return FileResponse(index_path)
        
        # Check if requested file directly exists in frontend
        target_file = frontend_dir / full_path
        if target_file.is_file():
            return FileResponse(target_file)
            
        # Fallback to index.html for client-side navigation
        index_path = frontend_dir / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
            
        return HTMLResponse("<h1>ThreatLens Backend Running</h1><p>Frontend loading...</p>")

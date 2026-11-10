# ThreatLens

## 1. Project name and one-line description

ThreatLens investigates suspicious URLs and presents evidence from domain, web-security, TLS, and threat-intelligence checks.

## 2. Problem

HTTPS and a valid certificate do not establish that a website is legitimate. Investigation signals are spread across DNS, certificate data, security headers, threat feeds, and community reports. ThreatLens puts the available findings and their limitations into one report.

## 3. Solution

ThreatLens accepts a URL and returns an evidence-led assessment. Depending on availability and authorization, checks include URL and lookalike analysis, DNS and reputation signals, TLS details, HTTP security headers, threat-intelligence matches, and static page or redirect inspection. The app also includes community reports, watchlists, PDF export, and a REST API.

The optional EVM registry stores report commitments (hashes), not raw URLs or report contents. A commitment can help check whether a report changed; it does not prove that the report's claims are true. The included Docker demo uses a local Anvil chain. A public-chain deployment is not configured by default.

## 4. Demo links and screenshot

- **Local application:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/) after completing the setup below.
- **Local API documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
- **Public demo:** Not deployed at the time this README was written.
- **Screenshot:** No application screenshot is committed in this repository yet.

Do not treat the local URL as a public demo link. Add a real, accessible deployment URL and a current screenshot here after deployment.

## 5. Tech stack

- Python, FastAPI, and Uvicorn for the API and locally served app.
- Vanilla HTML, CSS, and JavaScript for the frontend; Three.js is bundled locally for the 3D views.
- SQLite for local and single-instance persistent storage.
- scikit-learn for the URL classifier, with heuristic fallback.
- `cryptography`, `requests`, Beautiful Soup, and ReportLab for inspection and report generation.
- Solidity `ThreatRegistry`, web3.py, and Foundry Anvil for optional EVM report commitments.
- Docker Compose for the local app-plus-chain demo; Render and Vercel configuration is included for a split deployment.

The complete Python dependency list is in [requirements.txt](./requirements.txt). The frontend build has no third-party npm dependencies.

## 6. Architecture

```text
Browser
  ├─ Vercel static frontend (or FastAPI-served frontend locally)
  └─ HTTPS API requests
       └─ Render FastAPI service
            ├─ scanners and optional intelligence/AI providers
            ├─ SQLite database on a Render persistent disk
            └─ optional EVM JSON-RPC provider → ThreatRegistry contract
```

In the split deployment, Vercel builds the static files and embeds `THREATLENS_API_BASE_URL`. The browser calls the Render API directly, so the Render service must allow the exact Vercel origin in `CORS_ALLOWED_ORIGINS`. Browser session cookies require credentialed requests. The Render Blueprint sets `SESSION_COOKIE_SAMESITE=none` for the default cross-site domains and marks the cookie Secure; browsers that block third-party cookies may still prevent sign-in. Prefer Vercel and Render custom domains under the same registrable domain, then use `SESSION_COOKIE_SAMESITE=lax`.

The Render configuration uses SQLite and a persistent disk, which requires a paid Render plan. SQLite on one persistent disk is a single-instance setup; it is not configured for horizontally scaled web instances.

## 7. Setup and run

### Local Python app

Requirements: Python 3.10+ and a modern browser.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python scripts/run_server.py
```

Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/). The app runs without external API keys; optional providers may be unconfigured or unavailable. To use the local EVM registry as well, run the Docker Compose setup instead.

### Local app and Anvil chain

Requirements: Docker Desktop with its engine running.

```powershell
docker compose up --build
```

The Compose setup starts Anvil and the app. On chain ID `31337`, the app startup script deploys the contract when deployment metadata is absent. This is a local development chain, not a public network; its chain state is temporary. Stop the services with `Ctrl+C`, or run `docker compose down`.

### Deploy the API to Render

1. Push this repository to a Git provider connected to Render.
2. Create a Render Blueprint from the repository and review [render.yaml](./render.yaml). The included SQLite persistent disk requires a paid plan and incurs hosting cost.
3. Set `CORS_ALLOWED_ORIGINS` to the planned Vercel origin (scheme and hostname, no path); update it to the exact origin after the frontend is deployed.
4. Deploy and wait for `https://<your-render-service>/healthz` to return `{"status":"ok"}`.
5. Add optional API keys in the Render environment settings, not in source control.

Render's `SESSION_SECRET` is generated by the Blueprint. The SQLite database is stored at `/data/threatlens.db`.

### Deploy the frontend to Vercel

1. Import the same repository into Vercel and use the repository root as the project root.
2. Set the build command to `npm run build` and the output directory to `dist`.
3. Set `THREATLENS_API_BASE_URL` to the Render API origin, for example `https://your-service.onrender.com` (no trailing path or slash).
4. Deploy, then set the exact resulting Vercel origin in the Render `CORS_ALLOWED_ORIGINS` environment variable and redeploy/restart the API. Cross-origin browser requests will fail until this origin is allowed.
5. Open the Vercel URL and test sign-in, a scan, PDF export, and `GET /healthz` on the API.

The Vercel build fails if `THREATLENS_API_BASE_URL` is missing or is not HTTPS. This prevents a successful-looking frontend deployment that still points its API requests at Vercel itself.

### Verification

Run the backend tests and compile check from the repository root:

```powershell
python -m unittest backend.tests.test_all
python -m compileall -q backend scripts
```

The repository also includes `scripts/check_all.ps1` for the project's combined checks. A successful local test run does not replace testing the actual Render/Vercel configuration, secrets, CORS origin, persistent disk, or any external provider credentials.

## 8. Disclosures

### Configuration and API keys

`.env.example` lists the runtime settings and optional provider keys used by the code. Copy it to `.env` for local work; never commit `.env` or real credentials. On Render, Vercel, or another host, set variables in that provider's environment settings.

Threat-intelligence API keys are optional: `URLHAUS_API_KEY`, `PHISHTANK_API_KEY`, `SAFE_BROWSING_API_KEY`, and `VIRUSTOTAL_API_KEY`. OpenPhish is configured through `OPENPHISH_FEED_URL` and can use a cached feed. AI provider keys are optional and are only used when `USE_EXTERNAL_AI=true`. Blank keys mean those external providers are not configured; they do not imply a clean result.

The Web3 integration is also optional. A hosted registry needs a reachable `WEB3_PROVIDER_URI`, deployed `THREAT_REGISTRY_ADDRESS`, and a funded/authorized transaction signer (`WEB3_RELAYER_PRIVATE_KEY` or an unlocked RPC account). Keep signing keys in the hosting provider's secret store. Never use Anvil's published test accounts or keys for real funds. Without a configured chain and contract, registry functions remain unavailable.

### Safety and limitations

- Redirect and page-content checks require the user to confirm authorization. Retrieved scripts are not executed.
- A low score or an absence of findings is not proof that a site is safe.
- External feeds and provider APIs can be unavailable, stale, rate-limited, or subject to their own terms and limits.
- AI output is an optional explanation layer, not a substitute for evidence or analyst review.
- TLS results are limited by the certificate chain and revocation data actually available to the scanner. A certificate alone does not establish site legitimacy.
- The local Anvil chain demonstrates contract interaction but does not provide public-network decentralization or durable public consensus.

### Libraries, assets, and AI assistance

The project uses the libraries listed in [requirements.txt](./requirements.txt), plus locally bundled Three.js in `frontend/js/vendor/`. The Solidity contract and application UI are part of this repository. No public production deployment or third-party UI template is claimed here.

GitHub Copilot was used as AI coding assistance during development. Generated code and documentation should be reviewed and tested by the project maintainers. Threat intelligence, model behavior, and contract behavior should be evaluated before production use.

## 9. Track

**HackMatrix — cybersecurity-focused phishing and malicious-site investigation.** The project also demonstrates optional local AI explanations and EVM report-integrity commitments; these are supporting capabilities, not claims of a production-grade autonomous security service or a public decentralized deployment.

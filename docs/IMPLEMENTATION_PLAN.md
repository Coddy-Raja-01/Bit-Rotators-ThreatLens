# ThreatLens implementation plan

The existing FastAPI, SQLite, scanner, ML, community, watchlist, PDF, and Three.js paths stay in place. This plan only fills gaps against the hackathon statement.

## Already in the tree

- SSRF guard with obfuscated-IP parsing and a DNS-pin adapter (`backend/scanners/ssrf.py`)
- Lookalike, redirects, static content, headers, TLS/CT, fingerprint, intel, scoring (`backend/scanners/*`)
- `Finding` and `RiskAssessment` models (`backend/models/evidence.py`)
- Five-class scoring with a mandatory disclaimer (`backend/scanners/scoring.py`)
- Assessment JSON stored by `report_id` (`assessments` table)
- Joblib load plus SHA-256 check (`backend/ml/classifier.py`)
- Bundled feed `data/threat_feed_sample.csv` and `data/compromised_cas.json`
- slowapi limits, auth, API keys, watchlist CT alert hook

## Phase 1 — close the evidence loop

- Feed URL-normalisation, DNS, and RDAP findings into the coordinator and the scorer.
- Keep the legacy report shape (`unified_scoring`, module blocks) so the current UI and tests keep working.
- Persist the full report, including coverage and limitations.

## Phase 2 — depth that was only partial

- PhishTank provider (optional key, timeout, cache, offline rows).
- OpenPhish community feed cached on disk and refreshed on a timer, with the CSV as fallback.
- Consent flag: multi-hop redirects and HTML body inspection run only when the user ticks authorisation. DNS, lexical, intel, and TLS still run.
- Train script writes `model.joblib` and a `.sha256` sidecar (no new pickle writes).
- Make the DNS-pin adapter actually connect to the validated IP for the duration of the request.

## Phase 3 — evidence-grounded AI

- `backend/ai/`: redaction, injection filter, pluggable provider, template fallback, TF-IDF snippets from `data/knowledge/`, scam-message analyser.
- Every rendered claim must cite a finding id. Classification stays deterministic.
- Screenshot/QR path degrades cleanly when `pyzbar` or Tesseract is absent.

## Phase 4 — correlation

- Store indicators per report and link shared values into campaign graphs.
- `GET /api/correlation/{report_id}` and `GET /api/campaigns`.
- Seed four related demo reports that share a nameserver, address, and UPI id.

## Phase 5 — Web3 integrity, not truth

- `contracts/ThreatRegistry.sol` plus Hardhat tests.
- Canonical JSON, keccak256, relayer or MetaMask calldata.
- If the chain is down, a local integrity ledger still lets verify and “simulate tampering” run. The UI says the chain records history, not truth.
- No raw URLs or message text go on chain.

## Phase 6 — console UX

- Design tokens, five-step stepper, SSE investigation timeline, tabbed report, scam view, force graph, registry, dashboard, demo mode.
- Existing 3D modules stay mounted from the report view.
- Words “Safe” and “Verified safe” are not used for a verdict.

## Phase 7 — only the extension

- Manifest V3 popup that calls `/api/scan` and warns before treating a page as trustworthy. It never says a site is safe.

## Phase 8 — proof and runbooks

- Unit tests for SSRF bypasses, injection, evidence validation, hashing, scam language, and the five-class engine.
- Docs, Dockerfile, compose file for the app plus a local chain, and `scripts/check_all.ps1`.

## Explicit non-goals

- No exploit payloads, no active intrusion, no malware execution, no foundation-model training, no seed-phrase collection.

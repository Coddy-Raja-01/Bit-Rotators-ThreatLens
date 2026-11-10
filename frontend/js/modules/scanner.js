import { renderTrustChain3D } from "./trust_chain_3d.js";
import { renderRedirectPath3D } from "./redirect_3d.js";
import { renderIntelSourceStatus } from "./intel_status.js";
import { loadAiModeStatus, renderAiModeStatus } from "./ai_status.js";

export function renderScanReport(containerEl, report) {
  if (!containerEl || !report) return;

  const scoring = report.unified_scoring || {};
  const target = report.target || {};
  const threat = report.threat_analysis || {};
  const security = report.web_security || {};
  const cert = report.certificate_validation || {};
  const community = report.community_intelligence || {};
  const dns = report.dns_characteristics || {};
  const rdap = report.rdap_registration || {};
  const coverage = scoring.coverage || {};

  let bannerClass = "banner-green";
  let badgeClass = "badge-green";
  if (scoring.verdict_color === "red") {
    bannerClass = "banner-red";
    badgeClass = "badge-red";
  } else if (scoring.verdict_color === "amber-red" || scoring.verdict_color === "amber") {
    bannerClass = "banner-amber";
    badgeClass = "badge-amber";
  }

  containerEl.innerHTML = `
    <!-- Top Metadata Bar -->
    <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
      <div>
        <h1 style="margin-bottom:2px;">Scan Report: <span class="font-mono" style="font-size:20px;">${escapeHtml(target.hostname || target.input_url)}</span></h1>
        <p style="color:#666; font-size:12px;">
          Scanned at ${new Date(report.scan_timestamp * 1000).toUTCString()} • Report ${escapeHtml(report.report_id || "")} is stored • Latency: ${report.elapsed_ms || 0}ms
        </p>
      </div>
      <div style="display:flex; gap:8px;">
        <button type="button" class="btn-secondary" id="btn-export-pdf" style="display:inline-flex; align-items:center; gap:4px;">
          Download PDF
        </button>
        <button type="button" class="btn-secondary" id="btn-export-json" style="display:inline-flex; align-items:center; gap:4px;">
          Export JSON
        </button>
        <button type="button" class="btn-secondary" id="btn-integrity-commit">Commit to ThreatRegistry</button>
      </div>
    </div>

    <!-- Unified Risk Score Banner -->
    <div class="score-banner ${bannerClass}">
      <div class="score-number-box">
        <span class="score-value">${scoring.score ?? 0}</span>
        <span class="score-denom">/ 100</span>
        <span class="badge ${badgeClass}" style="margin-left:8px; font-size:13px; padding:4px 9px;">${scoring.verdict || "UNKNOWN"}</span>
      </div>
      <div class="score-details">
        <h2>Unified Assessment Verdict</h2>
        <p>${escapeHtml(scoring.summary || "")}</p>
      </div>
    </div>

    <!-- Tab Navigation -->
    <div class="tab-navigation">
      <button class="tab-btn active" data-tab="tab-summary">Summary & Verdict Evidence (${scoring.evidence_count || 0})</button>
      <button class="tab-btn" data-tab="tab-threat">Threat Analysis & Lookalikes</button>
      <button class="tab-btn" data-tab="tab-security">Web Security & Headers (Grade: ${security.headers_grade || "N/A"})</button>
      <button class="tab-btn" data-tab="tab-certificate">Certificate & Trust 3D</button>
      <button class="tab-btn" data-tab="tab-community">Community Intelligence (${community.report_count || 0})</button>
    </div>

    <!-- Tab 1: Summary -->
    <div class="tab-content" id="tab-summary">
      <div class="box">
        <div class="box-title">Why this verdict: evidence breakdown</div>
        <p style="font-size:13px; color:#555; margin-bottom:10px;">
          The Unified Risk Score blends threat analysis, web security headers, certificate validation, and community reporting.
          Each detected indicator contributes specific penalty points toward the final score:
        </p>
        <table class="data-table">
          <thead>
            <tr>
              <th style="width:130px;">Module</th>
              <th style="width:70px;">Impact</th>
              <th>Observed Evidence & Signal</th>
              <th style="width:90px;">Severity</th>
            </tr>
          </thead>
          <tbody>
            ${(scoring.evidence_breakdown || []).map(ev => {
              let sevBadge = "badge-neutral";
              if (ev.severity === "CRITICAL") sevBadge = "badge-red";
              if (ev.severity === "HIGH") sevBadge = "badge-red";
              if (ev.severity === "MEDIUM") sevBadge = "badge-amber";
              if (ev.severity === "SAFE") sevBadge = "badge-green";
              return `
                <tr>
                  <td>
                    <strong>${escapeHtml(ev.module || "")}</strong><br/>
                    <span style="font-size:11px; color:#666;">${escapeHtml(ev.category || "")}</span>
                  </td>
                  <td class="font-mono"><strong>${ev.points}</strong></td>
                  <td>${escapeHtml(ev.evidence || "")}</td>
                  <td><span class="badge ${sevBadge}">${ev.severity || "INFO"}</span></td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>
      </div>

      <div class="box">
        <div class="box-title">Target Network Summary</div>
        <table class="data-table">
          <tbody>
            <tr>
              <td style="width:180px;"><strong>Input URL</strong></td>
              <td class="font-mono">${escapeHtml(target.input_url || "")}</td>
            </tr>
            <tr>
              <td><strong>Normalized Canonical URL</strong></td>
              <td class="font-mono">${escapeHtml(target.normalized_url || "")}</td>
            </tr>
            <tr>
              <td><strong>Final Landing URL</strong></td>
              <td class="font-mono">${escapeHtml(target.final_url || "")}</td>
            </tr>
            <tr>
              <td><strong>Resolved Public IP(s)</strong></td>
              <td class="font-mono">${(target.resolved_ips || []).join(", ") || "No active DNS resolution"}</td>
            </tr>
            <tr>
              <td><strong>DNS Nameservers</strong></td>
              <td class="font-mono">${escapeHtml((dns.records?.NS || []).join(", ") || "Not available")}</td>
            </tr>
            <tr>
              <td><strong>Domain Registration</strong></td>
              <td>${escapeHtml(rdap.registration_date ? `${rdap.registration_date} (${rdap.age_days} days old)` : "RDAP data not available")}</td>
            </tr>
            <tr>
              <td><strong>Redirect / Content Consent</strong></td>
              <td>${target.authorized_target ? "Authorized" : "Not authorized; checks skipped"}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="box">
        <div class="box-title">Evidence Coverage</div>
        <p style="font-size:12px; color:#555;">
          ${coverage.executed_checks || 0} completed, ${coverage.skipped_checks || 0} skipped, ${coverage.failed_checks || 0} failed out of ${coverage.total_checks || 0} checks.
        </p>
        <table class="data-table">
          <tbody>
            ${(coverage.checks || []).map(check => `
              <tr>
                <td><strong>${escapeHtml(check.name || "")}</strong></td>
                <td>${escapeHtml(check.status || "")}</td>
                <td>${escapeHtml(check.details || "")}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>

      <div class="box">
        <div class="box-title">Atomic Findings</div>
        <table class="data-table">
          <thead>
            <tr><th>Finding ID</th><th>Severity</th><th>Finding</th><th>Source</th></tr>
          </thead>
          <tbody>
            ${(scoring.findings || []).map(finding => `
              <tr>
                <td class="font-mono">${escapeHtml(finding.id || "")}</td>
                <td>${escapeHtml(finding.severity || "")}</td>
                <td>${escapeHtml(finding.title || "")}</td>
                <td>${escapeHtml(finding.source || "")}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
      ${renderIntelSourceStatus(threat.external_intel?.sources || [])}
      ${renderAiModeStatus()}
      <div class="box">
        <div class="box-title">Report Integrity</div>
        <p style="font-size:12px; color:#555;">
          The deployed ThreatRegistry records report hashes and revision history. A chain commitment does not validate whether a report's claims are true.
        </p>
        <button type="button" class="btn-secondary" id="btn-integrity-verify">Verify commitment</button>
        <button type="button" class="btn-secondary" id="btn-integrity-tamper">Simulate tampering</button>
        <pre id="integrity-status" style="white-space:pre-wrap; font-size:12px;"></pre>
      </div>
    </div>

    <!-- Tab 2: Threat Analysis -->
    <div class="tab-content" id="tab-threat" style="display:none;">
      <!-- Lookalike Domain Section -->
      <div class="box">
        <div class="box-title">Lookalike Domain & Brand Impersonation Detector</div>
        ${renderLookalikeCard(threat.lookalike)}
      </div>

      <!-- ML Feature Inspector -->
      <div class="box">
        <div class="box-title">Machine Learning Classifier & Lexical Features</div>
        <p style="font-size:13px; color:#555; margin-bottom:10px;">
          Trained on structural URL markers, character entropy, keyword density, and token depth:
        </p>
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px;">
          <div style="font-size:13px;">Phishing Likelihood:</div>
          <div style="flex:1; max-width:240px; height:14px; background:#e0e0dc; border-radius:2px; overflow:hidden;">
            <div style="height:100%; width:${Math.round((threat.ml_probability || 0)*100)}%; background:${(threat.ml_probability || 0) > 0.5 ? '#b02a2a' : '#277438'};"></div>
          </div>
          <div class="font-mono"><strong>${Math.round((threat.ml_probability || 0)*100)}%</strong> (${threat.ml_engine || 'heuristics'})</div>
        </div>

        <table class="data-table">
          <thead>
            <tr>
              <th>Feature Name</th>
              <th>Value</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Domain Character Entropy</td>
              <td class="font-mono">${threat.ml_features?.domain_entropy ?? "N/A"}</td>
              <td>Shannon entropy measuring randomness / machine generation. Normal domains typically score under 3.8.</td>
            </tr>
            <tr>
              <td>Suspicious TLD Flag</td>
              <td class="font-mono">${threat.ml_features?.is_suspicious_tld ? "YES (+25)" : "NO"}</td>
              <td>Evaluates against high-abuse TLDs (.xyz, .top, .buzz, .club, .pw, .vip).</td>
            </tr>
            <tr>
              <td>Sensitive Keywords in URL</td>
              <td class="font-mono">${threat.ml_features?.sensitive_word_hits?.join(", ") || "None"}</td>
              <td>Presence of target brand or credential keywords (login, verify, banking, wallet).</td>
            </tr>
            <tr>
              <td>Subdomain Depth</td>
              <td class="font-mono">${threat.ml_features?.subdomain_depth ?? 0} levels</td>
              <td>Deep subdomains frequently used to obscure malicious hostnames.</td>
            </tr>
            <tr>
              <td>Hyphen Count</td>
              <td class="font-mono">${threat.ml_features?.num_hyphens ?? 0}</td>
              <td>Multiple hyphens often indicate brand combination squatting.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Static Content Inspector -->
      <div class="box">
        <div class="box-title">Static Page Content Analysis</div>
        ${renderContentInspectorCard(threat.content)}
      </div>

      <!-- 3D Redirect Chain -->
      <div class="box">
        <div class="box-title">Redirect Chain Tracer (3D View)</div>
        <p style="font-size:13px; color:#555; margin-bottom:10px;">
          Traces safe hop-by-hop redirects with server-side SSRF validation on every destination:
        </p>
        <div id="redirect-3d-mount"></div>
      </div>
    </div>

    <!-- Tab 3: Web Security -->
    <div class="tab-content" id="tab-security" style="display:none;">
      <div class="box">
        <div class="box-title">HTTP Response Security Headers Grade</div>
        <div style="display:flex; align-items:center; gap:20px; margin-bottom:14px;">
          <div style="font-size:48px; font-family:var(--font-serif); font-weight:bold; color:var(--primary-blue); border:2px solid var(--primary-blue); width:70px; height:70px; display:flex; align-items:center; justify-content:center; border-radius:2px;">
            ${security.headers_grade || "C"}
          </div>
          <div>
            <div style="font-size:16px; font-weight:bold;">Overall Grade: ${security.headers_grade} (${security.headers_score ?? 0} / 100 points)</div>
            <p style="font-size:13px; color:#555;">Evaluated against modern OWASP and CA/Browser Forum defensive baselines.</p>
          </div>
        </div>

        <table class="data-table">
          <thead>
            <tr>
              <th>Security Header</th>
              <th>Status</th>
              <th>Observed Setting / Recommendation</th>
            </tr>
          </thead>
          <tbody>
            ${renderSecurityHeaderRows(security)}
          </tbody>
        </table>
      </div>

      <!-- Tech Fingerprint & Vulnerable Software -->
      <div class="box">
        <div class="box-title">Technology Fingerprint & Vulnerability Correlator</div>
        ${renderTechFingerprintCard(security.fingerprint)}
      </div>
    </div>

    <!-- Tab 4: Certificate & Trust -->
    <div class="tab-content" id="tab-certificate" style="display:none;">
      <!-- 3D Trust Chain -->
      <div class="box">
        <div class="box-title">Presented Certificate (Interactive)</div>
        <p style="font-size:13px; color:#555; margin-bottom:10px;">
          Inspect the certificate presented by the host. Intermediate and root certificates are not inferred when the server does not provide them.
        </p>
        <p style="font-size:13px; color:#555; margin-bottom:10px;">
          Chain validation: ${escapeHtml(cert.chain_validation || "Not verified")}. ${escapeHtml(cert.chain_validation_details || "")}
          Revocation status: ${escapeHtml(cert.revocation?.status || "Not verified")}.
        </p>
        <div id="trust-chain-3d-mount"></div>
      </div>

      <!-- Weak Key Analysis -->
      <div class="box">
        <div class="box-title">Weak Key & Cryptographic Algorithm Check</div>
        ${renderWeakKeyCard(cert.weak_key_analysis, cert.chain)}
      </div>

      <!-- CT Timeline -->
      <div class="box">
        <div class="box-title">Certificate Transparency (CT) Issuance Timeline</div>
        <p style="font-size:13px; color:#555; margin-bottom:10px;">
          Historical certificate log entries from public Certificate Transparency append-only logs:
        </p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Logged Date</th>
              <th>Domain / SAN</th>
              <th>Issuing Authority</th>
              <th>Certificate Type</th>
            </tr>
          </thead>
          <tbody>
            ${(cert.ct_timeline || []).map(entry => `
              <tr>
                <td class="font-mono">${escapeHtml(entry.date || "N/A")}</td>
                <td class="font-mono">${escapeHtml(entry.domain || "")}</td>
                <td>${escapeHtml(entry.issuer || "Unknown CA")}</td>
                <td><span class="badge ${entry.is_wildcard ? 'badge-amber' : 'badge-neutral'}">${entry.flag || 'Normal'}</span></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Tab 5: Community -->
    <div class="tab-content" id="tab-community" style="display:none;">
      <div class="box">
        <div class="box-title">Collaborative Threat Intelligence & Verification</div>
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-bottom:14px;">
          <div>
            <div style="font-size:15px; font-weight:bold;">
              Consensus Status: 
              <span class="badge ${community.is_verified ? 'badge-red' : (community.report_count > 0 ? 'badge-amber' : 'badge-green')}">
                ${community.is_verified ? 'VERIFIED MALICIOUS' : (community.report_count > 0 ? 'PENDING COMMUNITY CONSENSUS' : 'NO ACTIVE COMPLAINTS')}
              </span>
            </div>
            <p style="font-size:13px; color:#555; margin-top:2px;">
              ${community.report_count || 0} user report(s) on file • ${community.confirmations || 0} confirmations • ${community.disputes || 0} disputes
            </p>
          </div>
          <div>
            <button class="btn-primary" id="btn-report-this-site" data-url="${escapeHtml(target.input_url || '')}">
              Report This URL to Database
            </button>
          </div>
        </div>

        ${renderCommunityReportsList(community.recent_reports)}
      </div>
    </div>
  `;

  // Attach Tab switching logic
  const tabBtns = containerEl.querySelectorAll(".tab-btn");
  const tabContents = containerEl.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(tc => tc.style.display = "none");

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetEl = containerEl.querySelector(`#${targetId}`);
      if (targetEl) {
        targetEl.style.display = "block";

        // Render 3D views when their tab is displayed
        if (targetId === "tab-certificate") {
          const mount = targetEl.querySelector("#trust-chain-3d-mount");
          if (mount && !mount.hasChildNodes()) {
            renderTrustChain3D(mount, cert.chain || []);
          }
        } else if (targetId === "tab-threat") {
          const mount = targetEl.querySelector("#redirect-3d-mount");
          if (mount && !mount.hasChildNodes()) {
            renderRedirectPath3D(mount, threat.redirects || {});
          }
        }
      }
    });
  });

  // Attach report button listener
  const reportBtn = containerEl.querySelector("#btn-report-this-site");
  if (reportBtn) {
    reportBtn.addEventListener("click", () => {
      window.location.hash = `#report?url=${encodeURIComponent(reportBtn.getAttribute("data-url"))}`;
    });
  }

  const jsonExportBtn = containerEl.querySelector("#btn-export-json");
  jsonExportBtn?.addEventListener("click", () => {
    const reportBlob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    downloadBlob(reportBlob, "threatlens-report.json");
  });

  const integrityStatus = containerEl.querySelector("#integrity-status");
  loadAiModeStatus(containerEl);

  const commitBtn = containerEl.querySelector("#btn-integrity-commit");
  commitBtn?.addEventListener("click", async () => {
    commitBtn.disabled = true;
    try {
      const response = await fetch(`/api/chain/commit/${encodeURIComponent(report.report_id)}`, {
        method: "POST"
      });
      const receipt = await response.json();
      if (!response.ok) throw new Error(receipt.detail || "Could not record report integrity.");
      integrityStatus.textContent = `Recorded in ${receipt.network}: ${receipt.report_hash}\n${receipt.integrity_scope}`;
    } catch (error) {
      integrityStatus.textContent = error.message;
    } finally {
      commitBtn.disabled = false;
    }
  });

  const verifyIntegrity = async (simulatedTampering) => {
    integrityStatus.textContent = "Verifying report integrity...";
    try {
      const response = await fetch(
        `/api/chain/verify/${encodeURIComponent(report.report_id)}?simulated_tampering=${simulatedTampering}`,
        { method: "POST" }
      );
      const verification = await response.json();
      if (!response.ok) throw new Error(verification.detail || "Could not verify report integrity.");
      integrityStatus.textContent = `${verification.message}\n${verification.integrity_scope || ""}`;
    } catch (error) {
      integrityStatus.textContent = error.message;
    }
  };
  containerEl.querySelector("#btn-integrity-verify")
    ?.addEventListener("click", () => verifyIntegrity(false));
  containerEl.querySelector("#btn-integrity-tamper")
    ?.addEventListener("click", () => verifyIntegrity(true));

  const pdfExportBtn = containerEl.querySelector("#btn-export-pdf");
  pdfExportBtn?.addEventListener("click", async () => {
    pdfExportBtn.disabled = true;
    try {
      const response = await fetch("/api/scan/export/pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report)
      });
      if (!response.ok) {
        throw new Error(`PDF export failed (${response.status}): ${await response.text()}`);
      }
      downloadBlob(await response.blob(), "threatlens-report.pdf");
    } catch (error) {
      window.alert(error.message);
    } finally {
      pdfExportBtn.disabled = false;
    }
  });
}

// Helper Cards

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderLookalikeCard(lookalike) {
  if (!lookalike) return "<p style='color:#666;'>No lookalike analysis available.</p>";

  if (lookalike.is_legitimate_brand) {
    return `
      <div style="background:#f2f8f3; border:1px solid #b5dab9; padding:12px; border-radius:2px;">
        <strong style="color:#277438;">Official Domain Verified:</strong>
        This domain is the authentic canonical site of <strong>${escapeHtml(lookalike.matched_brand)}</strong> (${escapeHtml(lookalike.canonical_domain)}).
      </div>
    `;
  }

  if (lookalike.is_lookalike) {
    const susHtml = (lookalike.diff_suspicious || []).map(seg => {
      return seg.type === "diff" || seg.type === "insert" 
        ? `<span class="char-diff">${escapeHtml(seg.text)}</span>` 
        : `<span class="char-match">${escapeHtml(seg.text)}</span>`;
    }).join("");

    const canHtml = (lookalike.diff_canonical || []).map(seg => {
      return seg.type === "diff" || seg.type === "delete"
        ? `<span class="char-diff">${escapeHtml(seg.text)}</span>`
        : `<span class="char-match">${escapeHtml(seg.text)}</span>`;
    }).join("");

    return `
      <div style="background:#fdf2f2; border:1px solid #e5b0b0; padding:12px; border-radius:2px; margin-bottom:12px;">
        <strong style="color:#b02a2a;">IMPERSONATION DETECTED:</strong>
        ${escapeHtml(lookalike.technique || "Deceptive brand squatting")}
        <p style="font-size:13px; color:#555; margin-top:4px;">
          This domain is mimicking the official service of <strong>${escapeHtml(lookalike.matched_brand)}</strong> (${lookalike.category || "FinTech / Web"}).
        </p>
      </div>

      <div class="diff-container">
        <div class="diff-box">
          <div class="diff-box-title">Suspicious Input Domain</div>
          <div class="diff-display">${susHtml || lookalike.suspicious_domain}</div>
        </div>
        <div class="diff-box">
          <div class="diff-box-title">Genuine Brand Domain (${escapeHtml(lookalike.matched_brand)})</div>
          <div class="diff-display">${canHtml || lookalike.canonical_domain}</div>
        </div>
      </div>

      <p style="font-size:12px; color:#666; margin-top:6px;">
        Differing characters are highlighted in red and underlined.
      </p>
    `;
  }

  return `
    <p style="font-size:13px; color:#555;">
      No direct brand lookalike, homoglyph substitution, or brand keyword squatting detected against monitored entities.
    </p>
  `;
}

function renderContentInspectorCard(content) {
  if (!content || !content.fetched) {
    return `<p style="color:#666; font-size:13px;">${escapeHtml(content?.error || "Page content not reachable for static analysis.")}</p>`;
  }

  return `
    <table class="data-table">
      <tbody>
        <tr>
          <td style="width:200px;"><strong>Webpage HTML Title</strong></td>
          <td>${escapeHtml(content.title || "No title declared")}</td>
        </tr>
        <tr>
          <td><strong>Cross-Domain Forms</strong></td>
          <td>
            ${content.cross_domain_forms?.length > 0 
              ? `<span class="badge badge-red">${content.cross_domain_forms.length} Foreign Target(s)</span> Form targets: ${content.cross_domain_forms.map(f => escapeHtml(f.action_domain)).join(", ")}`
              : `<span class="badge badge-green">PASS</span> All forms submit internally`}
          </td>
        </tr>
        <tr>
          <td><strong>Hidden / 0-Pixel Iframes</strong></td>
          <td>
            ${content.hidden_iframes?.length > 0
              ? `<span class="badge badge-red">FLAGGED</span> ${content.hidden_iframes.length} invisible iframe(s) detected`
              : `<span class="badge badge-green">NONE</span>`}
          </td>
        </tr>
        <tr>
          <td><strong>Obfuscated JS Code</strong></td>
          <td>
            ${content.obfuscated_scripts?.length > 0
              ? `<span class="badge badge-amber">DETECTED</span> ${content.obfuscated_scripts.map(s => escapeHtml(s.pattern)).join(", ")}`
              : `<span class="badge badge-green">CLEAN</span> No eval/unescape/hex signatures`}
          </td>
        </tr>
        <tr>
          <td><strong>Social Engineering Patterns</strong></td>
          <td>
            ${content.scam_indicators?.length > 0
              ? `<span class="badge badge-red">LURES DETECTED</span> ${content.scam_indicators.join(", ")}`
              : `<span class="badge badge-green">NONE</span>`}
          </td>
        </tr>
      </tbody>
    </table>
  `;
}

function renderSecurityHeaderRows(security) {
  const headers = [
    { name: "Strict-Transport-Security", title: "HSTS Enforced" },
    { name: "Content-Security-Policy", title: "Content Security Policy (CSP)" },
    { name: "X-Frame-Options", title: "Clickjacking Protection (X-Frame-Options)" },
    { name: "X-Content-Type-Options", title: "MIME-Sniffing Defense (nosniff)" },
    { name: "Referrer-Policy", title: "Referrer Disclosure Policy" },
    { name: "Permissions-Policy", title: "Browser API Permissions Policy" }
  ];

  return headers.map(h => {
    const val = security.headers_present?.[h.name];
    const isMissing = !val;
    const badge = isMissing ? `<span class="badge badge-red">MISSING</span>` : `<span class="badge badge-green">CONFIGURED</span>`;
    const desc = isMissing ? "Header is absent; defense mechanism inactive." : escapeHtml(val);
    return `
      <tr>
        <td><strong>${h.title}</strong><br/><span class="font-mono" style="font-size:11px; color:#666;">${h.name}</span></td>
        <td>${badge}</td>
        <td class="font-mono" style="font-size:12px; word-break:break-all;">${desc}</td>
      </tr>
    `;
  }).join("");
}

function renderTechFingerprintCard(fp) {
  if (!fp || (!fp.detected_technologies?.length && !fp.server_header)) {
    return "<p style='color:#666; font-size:13px;'>No specific server or framework headers revealed.</p>";
  }

  const techList = (fp.detected_technologies || []).map(t => `
    <tr>
      <td><strong>${escapeHtml(t.product)}</strong></td>
      <td class="font-mono">${escapeHtml(t.version)}</td>
      <td>${escapeHtml(t.source)}</td>
    </tr>
  `).join("");

  const vulnList = (fp.vulnerabilities || []).map(v => `
    <div style="background:#fdf2f2; border:1px solid #e5b0b0; padding:10px; border-radius:2px; margin-bottom:8px;">
      <strong style="color:#b02a2a;">${escapeHtml(v.cve)} (${v.severity})</strong> - ${escapeHtml(v.product)} ${escapeHtml(v.version)}
      <p style="font-size:12px; color:#444; margin-top:2px;">${escapeHtml(v.summary)}</p>
    </div>
  `).join("");

  return `
    <table class="data-table" style="margin-bottom:12px;">
      <thead>
        <tr>
          <th>Detected Software</th>
          <th>Version</th>
          <th>Extraction Source</th>
        </tr>
      </thead>
      <tbody>
        ${techList || `<tr><td colspan="3">${escapeHtml(fp.server_header || "Generic Web Server")}</td></tr>`}
      </tbody>
    </table>

    ${fp.has_vulnerabilities ? `<div><h3 style="font-size:14px; margin-bottom:6px;">Known Vulnerability Corroboration</h3>${vulnList}</div>` : `<p style="font-size:12px; color:#277438;">No matching unpatched CVEs found in local vulnerability registry.</p>`}
  `;
}

function renderWeakKeyCard(weakAnalysis, chain) {
  if (!weakAnalysis) return "<p style='color:#666;'>No key analysis available.</p>";

  const leaf = chain && chain[0] ? chain[0] : {};

  return `
    <table class="data-table" style="margin-bottom:12px;">
      <tbody>
        <tr>
          <td style="width:200px;"><strong>Key Algorithm & Bit-Length</strong></td>
          <td class="font-mono">${leaf.key_type || "RSA"} ${leaf.key_size || 2048} bits</td>
        </tr>
        <tr>
          <td><strong>Signature Digest Hash</strong></td>
          <td class="font-mono">${leaf.sig_algo || "sha256WithRSAEncryption"}</td>
        </tr>
        <tr>
          <td><strong>Certificate Validity Period</strong></td>
          <td>Valid from <strong>${leaf.valid_from || "N/A"}</strong> until <strong>${leaf.valid_to || "N/A"}</strong> (${leaf.days_until_expiry ?? 0} days remaining)</td>
        </tr>
        <tr>
          <td><strong>Weak Key Audit Status</strong></td>
          <td>
            ${weakAnalysis.is_weak 
              ? `<span class="badge badge-red">WEAK KEY DETECTED</span> ${weakAnalysis.reasons?.join("; ")}`
              : `<span class="badge badge-green">PASS</span> Key length and signature meet standard criteria`}
          </td>
        </tr>
      </tbody>
    </table>

    <div style="background:#fafaf8; border:1px solid #dcdcd8; padding:12px; border-radius:2px; font-size:13px;">
      <strong>Why Cryptographic Key Auditing Matters:</strong>
      <p style="color:#555; margin-top:4px;">
        This check measures the public key size and signature algorithm presented in this certificate. It cannot determine how a Certificate Authority generated a private key or whether unrelated certificates share key material.
      </p>
    </div>
  `;
}

function renderCommunityReportsList(reports) {
  if (!reports || reports.length === 0) {
    return "<p style='color:#666; font-size:13px;'>No specific community reports submitted for this host yet.</p>";
  }

  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Category</th>
          <th>Report Description</th>
          <th>Votes</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${reports.map(r => `
          <tr>
            <td><strong>${escapeHtml(r.category || 'General')}</strong></td>
            <td>${escapeHtml(r.description || '')}</td>
            <td class="font-mono">${r.confirmations || 0} confirms / ${r.disputes || 0} disputes</td>
            <td><span class="badge ${r.is_verified ? 'badge-red' : 'badge-amber'}">${r.is_verified ? 'VERIFIED' : 'PENDING'}</span></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function initDatabaseView(containerEl, onScanTarget) {
  if (!containerEl) return;

  containerEl.innerHTML = `
    <div style="margin-bottom:16px;">
      <h1>Public Threat Intelligence Database</h1>
      <p style="color:#555; font-size:13px;">
        Community-submitted phishing lures, credential harvesters, and malicious hosts. 
        Entries with 3 or more net community confirmations become verified and factor into automated risk scoring.
      </p>
    </div>

    <!-- Filter Bar -->
    <div class="box" style="padding:12px; margin-bottom:16px;">
      <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
        <div style="flex:2; min-width:200px;">
          <input type="text" id="db-search" placeholder="Search domain, URL, or keywords (e.g. chase, crypto, refund)...">
        </div>
        <div style="flex:1; min-width:160px;">
          <select id="db-category">
            <option value="all">All Categories</option>
            <option value="banking">Banking</option>
            <option value="fake job offer">Fake Job Offer</option>
            <option value="payment link">Payment Link</option>
            <option value="university/government impersonation">University / Government</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div style="display:flex; align-items:center; gap:6px;">
          <input type="checkbox" id="db-verified-only" style="width:auto;">
          <label for="db-verified-only" style="font-size:13px; cursor:pointer;">Verified Only</label>
        </div>
        <div>
          <button class="btn-primary" id="db-filter-btn" style="padding:8px 14px;">Filter</button>
        </div>
      </div>
    </div>

    <!-- Threat List Mount -->
    <div id="db-table-mount">
      <p style="color:#666; font-size:13px;">Loading threat records...</p>
    </div>
  `;

  const searchInput = containerEl.querySelector("#db-search");
  const catSelect = containerEl.querySelector("#db-category");
  const verifiedCheck = containerEl.querySelector("#db-verified-only");
  const filterBtn = containerEl.querySelector("#db-filter-btn");
  const tableMount = containerEl.querySelector("#db-table-mount");

  function loadThreats() {
    tableMount.innerHTML = "<p style='color:#666; font-size:13px;'>Loading threat records...</p>";
    const params = new URLSearchParams();
    if (searchInput.value.trim()) params.set("search", searchInput.value.trim());
    if (catSelect.value !== "all") params.set("category", catSelect.value);
    if (verifiedCheck.checked) params.set("verified_only", "true");

    fetch(`/api/reports?${params.toString()}`)
      .then(res => res.json())
      .then(data => {
        renderThreatsTable(tableMount, data, onScanTarget, loadThreats);
      })
      .catch(err => {
        tableMount.innerHTML = `<p style="color:#b02a2a; font-size:13px;">Failed to load threat reports: ${err.message}</p>`;
      });
  }

  filterBtn.addEventListener("click", loadThreats);
  searchInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") loadThreats();
  });

  // Initial load
  loadThreats();
}

function renderThreatsTable(container, reports, onScanTarget, onRefresh) {
  if (!reports || reports.length === 0) {
    container.innerHTML = "<p style='color:#666; font-size:13px;'>No threat reports match your search criteria.</p>";
    return;
  }

  container.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Domain / Suspect URL</th>
          <th>Category</th>
          <th>Report Details</th>
          <th>Community Consensus</th>
          <th>Status</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        ${reports.map(r => `
          <tr data-id="${r.id}">
            <td style="max-width:220px; word-break:break-all;">
              <strong class="font-mono">${escapeHtml(r.domain || "")}</strong><br/>
              <span class="font-mono" style="font-size:11px; color:#666;">${escapeHtml(r.url || "")}</span>
            </td>
            <td><span class="badge badge-neutral">${escapeHtml(r.category || 'General')}</span></td>
            <td style="max-width:280px; font-size:12px;">${escapeHtml(r.description || '')}</td>
            <td>
              <div style="display:flex; align-items:center; gap:6px; font-size:12px;">
                <span class="font-mono"><strong>+${r.confirmations || 0}</strong> / <font color="#999">-${r.disputes || 0}</font></span>
                <button class="btn-secondary btn-vote" data-id="${r.id}" data-type="confirm" style="padding:2px 6px; font-size:11px;" title="Confirm threat">Confirm</button>
                <button class="btn-secondary btn-vote" data-id="${r.id}" data-type="dispute" style="padding:2px 6px; font-size:11px;" title="Dispute threat">Dispute</button>
              </div>
            </td>
            <td>
              <span class="badge ${r.is_verified ? 'badge-red' : 'badge-amber'}">
                ${r.is_verified ? 'VERIFIED' : 'PENDING'}
              </span>
            </td>
            <td>
              <button class="btn-primary btn-scan-now" data-url="${escapeHtml(r.url || r.domain)}" style="padding:3px 8px; font-size:11px;">
                Scan
              </button>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;

  // Attach voting listeners
  container.querySelectorAll(".btn-vote").forEach(btn => {
    btn.addEventListener("click", () => {
      const repId = btn.getAttribute("data-id");
      const voteType = btn.getAttribute("data-type");
      btn.disabled = true;

      fetch(`/api/reports/${repId}/vote`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vote_type: voteType })
      })
      .then(res => res.json())
      .then(res => {
        if (res.error) {
          alert(res.error);
        } else {
          onRefresh();
        }
      })
      .catch(err => {
        alert("Vote failed: " + err.message);
      })
      .finally(() => {
        btn.disabled = false;
      });
    });
  });

  // Attach scan now listeners
  container.querySelectorAll(".btn-scan-now").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetUrl = btn.getAttribute("data-url");
      if (onScanTarget) onScanTarget(targetUrl);
    });
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

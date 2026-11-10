const STORAGE_KEY = "threatlens.recentScans";
const MAX_RECENT_SCANS = 10;

export function saveRecentScan(report) {
  const scoring = report?.unified_scoring || {};
  const target = report?.target || {};
  if (!report?.report_id) return;

  const recent = readRecentScans();
  const entry = {
    report_id: report.report_id,
    domain: target.hostname || "Unknown target",
    classification: scoring.classification || "Inconclusive",
    score: Number(scoring.score) || 0,
    created_at: Number(report.scan_timestamp) || Math.floor(Date.now() / 1000),
  };
  const updated = [entry, ...recent.filter(scan => scan.report_id !== entry.report_id)]
    .slice(0, MAX_RECENT_SCANS);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
}

export async function refreshRecentScans(mount, onSelect) {
  if (!mount) return;
  const wasOpen = mount.querySelector(".recent-scans")?.open || false;

  mount.innerHTML = `
    <details class="recent-scans">
      <summary>
        <span>Recent scans</span>
        <span class="recent-scan-count" aria-live="polite">Loading</span>
      </summary>
      <div class="recent-scans-actions">
        <span>This clears local shortcuts only; saved reports remain in ThreatLens.</span>
        <button type="button" class="btn-secondary recent-scans-clear">Clear all</button>
      </div>
      <div class="recent-scan-list" role="status">Loading recent scans…</div>
    </details>
  `;
  mount.querySelector(".recent-scans").open = wasOpen;

  const list = mount.querySelector(".recent-scan-list");
  const count = mount.querySelector(".recent-scan-count");
  try {
    const scans = readRecentScans();

    count.textContent = String(scans.length);
    const clearButton = mount.querySelector(".recent-scans-clear");
    clearButton.hidden = scans.length === 0;
    clearButton.addEventListener("click", () => {
      try {
        localStorage.removeItem(STORAGE_KEY);
        refreshRecentScans(mount, onSelect);
      } catch {
        list.textContent = "Could not clear recent scans from this browser.";
        list.setAttribute("role", "alert");
      }
    });

    if (!scans.length) {
      list.textContent = "No saved scans yet.";
      return;
    }

    list.innerHTML = scans.map(scan => `
      <div class="recent-scan-item">
        <button type="button" class="recent-scan-open" data-report-id="${escapeHtml(scan.report_id)}">
          <span class="recent-scan-domain">${escapeHtml(scan.domain || "Unknown target")}</span>
          <span class="recent-scan-meta">
            ${escapeHtml(scan.classification || "Inconclusive")} · ${Number(scan.score) || 0}/100 · ${formatDate(scan.created_at)}
          </span>
        </button>
        <button type="button" class="recent-scan-remove" data-report-id="${escapeHtml(scan.report_id)}" aria-label="Remove ${escapeHtml(scan.domain || "scan")} from recent scans">Remove</button>
      </div>
    `).join("");

    list.querySelectorAll(".recent-scan-open").forEach(button => {
      button.addEventListener("click", () => onSelect(button.dataset.reportId));
    });
    list.querySelectorAll(".recent-scan-remove").forEach(button => {
      button.addEventListener("click", () => {
        try {
          const updated = readRecentScans().filter(scan => scan.report_id !== button.dataset.reportId);
          if (updated.length) localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
          else localStorage.removeItem(STORAGE_KEY);
          refreshRecentScans(mount, onSelect);
        } catch {
          list.textContent = "Could not remove this scan from recent scans.";
          list.setAttribute("role", "alert");
        }
      });
    });
  } catch {
    count.textContent = "Unavailable";
    list.textContent = "Recent scans are unavailable in this browser.";
    list.setAttribute("role", "alert");
  }
}

function readRecentScans() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (!stored) return [];
  const scans = JSON.parse(stored);
  if (!Array.isArray(scans)) throw new Error("Recent scan storage is invalid.");
  return scans.filter(scan => scan && typeof scan.report_id === "string");
}

function formatDate(timestamp) {
  const date = new Date(Number(timestamp) * 1000);
  return Number.isNaN(date.getTime()) ? "Time unavailable" : date.toLocaleString();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

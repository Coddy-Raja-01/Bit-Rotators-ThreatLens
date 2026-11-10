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

  mount.innerHTML = `
    <details class="recent-scans">
      <summary>
        <span>Recent scans</span>
        <span class="recent-scan-count" aria-live="polite">Loading</span>
      </summary>
      <div class="recent-scan-list" role="status">Loading recent scans…</div>
    </details>
  `;

  const list = mount.querySelector(".recent-scan-list");
  const count = mount.querySelector(".recent-scan-count");
  try {
    const scans = readRecentScans();

    count.textContent = String(scans.length);
    if (!scans.length) {
      list.textContent = "No saved scans yet.";
      return;
    }

    list.innerHTML = scans.map(scan => `
      <button type="button" class="recent-scan-item" data-report-id="${escapeHtml(scan.report_id)}">
        <span class="recent-scan-domain">${escapeHtml(scan.domain || scan.target_url || "Unknown target")}</span>
        <span class="recent-scan-meta">
          ${escapeHtml(scan.classification || "Inconclusive")} · ${Number(scan.score) || 0}/100 · ${formatDate(scan.created_at)}
        </span>
      </button>
    `).join("");

    list.querySelectorAll(".recent-scan-item").forEach(button => {
      button.addEventListener("click", () => onSelect(button.dataset.reportId));
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

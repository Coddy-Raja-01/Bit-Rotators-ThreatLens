function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  })[character]);
}

export function renderIntelSourceStatus(sources = []) {
  const rows = sources.map(source => `
    <tr>
      <td>${escapeHtml(source.name || "")}</td>
      <td>${escapeHtml(source.status || "unknown")}</td>
      <td>${escapeHtml(source.last_refresh || "Per-target lookup / not cached")}</td>
      <td>${source.record_count == null ? "N/A" : escapeHtml(source.record_count)}</td>
    </tr>
  `).join("");

  return `
    <div class="box">
      <div class="box-title">Intelligence Sources</div>
      <table class="data-table">
        <thead>
          <tr><th>Source</th><th>Status</th><th>Last refresh (UTC)</th><th>Records</th></tr>
        </thead>
        <tbody>${rows || '<tr><td colspan="4">Source status is not included in this report.</td></tr>'}</tbody>
      </table>
    </div>
  `;
}

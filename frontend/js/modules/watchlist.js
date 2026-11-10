export function initWatchlistView(containerEl, currentUser, onRequireAuth) {
  if (!containerEl) return;

  if (!currentUser) {
    containerEl.innerHTML = `
      <div class="box" style="max-width:500px; margin:40px auto; padding:24px;">
        <h2 style="margin-bottom:8px;">Sign in to Access Domain Watchlist</h2>
        <p style="color:#555; font-size:13px; margin-bottom:16px;">
          ThreatLens Watchlist continuously monitors domains on a schedule for certificate changes, impending expiration, and new community phishing reports.
        </p>
        <form id="inline-login-form">
          <div style="margin-bottom:10px;">
            <label for="inline-username" style="display:block; font-size:12px; margin-bottom:2px;">Username or Email</label>
            <input type="text" id="inline-username" autocomplete="username" required>
          </div>
          <div style="margin-bottom:14px;">
            <label for="inline-password" style="display:block; font-size:12px; margin-bottom:2px;">Password</label>
            <input type="password" id="inline-password" autocomplete="current-password" required>
          </div>
          <button type="submit" class="btn-primary" style="width:100%;">Sign In & Open Watchlist</button>
        </form>
      </div>
    `;

    containerEl.querySelector("#inline-login-form")?.addEventListener("submit", (e) => {
      e.preventDefault();
      const u = containerEl.querySelector("#inline-username").value;
      const p = containerEl.querySelector("#inline-password").value;
      if (onRequireAuth) onRequireAuth(u, p);
    });
    return;
  }

  containerEl.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px; margin-bottom:16px;">
      <div>
        <h1>Domain Watchlist & Automated Alerts</h1>
        <p style="color:#555; font-size:13px;">
          Signed in as <strong>${escapeHtml(currentUser.username)}</strong>.
          Watched domains are monitored for SSL replacements, certificate expiration (<=14 days), and community threat flags.
        </p>
      </div>
      <div>
        <button class="btn-secondary" id="btn-recheck-watchlist">Re-check All Domains Now</button>
      </div>
    </div>

    <!-- Add to Watchlist Form -->
    <div class="box" style="padding:14px; margin-bottom:18px;">
      <div class="box-title" style="margin-bottom:8px;">Add Domain to Automated Watchlist</div>
      <form id="add-watchlist-form" style="display:flex; gap:8px;">
        <input type="text" id="watchlist-domain-input" placeholder="e.g. mycompany-portal.com or yourbank.com" required style="flex:1;">
        <button type="submit" class="btn-primary">Add Domain</button>
      </form>
    </div>

    <!-- Alerts Section -->
    <div class="box" id="watchlist-alerts-box" style="margin-bottom:18px; display:none;">
      <div class="box-title">
        <span>Active Security Alerts (<span id="alert-count-num">0</span>)</span>
        <button class="btn-secondary" id="btn-clear-alerts" style="padding:2px 8px; font-size:11px;">Mark All Read</button>
      </div>
      <div id="alerts-list-mount"></div>
    </div>

    <!-- Watchlist Table -->
    <div class="box">
      <div class="box-title">Monitored Domains</div>
      <div id="watchlist-table-mount">
        <p style="color:#666; font-size:13px;">Loading watched domains...</p>
      </div>
    </div>
  `;

  const addForm = containerEl.querySelector("#add-watchlist-form");
  const domainInput = containerEl.querySelector("#watchlist-domain-input");
  const recheckBtn = containerEl.querySelector("#btn-recheck-watchlist");
  const tableMount = containerEl.querySelector("#watchlist-table-mount");
  const alertsBox = containerEl.querySelector("#watchlist-alerts-box");
  const alertsMount = containerEl.querySelector("#alerts-list-mount");
  const alertCountEl = containerEl.querySelector("#alert-count-num");
  const clearAlertsBtn = containerEl.querySelector("#btn-clear-alerts");

  function loadWatchlist() {
    window.apiFetch("/api/watchlist")
      .then(res => res.json())
      .then(items => {
        renderWatchlistTable(tableMount, items, loadWatchlist);
      })
      .catch(err => {
        tableMount.innerHTML = `<p style="color:#b02a2a; font-size:13px;">Failed to load watchlist: ${err.message}</p>`;
      });

    // Load alerts
    window.apiFetch("/api/alerts?unread_only=true")
      .then(res => res.json())
      .then(alerts => {
        if (alerts && alerts.length > 0) {
          alertsBox.style.display = "block";
          alertCountEl.textContent = alerts.length;
          renderAlertsList(alertsMount, alerts);
        } else {
          alertsBox.style.display = "none";
        }
      });
  }

  addForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const d = domainInput.value.trim();
    if (!d) return;

    window.apiFetch("/api/watchlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: d })
    })
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        alert(data.error);
      } else {
        domainInput.value = "";
        loadWatchlist();
      }
    })
    .catch(err => {
      alert("Error adding domain: " + err.message);
    });
  });

  recheckBtn.addEventListener("click", () => {
    recheckBtn.disabled = true;
    recheckBtn.textContent = "Checking...";
    window.apiFetch("/api/watchlist/check-now", { method: "POST" })
      .then(res => res.json())
      .then(res => {
        alert(`Audit finished: Checked ${res.domains_checked} domains. Generated ${res.new_alerts_created} new alerts.`);
        loadWatchlist();
      })
      .catch(err => alert("Re-check failed: " + err.message))
      .finally(() => {
        recheckBtn.disabled = false;
        recheckBtn.textContent = "Re-check All Domains Now";
      });
  });

  clearAlertsBtn.addEventListener("click", () => {
    window.apiFetch("/api/alerts/read", { method: "POST" })
      .then(res => res.json())
      .then(() => loadWatchlist());
  });

  loadWatchlist();
}

function renderWatchlistTable(container, items, onRefresh) {
  if (!items || items.length === 0) {
    container.innerHTML = "<p style='color:#666; font-size:13px;'>Your watchlist is currently empty. Add your first domain above.</p>";
    return;
  }

  container.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Monitored Domain</th>
          <th>Health Status</th>
          <th>Last Checked</th>
          <th>Unread Alerts</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        ${items.map(it => {
          let badgeClass = "badge-green";
          if (it.last_status === "EXPIRING_SOON" || it.last_status === "PENDING") badgeClass = "badge-amber";
          if (it.last_status === "NO_SSL" || it.last_status === "MALICIOUS_THREAT") badgeClass = "badge-red";

          const checkedTime = it.last_checked ? new Date(it.last_checked * 1000).toLocaleString() : "Never";

          return `
            <tr>
              <td class="font-mono"><strong>${escapeHtml(it.domain)}</strong></td>
              <td><span class="badge ${badgeClass}">${escapeHtml(it.last_status || 'UNKNOWN')}</span></td>
              <td style="font-size:12px; color:#555;">${checkedTime}</td>
              <td>${it.unread_alerts > 0 ? `<span class="badge badge-red">${it.unread_alerts} Alert(s)</span>` : `<font color="#666">0</font>`}</td>
              <td>
                <button class="btn-danger btn-delete-watch" data-id="${it.id}" style="padding:2px 7px; font-size:11px;">
                  Remove
                </button>
              </td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;

  container.querySelectorAll(".btn-delete-watch").forEach(btn => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-id");
      if (!confirm("Remove this domain from watchlist?")) return;
      window.apiFetch(`/api/watchlist/${id}`, { method: "DELETE" })
        .then(res => res.json())
        .then(() => onRefresh())
        .catch(err => alert("Error removing domain: " + err.message));
    });
  });
}

function renderAlertsList(container, alerts) {
  container.innerHTML = alerts.map(a => {
    let borderCol = "#c27803";
    let bgCol = "#fffbf0";
    if (a.severity === "CRITICAL") {
      borderCol = "#b02a2a";
      bgCol = "#fdf2f2";
    }
    const timeStr = new Date(a.created_at * 1000).toLocaleString();

    return `
      <div style="background:${bgCol}; border-left:3px solid ${borderCol}; padding:10px 12px; margin-bottom:8px; font-size:13px;">
        <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
          <strong>${escapeHtml(a.title)}: <span class="font-mono">${escapeHtml(a.domain)}</span></strong>
          <span style="font-size:11px; color:#666;">${timeStr}</span>
        </div>
        <p style="color:#333; margin:0;">${escapeHtml(a.message)}</p>
      </div>
    `;
  }).join("");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

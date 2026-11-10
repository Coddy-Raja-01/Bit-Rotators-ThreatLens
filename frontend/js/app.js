import { renderScanReport } from "./modules/scanner.js";
import { initDatabaseView } from "./modules/database_view.js";
import { initWatchlistView } from "./modules/watchlist.js";
import { refreshRecentScans, saveRecentScan } from "./modules/recent_scans.js";

// Global App State
const state = {
  currentUser: null,
  currentScan: null,
};

// DOM Elements
const navLinks = document.querySelectorAll(".nav-link");
const viewSections = document.querySelectorAll(".view-section");
const headerAuthMount = document.querySelector("#header-auth-mount");
const mainScanForm = document.querySelector("#main-scan-form");
const scanUrlInput = document.querySelector("#scan-url-input");
const scanAuthorizedTarget = document.querySelector("#scan-authorized-target");
const btnRunScan = document.querySelector("#btn-run-scan");
const scanReportMount = document.querySelector("#scan-report-mount");
const recentScansMount = document.querySelector("#recent-scans-mount");

// Init application
document.addEventListener("DOMContentLoaded", () => {
  setupRouting();
  checkAuth();
  loadStats();
  loadRegistryStatus();
  setupScanForm();
  refreshRecentScans(recentScansMount, loadRecentScan);
  setupSubmitThreatForm();
  setupAuthTabs();
});

document.querySelector("#btn-refresh-registry")?.addEventListener("click", loadRegistryStatus);

// Routing
function setupRouting() {
  window.addEventListener("hashchange", handleRoute);
  handleRoute();
}

function handleRoute() {
  const hash = window.location.hash.slice(1) || "home";
  const [route, queryStr] = hash.split("?");
  const params = new URLSearchParams(queryStr || "");

  // Update nav active classes
  navLinks.forEach(link => {
    if (link.getAttribute("data-view") === route) {
      link.classList.add("active");
    } else {
      link.classList.remove("active");
    }
  });

  // Switch view
  viewSections.forEach(sec => {
    sec.classList.remove("active");
  });

  const targetSec = document.querySelector(`#view-${route}`);
  if (targetSec) {
    targetSec.classList.add("active");
  } else {
    document.querySelector("#view-home")?.classList.add("active");
  }

  // View specific activations
  if (route === "database") {
    const mount = document.querySelector("#database-view-mount");
    initDatabaseView(mount, (urlToScan) => {
      window.location.hash = "#home";
      scanUrlInput.value = urlToScan;
      triggerScan(urlToScan);
    });
  } else if (route === "watchlist") {
    const mount = document.querySelector("#watchlist-view-mount");
    initWatchlistView(mount, state.currentUser, (username, password) => {
      performLogin(username, password, () => {
        initWatchlistView(mount, state.currentUser);
      });
    });
  } else if (route === "submit") {
    if (params.get("url")) {
      const repUrlInput = document.querySelector("#report-url");
      if (repUrlInput) repUrlInput.value = decodeURIComponent(params.get("url"));
    }
  } else if (route === "api") {
    setupApiKeyManager();
  }
}

// Authentication Check
function checkAuth() {
  window.apiFetch("/api/auth/me")
    .then(res => res.json())
    .then(data => {
      state.currentUser = data.user;
      renderHeaderAuth();
    })
    .catch(() => {
      state.currentUser = null;
      renderHeaderAuth();
    });
}

function renderHeaderAuth() {
  if (state.currentUser) {
    headerAuthMount.innerHTML = `
      <span style="color:#555;">User: <strong>${escapeHtml(state.currentUser.username)}</strong></span>
      <button class="btn-secondary" id="btn-logout" style="padding:2px 8px; font-size:11px;">Sign Out</button>
    `;
    headerAuthMount.querySelector("#btn-logout")?.addEventListener("click", () => {
      window.apiFetch("/api/auth/logout", { method: "POST" })
        .then(() => {
          state.currentUser = null;
          renderHeaderAuth();
          handleRoute();
        });
    });
  } else {
    headerAuthMount.innerHTML = `
      <a href="#auth" class="nav-link" data-view="auth">Sign in / Register</a>
    `;
  }
}

// Global Stats
function loadStats() {
  window.apiFetch("/api/stats")
    .then(res => res.json())
    .then(stats => {
      const elReports = document.querySelector("#stat-reports");
      const elVerified = document.querySelector("#stat-verified");

      if (elReports) elReports.textContent = stats.total_reports ?? 0;
      if (elVerified) elVerified.textContent = stats.verified_threats ?? 0;
    })
    .catch(() => {});
}

async function loadRegistryStatus() {
  const statusEl = document.querySelector("#registry-status");
  const metadataEl = document.querySelector("#registry-metadata");
  if (!statusEl || !metadataEl) return;

  statusEl.textContent = "Checking registry connection…";
  statusEl.className = "registry-state";
  metadataEl.textContent = "";
  try {
    const response = await window.apiFetch("/api/chain/status/availability");
    const data = await response.json();
    if (!response.ok) throw new Error("Status could not be checked.");
    if (!data.connected) {
      statusEl.textContent = "Not connected · Registry unavailable";
      statusEl.classList.add("is-disconnected");
      metadataEl.textContent = "On-chain commits need a deployed registry and configured RPC. Scanning and report export remain available.";
      return;
    }

    statusEl.textContent = `Connected · ${data.network || "EVM network"}`;
    statusEl.classList.add("is-connected");
    metadataEl.textContent = [
      `Chain ID ${data.chain_id}`,
      `Contract ${data.contract_address}`,
      `${data.report_count} committed report${data.report_count === 1 ? "" : "s"}`,
    ].join("  ·  ");
  } catch {
    statusEl.textContent = "Not connected · Registry unavailable";
    statusEl.classList.add("is-disconnected");
    metadataEl.textContent = "On-chain commits need a deployed registry and configured RPC. Scanning and report export remain available.";
  }
}

// Setup Main Scan Form
function setupScanForm() {
  mainScanForm?.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = scanUrlInput.value.trim();
    if (!url) return;
    triggerScan(url);
  });

  // Setup quick example buttons
  document.querySelectorAll(".quick-examples .link-tag").forEach(tag => {
    tag.addEventListener("click", () => {
      const url = tag.getAttribute("data-url");
      scanUrlInput.value = url;
      triggerScan(url);
    });
  });
}

function triggerScan(rawUrl) {
  btnRunScan.disabled = true;
  btnRunScan.textContent = "Investigating…";
  scanReportMount.style.display = "block";
  scanReportMount.innerHTML = `
    <div class="box scan-loading" role="status" aria-live="polite">
      <span class="scan-spinner" aria-hidden="true"></span>
      <div>
        <h3>Investigating target</h3>
        <p>Validating the destination, then checking available signals. Authorized content checks may take longer.</p>
      </div>
    </div>
  `;
  scanReportMount.scrollIntoView({ behavior: "smooth" });

  window.apiFetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: rawUrl,
      authorized_target: Boolean(scanAuthorizedTarget?.checked)
    })
  })
  .then(res => {
    if (!res.ok) {
      return res.json().then(errData => { throw new Error(errData.message || errData.detail || "Scan request failed"); });
    }
    return res.json();
  })
  .then(report => {
    state.currentScan = report;
    renderScanReport(scanReportMount, report);
    let recentSaved = true;
    try {
      saveRecentScan(report);
    } catch {
      recentSaved = false;
      const recentList = recentScansMount?.querySelector(".recent-scan-list");
      if (recentList) {
        recentList.setAttribute("role", "alert");
        recentList.textContent = "This scan could not be saved to recent scans in this browser.";
      }
    }
    if (recentSaved) refreshRecentScans(recentScansMount, loadRecentScan);
  })
  .catch(err => {
    scanReportMount.innerHTML = `
      <div class="box" style="background:#fdf2f2; border:1px solid #e5b0b0; padding:16px;">
        <strong style="color:#b02a2a;">Scan Blocked or Failed:</strong>
        <p style="font-size:13px; color:#333; margin-top:4px;">${escapeHtml(err.message)}</p>
      </div>
    `;
  })
  .finally(() => {
    btnRunScan.disabled = false;
    btnRunScan.textContent = "Investigate";
  });
}

async function loadRecentScan(reportId) {
  try {
    const response = await window.apiFetch(`/api/scan/${encodeURIComponent(reportId)}`);
    const report = await response.json();
    if (!response.ok) throw new Error(report.detail || "Could not open this saved scan.");
    state.currentScan = report;
    scanReportMount.style.display = "block";
    renderScanReport(scanReportMount, report);
    scanReportMount.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch {
    const list = recentScansMount?.querySelector(".recent-scan-list");
    if (list) {
      list.setAttribute("role", "alert");
      list.textContent = error.message;
    }
  }
}

// Setup Submit Threat Form
function setupSubmitThreatForm() {
  const form = document.querySelector("#submit-threat-form");
  if (!form) return;

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = document.querySelector("#report-url").value.trim();
    const category = document.querySelector("#report-category").value;
    const description = document.querySelector("#report-description").value.trim();

    window.apiFetch("/api/reports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, category, description })
    })
    .then(res => res.json())
    .then(data => {
      alert("Report successfully recorded in the community threat database.");
      form.reset();
      window.location.hash = "#database";
    })
    .catch(err => {
      alert("Submission error: " + err.message);
    });
  });
}

// Setup Auth Tabs & Forms
function setupAuthTabs() {
  const tabLogin = document.querySelector("#auth-tab-login");
  const tabRegister = document.querySelector("#auth-tab-register");
  const boxLogin = document.querySelector("#auth-login-box");
  const boxRegister = document.querySelector("#auth-register-box");
  const formLogin = document.querySelector("#form-login");
  const formRegister = document.querySelector("#form-register");

  tabLogin?.addEventListener("click", () => {
    tabLogin.classList.add("active");
    tabRegister.classList.remove("active");
    boxLogin.style.display = "block";
    boxRegister.style.display = "none";
  });

  tabRegister?.addEventListener("click", () => {
    tabRegister.classList.add("active");
    tabLogin.classList.remove("active");
    boxRegister.style.display = "block";
    boxLogin.style.display = "none";
  });

  formLogin?.addEventListener("submit", (e) => {
    e.preventDefault();
    const u = document.querySelector("#login-username").value.trim();
    const p = document.querySelector("#login-password").value;
    performLogin(u, p, () => {
      window.location.hash = "#watchlist";
    });
  });

  formRegister?.addEventListener("submit", (e) => {
    e.preventDefault();
    const u = document.querySelector("#reg-username").value.trim();
    const em = document.querySelector("#reg-email").value.trim();
    const p = document.querySelector("#reg-password").value;

    window.apiFetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: u, email: em, password: p })
    })
    .then(res => {
      if (!res.ok) return res.json().then(e => { throw new Error(e.detail || "Registration failed"); });
      return res.json();
    })
    .then(data => {
      state.currentUser = data.user;
      renderHeaderAuth();
      alert("Account created successfully!");
      window.location.hash = "#watchlist";
    })
    .catch(err => alert(err.message));
  });
}

function performLogin(username_or_email, password, onSuccess) {
  window.apiFetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username_or_email, password })
  })
  .then(res => {
    if (!res.ok) return res.json().then(e => { throw new Error(e.detail || "Authentication failed"); });
    return res.json();
  })
  .then(data => {
    state.currentUser = data.user;
    renderHeaderAuth();
    if (onSuccess) onSuccess();
  })
  .catch(err => alert(err.message));
}

// API Key Manager
function setupApiKeyManager() {
  const mount = document.querySelector("#api-key-manager-mount");
  if (!mount) return;

  if (!state.currentUser) {
    mount.innerHTML = `
      <p style="font-size:12px; color:#666;">
        <a href="#auth">Sign in</a> to generate and manage automated API keys.
      </p>
    `;
    return;
  }

  mount.innerHTML = `
    <div style="margin-bottom:10px;">
      <button class="btn-primary" id="btn-gen-key">Generate New API Key</button>
    </div>
    <div id="api-keys-list"></div>
  `;

  const listEl = mount.querySelector("#api-keys-list");

  function loadKeys() {
    window.apiFetch("/api/keys")
      .then(res => res.json())
      .then(keys => {
        if (!keys || keys.length === 0) {
          listEl.innerHTML = "<p style='font-size:12px; color:#666;'>No API keys generated yet.</p>";
          return;
        }
        listEl.innerHTML = `
          <table class="data-table">
            <thead>
              <tr>
                <th>Key Name</th>
                <th>Prefix</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              ${keys.map(k => `
                <tr>
                  <td><strong>${escapeHtml(k.name)}</strong></td>
                  <td class="font-mono">${escapeHtml(k.key_prefix)}</td>
                  <td>${new Date(k.created_at * 1000).toLocaleDateString()}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        `;
      });
  }

  mount.querySelector("#btn-gen-key")?.addEventListener("click", () => {
    const keyName = prompt("Enter a label for this API key:", "Production Automation");
    if (!keyName) return;

    window.apiFetch("/api/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: keyName })
    })
    .then(res => res.json())
    .then(data => {
      prompt("Copy and save your new API key now (it will not be displayed again):", data.api_key);
      loadKeys();
    })
    .catch(err => alert("Error creating key: " + err.message));
  });

  loadKeys();
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function renderAiModeStatus() {
  return `
    <div class="box">
      <div class="box-title">AI Analysis Mode</div>
      <p id="ai-mode-status" style="font-size:13px; color:#555;">Loading configured mode...</p>
    </div>
  `;
}

export function loadAiModeStatus(containerEl) {
  const statusEl = containerEl.querySelector("#ai-mode-status");
  fetch("/api/ai/status")
    .then(response => {
      if (!response.ok) throw new Error(`AI mode status unavailable (${response.status})`);
      return response.json();
    })
    .then(status => {
      if (statusEl) {
        statusEl.textContent = `${status.provider || "Unknown"}${status.model ? ` (${status.model})` : ""}`;
      }
    })
    .catch(error => {
      if (statusEl) statusEl.textContent = error.message;
    });
}

const form = document.querySelector("#scan-form");
const result = document.querySelector("#result");
const submit = document.querySelector("#submit");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  submit.disabled = true;
  result.className = "";
  result.textContent = "Inspecting with the local ThreatLens server...";

  try {
    const response = await fetch("http://127.0.0.1:8000/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: document.querySelector("#url").value.trim(),
        authorized_target: document.querySelector("#authorized").checked
      })
    });
    const report = await response.json();
    if (!response.ok || !report.success) {
      throw new Error(report.message || report.detail || "The scan could not be completed.");
    }

    const score = report.unified_scoring;
    result.className = score.classification === "Low Risk" ? "" : "warning";
    result.textContent = [
      `${score.classification} - score ${score.score}/100`,
      score.summary,
      score.disclaimer,
      "Review the evidence before making a decision."
    ].join("\n\n");
  } catch (error) {
    result.className = "warning";
    result.textContent = `${error.message}\n\nConfirm that ThreatLens is running at http://127.0.0.1:8000.`;
  } finally {
    submit.disabled = false;
  }
});

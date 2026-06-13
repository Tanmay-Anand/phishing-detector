const SVG = {
  safe: `<svg width="40" height="40" viewBox="0 0 24 24" fill="none"
    stroke="#10b981" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <polyline points="9 12 11 14 15 10"/>
  </svg>`,

  suspicious: `<svg width="40" height="40" viewBox="0 0 24 24" fill="none"
    stroke="#f59e0b" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <line x1="12" y1="9" x2="12" y2="13"/>
    <circle cx="12" cy="16.5" r="0.5" fill="#f59e0b"/>
  </svg>`,

  dangerous: `<svg width="40" height="40" viewBox="0 0 24 24" fill="none"
    stroke="#ef4444" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <line x1="9" y1="10" x2="15" y2="16"/>
    <line x1="15" y1="10" x2="9" y2="16"/>
  </svg>`
};

const cfg = {
  safe:       { badge: "All Clear",  title: "No Threats Detected", barLabel: "Low" },
  suspicious: { badge: "Suspicious", title: "Suspicious Activity",  barLabel: "Medium" },
  dangerous:  { badge: "Dangerous",  title: "Threat Detected",      barLabel: "High" }
};

const header     = document.getElementById("header");
const shieldRing = document.getElementById("shield-ring");
const shieldIcon = document.getElementById("shield-icon");
const riskBadge  = document.getElementById("risk-badge");
const riskTitle  = document.getElementById("risk-title");
const domainText = document.getElementById("domain-text");
const pulseDot   = document.getElementById("pulse-dot");
const content    = document.getElementById("content");

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (!tab?.url) return;

  let hostname;
  try { hostname = new URL(tab.url).hostname; }
  catch { riskTitle.textContent = "Cannot analyze this page"; return; }

  domainText.textContent = hostname;

  chrome.storage.local.get(hostname, (result) => {
    const data = result[hostname];

    if (!data) {
      riskTitle.textContent = "Reload the page to scan";
      riskBadge.textContent = "No data yet";
      return;
    }

    const { riskLevel, warnings } = data;
    const c = cfg[riskLevel];

    // Apply theme
    header.classList.add(riskLevel);
    shieldRing.classList.add(riskLevel);
    pulseDot.classList.add(riskLevel);

    shieldIcon.innerHTML  = SVG[riskLevel];
    riskBadge.textContent = c.badge;
    riskBadge.className   = `risk-badge ${riskLevel}`;
    riskTitle.textContent = c.title;

    // Bar width scales with number of warnings
    const dynamicWidth = riskLevel === "safe"
      ? "4%"
      : `${Math.min(95, 35 + warnings.length * 15)}%`;

    const scoreHTML = `
      <div class="score-section">
        <div class="score-row">
          <span class="score-row-label">Threat Level</span>
          <span class="score-level ${riskLevel}">${c.barLabel} Risk</span>
        </div>
        <div class="bar-bg">
          <div class="bar-fill ${riskLevel}" style="width:${dynamicWidth}"></div>
        </div>
      </div>`;

    let bodyHTML = "";

    if (warnings.length === 0) {
      bodyHTML = `
        <div class="safe-card">
          <div class="safe-circle">
            <div class="check-mark"></div>
          </div>
          <div class="safe-heading">All checks passed</div>
          <div class="safe-sub">No phishing patterns detected.<br>This page appears safe.</div>
        </div>`;
    } else {
      const wCls   = riskLevel === "dangerous" ? "dangerous" : "suspicious";
      const wLabel = riskLevel === "dangerous" ? "x" : "!";
      const cards  = warnings.map(w => `
        <div class="warning-card ${wCls}">
          <div class="w-icon ${wCls}">${wLabel}</div>
          <span>${w}</span>
        </div>`).join("");
      bodyHTML = `
        <div class="warnings-section">
          <div class="section-title">Detected Issues — ${warnings.length} found</div>
          ${cards}
        </div>`;
    }

    content.innerHTML = scoreHTML + bodyHTML;
  });
});
// ===== URL ANALYSIS (Phase 2) =====
const url = new URL(window.location.href);
const hostname = url.hostname;
const domain = hostname.replace(/^www\./, "");
const warnings = [];

if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
  warnings.push("IP address used as domain");
}

const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"];
if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
  warnings.push("Suspicious TLD: ." + domain.split(".").pop());
}

const knownBrands = ["paypal", "google", "facebook", "apple", "amazon",
                     "microsoft", "netflix", "instagram", "twitter"];
const parts = domain.split(".");
const mainDomain = parts.slice(-2).join(".");
const subdomains = parts.slice(0, -2).join(".");

knownBrands.forEach(brand => {
  if (subdomains.includes(brand) && !mainDomain.includes(brand)) {
    warnings.push(`Brand "${brand}" used in subdomain to fake legitimacy`);
  }
});

const hyphenCount = (domain.match(/-/g) || []).length;
if (hyphenCount >= 3) {
  warnings.push(`Excessive hyphens (${hyphenCount}) in domain`);
}

const leetMap = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s" };
let normalized = domain;
for (const [char, replacement] of Object.entries(leetMap)) {
  normalized = normalized.replaceAll(char, replacement);
}
knownBrands.forEach(brand => {
  if (normalized.includes(brand) && !domain.includes(brand)) {
    warnings.push(`Lookalike domain: "${domain}" may be impersonating "${brand}"`);
  }
});

// ===== FORM INSPECTION (Phase 3) =====
function inspectForms() {
  const forms = [...document.querySelectorAll("form")];
  forms.forEach(form => {
    const inputs = [...form.querySelectorAll("input")];
    const hasPassword = inputs.some(i => i.type === "password");
    const hasUserField = inputs.some(i =>
      /user|email|login|account|phone/i.test(i.name + i.id + i.placeholder)
    );
    if (!hasPassword && !hasUserField) return;

    const formURL = new URL(form.action);
    if (formURL.hostname !== hostname) {
      warnings.push(`Credential form posts to foreign domain: ${formURL.hostname}`);
    }
    if (formURL.protocol === "http:") {
      warnings.push("Credential form submits over unencrypted HTTP");
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(formURL.hostname)) {
      warnings.push(`Credential form posts to IP address: ${formURL.hostname}`);
    }
  });
}

// ===== REDIRECT DETECTION — CLIENT SIDE (Phase 4) =====
function inspectMetaRefresh() {
  const meta = document.querySelector('meta[http-equiv="refresh"]');
  if (!meta) return;
  const content = meta.getAttribute("content") || "";
  const match = content.match(/url=(.+)/i);
  if (!match) return;
  const redirectTarget = new URL(match[1].trim(), window.location.href);
  if (redirectTarget.hostname !== hostname) {
    warnings.push(`Meta refresh redirects to different domain: ${redirectTarget.hostname}`);
  }
}

// ===== RISK SCORING (Phase 5) =====
function getRiskLevel(count) {
  if (count === 0) return "safe";
  if (count <= 2) return "suspicious";
  return "dangerous";
}

// ===== REPORT (Phase 5) — only one, uses chrome.storage.local =====
function report() {
  const riskLevel = getRiskLevel(warnings.length);

  if (warnings.length === 0) {
    console.log("[Phishing Detector] CLEAN:", domain);
  } else {
    console.warn("[Phishing Detector] WARNING on:", domain);
    warnings.forEach(w => console.warn("  ->", w));
  }

  chrome.storage.local.set(
    { [hostname]: { domain, warnings, riskLevel, timestamp: Date.now() } }
  );

  chrome.runtime.sendMessage({ type: "UPDATE_BADGE", riskLevel });
}

// ===== RUN =====
inspectForms();
inspectMetaRefresh();

let reported = false;
function reportOnce() {
  if (reported) return;
  reported = true;
  report();
}

const fallbackTimer = setTimeout(reportOnce, 800);

chrome.runtime.sendMessage({ type: "GET_REDIRECT_WARNINGS" }, (response) => {
  clearTimeout(fallbackTimer);
  if (chrome.runtime.lastError) { reportOnce(); return; }
  if (response && response.warnings) {
    response.warnings.forEach(w => warnings.push(w));
  }
  reportOnce();
});
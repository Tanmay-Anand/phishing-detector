const redirectCounts = {};
const redirectWarnings = {};

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;

  const { tabId, url, transitionQualifiers } = details;
  const isRedirect =
    transitionQualifiers.includes("server_redirect") ||
    transitionQualifiers.includes("client_redirect");

  if (!redirectWarnings[tabId]) redirectWarnings[tabId] = [];

  if (isRedirect) {
    redirectCounts[tabId] = (redirectCounts[tabId] || 0) + 1;
    if (redirectCounts[tabId] >= 2) {
      redirectWarnings[tabId].push(
        `Redirect chain: ${redirectCounts[tabId]} hops before landing`
      );
    }
    if (url.startsWith("http://")) {
      redirectWarnings[tabId].push(
        "Redirected from HTTPS to HTTP — possible SSL stripping"
      );
    }
  } else {
    redirectCounts[tabId] = 0;
    redirectWarnings[tabId] = [];
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Phase 4: content script requests redirect warnings
  if (message.type === "GET_REDIRECT_WARNINGS") {
    const tabId = sender.tab.id;
    const warnings = redirectWarnings[tabId] || [];
    redirectWarnings[tabId] = [];
    sendResponse({ warnings });
  }

  // Phase 5: content script tells us to update the badge
  if (message.type === "UPDATE_BADGE") {
    const tabId = sender.tab.id;
    const config = {
      safe:       { text: "",   color: "#22c55e" },
      suspicious: { text: "!",  color: "#f97316" },
      dangerous:  { text: "!!", color: "#ef4444" },
    };
    const { text, color } = config[message.riskLevel];
    chrome.action.setBadgeText({ text, tabId });
    chrome.action.setBadgeBackgroundColor({ color, tabId });
  }

  return true; // keep channel open for async sendResponse
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete redirectCounts[tabId];
  delete redirectWarnings[tabId];
});
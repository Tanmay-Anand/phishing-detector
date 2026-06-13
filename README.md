# Phishing Detector (Browser Extension)

A browser extension that detects phishing attempts in real time. Built with JavaScript and the Chrome/Edge Extension APIs (Manifest V3).

---

## Features

- **URL Analysis** — Detects IP-based domains, suspicious TLDs, lookalike character substitution, excessive hyphens, and brand spoofing in subdomains
- **Form Inspection** — Flags credential forms that submit to foreign domains, unencrypted HTTP endpoints, or IP addresses
- **Redirect Detection** — Catches server-side redirect chains, HTTPS-to-HTTP downgrades, and meta refresh hijacks
- **Live Badge** — Extension icon turns green / orange / red on every page automatically
- **Popup UI** — Click the icon to see a full risk report with threat level bar and warning breakdown

---

## Project Structure

```
phishing-detector/
├── manifest.json     — Extension config (permissions, scripts, popup)
├── background.js     — Service worker: redirect tracking, badge updates
├── content.js        — Injected into every page: URL, form, redirect checks
├── popup.html        — Popup UI layout and styles
└── popup.js          — Popup logic: reads scan results, renders risk state
```


---

## Detection Layers

| Layer | What It Checks |
|---|---|
| URL Analysis | IP domains, bad TLDs (.tk .ml .xyz), brand in subdomain, hyphens, leet substitution |
| Form Inspection | Cross-domain credential submission, HTTP forms, IP-addressed endpoints |
| Redirect Detection | Server redirect chains (2+ hops), HTTPS→HTTP downgrade, meta refresh hijacks |

---

## Risk Levels

| Level | Condition | Badge |
|---|---|---|
| Safe | 0 warnings | No badge |
| Suspicious | 1–2 warnings | Orange `!` |
| Dangerous | 3+ warnings | Red `!!` |

---

## Installation (Developer Mode)

1. Clone or download this repository
2. Open Edge and go to `edge://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked**
5. Select the `phishing-detector/` folder
6. Navigate to any website —> the extension activates automatically

> After any code change: reload the extension at `edge://extensions`, then hard-refresh the page (`Ctrl + Shift + R`).

---

## How It Works

```
Page loads
    │
    ▼
content.js injects
    ├── URL checks             (synchronous)
    ├── Form checks            (synchronous)
    ├── Meta refresh check     (synchronous)
    └── Ask background.js for redirect warnings (async)
            │
            ▼
        report() fires
            ├── Writes results to chrome.storage.local
            └── Sends UPDATE_BADGE to background.js
                        │
                        ▼
                background.js sets badge color + text

User clicks icon
    │
    ▼
popup.js reads chrome.storage.local
    └── Renders risk level, threat bar, and warning list
```

---

## Permissions Used

| Permission | Why |
|---|---|
| `webNavigation` | Listen to navigation events to detect redirect chains |
| `tabs` | Identify which tab sent a message |
| `storage` | Save scan results so the popup can read them |

---

## Technologies

- JavaScript (ES2020)
- Chrome Extension APIs — Manifest V3
- `chrome.webNavigation` — server-side redirect detection
- `chrome.storage.local` — cross-context result sharing
- `chrome.runtime` — message passing between scripts
- `chrome.action` — badge text and color control

---

## Why I build this? Because I need to learn about:

- Browser extension architecture (content scripts, service workers, popups)
- Message passing between isolated extension contexts
- DOM inspection and form analysis
- URL parsing and pattern matching
- Real-world phishing detection techniques used by security products

---

## Limitations

- Does not query external threat intelligence APIs (e.g. Google Safe Browsing)
- Brand list is static —> can be expanded in `content.js`
- Detection is heuristic-based, not ML-based
- Does not inspect HTTPS certificate validity

---

## License

What License? Anybody can make it.

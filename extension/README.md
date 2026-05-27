# ThreatShield Browser Extension (Phase 2)

This directory contains the Chrome Extension frontend code for **ThreatShield**. It monitors visited website URLs, runs scans via the backend threat APIs, displays real-time security alerts, and injects banners onto flagged pages.

## 📁 Extension Structure
```text
extension/
├── manifest.json            # Manifest V3 configuration (permissions, background worker)
├── assets/                  # Cyber shield icons (16px, 48px, 128px)
├── background/
│   └── background.js        # Service Worker tracking active navigation & scanning events
├── content/
│   └── content.js           # Content Script injecting safe warning banners (CWE-79 protected)
├── popup/
│   ├── popup.html           # Dashboard popup markup
│   ├── popup.js             # UI refresh trigger & DB feed integration
│   └── popup.css            # Dark cybersecurity glassmorphism stylesheet
├── services/
│   └── api.js               # Network abort/retries API wrapper for FastAPI
└── utils/
    └── helpers.js           # URL parsing & digital clock format helpers
```

---

## 🛠️ Chrome Installation Guide

To load this extension locally in Google Chrome or Microsoft Edge, follow these steps:

1. **Open Extension Management Page**:
   - In Google Chrome, navigate to: `chrome://extensions/`
   - In Microsoft Edge, navigate to: `edge://extensions/`

2. **Enable Developer Mode**:
   - Toggle the **Developer mode** switch in the top-right corner of the extensions page.

3. **Load the Unpacked Directory**:
   - Click the **Load unpacked** button in the top-left corner.
   - Select the `extension/` folder located in: `c:\Users\chinm\Desktop\ThreatShielf\extension`

4. **Verify Loading**:
   - The **ThreatShield Browser Protection** extension card will appear in your list.
   - Pin the ThreatShield icon (the green cyber-shield) to your browser toolbar for quick access.

---

## 🚦 Verification and End-to-End Testing

### Step 1: Run the Backend
Ensure the FastAPI server is running in the background. If it isn't running, start it:
```powershell
cd c:\Users\chinm\Desktop\ThreatShielf\backend
.\venv\Scripts\Activate.ps1
uvicorn app:app --reload
```

### Step 2: Check Connection Status
* Click the ThreatShield extension icon on your toolbar.
* If the FastAPI server is online, the badge in the top-right corner of the popup will display **Online (X.XXms DB RTT)** in green.
* If the server is offline or unreachable, it will display **Offline / Connection Error** in red.

### Step 3: Test Web Security Scanning (E2E)
We can test the threat scanner by triggering specific attack signatures in our web browser:

1. **Verify Safe Site**:
   - Navigate to a benign site (e.g. `https://example.com`).
   - Open the popup. It will display a **0/100** risk score and a green **BENIGN** verdict.

2. **Verify SQL Injection Signature Scan**:
   - Navigate to any site and append a SQL injection query parameter to the URL:
     `https://example.com/?query=union%20select%20*%20from%20users`
   - The background worker will intercept the navigation, pass the payload, and flag the site as malicious.
   - A red **DANGEROUS** banner will instantly slide in at the top of the webpage reading:
     `ThreatShield BLOCKADE: Critical threat [SQL_INJECTION] detected! Risk Score: 70/100...`
   - Open the popup. The risk ring will update to a red/orange dial displaying **70/100** and verdict **SQL_INJECTION**. The "Triggered Rules" card will list `SQLI_SIGNATURE_MATCH` and `HIGH_PAYLOAD_ENTROPY`.

3. **Verify Cross-Site Scripting (XSS) Signature Scan**:
   - Navigate to a site and append an inline handler pattern:
     `https://example.com/?search=onload=confirm(1)`
   - The background worker will flag it as suspicious.
   - An amber **SUSPICIOUS** alert will be logged.

4. **Verify SQLite Log Persistence**:
   - The popup's bottom panel is connected to the backend's `/threats/alerts` API.
   - As you trigger warning banners, the alerts are logged in the SQLite database.
   - Open the popup to see your recent scan incidents updated dynamically in the **RECENT THREAT ALERTS (SQLITE)** feed at the bottom!

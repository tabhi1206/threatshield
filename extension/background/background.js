/**
 * ThreatShield Browser Extension - Background Service Worker (Manifest V3)
 * Operates as the central control plane, intercepting browser events.
 * 
 * CYBERSECURITY ARCHITECTURE: SERVICE WORKER LIFECYCLE
 * Chrome Extension Service Workers are event-driven and ephemeral.
 * They run only when responding to browser events (like page navigation, messages, or alarms)
 * and automatically shut down during idle periods to conserve CPU/RAM.
 * Because of this, in-memory variables (like local maps) can be destroyed at any moment.
 * We must rely on `chrome.storage.local` to persist the scanning state of active tabs.
 */

// Import dependent scripts. In Manifest V3 service workers, we use importScripts.
importScripts("../utils/helpers.js", "../services/api.js");

// Keep track of internal scanning state to prevent redundant queries
const scanningInProgress = new Set();

/**
 * Entrypoint: Listen for completed tab loads or redirects.
 * Fires when a navigation is successfully completed.
 */
chrome.webNavigation.onCompleted.addListener((details) => {
  // Ignore frames inside websites (e.g. advertisements/iframes) to focus on top-level navigation
  if (details.frameId !== 0) return;
  
  handleUrlTransition(details.tabId, details.url);
});

/**
 * Listener for tab updates (e.g., when a user types a new URL and presses enter).
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only trigger when the URL is officially resolved
  if (changeInfo.url) {
    handleUrlTransition(tabId, changeInfo.url);
  }
});

/**
 * Handles tab transitions and triggers the threat analysis workflow.
 * 
 * @param {number} tabId - Unique ID of the browser tab.
 * @param {string} url - The URL loaded in the tab.
 */
async function handleUrlTransition(tabId, url) {
  // Skip non-web protocols (e.g. chrome://, file://, extension settings, about:blank)
  const parsed = parseUrlComponents(url);
  if (!parsed.isValid || (parsed.protocol !== "http:" && parsed.protocol !== "https:")) {
    console.log(`[ThreatShield Background] Skipping internal/non-web protocol: ${url}`);
    return;
  }

  // De-duplicate concurrent scan requests for the same URL in the same tab
  const scanKey = `${tabId}-${url}`;
  if (scanningInProgress.has(scanKey)) return;
  scanningInProgress.add(scanKey);

  console.log(`[ThreatShield Background] Event intercepted. Threat scan initiated for: ${parsed.hostname}`);

  // 1. Write "scanning" state to storage so popup can reflect active work immediately
  const initialScanState = {
    tabId: tabId,
    url: url,
    expanded_url: url,
    hostname: parsed.hostname,
    status: "SCANNING",
    threat_score: 0,
    threat_type: "PENDING",
    severity: "INFO",
    is_malicious: false,
    matched_rules: [],
    explanations: [],
    timestamp: Date.now()
  };
  
  await saveScanState(tabId, initialScanState);
  broadcastStateToPopup(initialScanState);

  try {
    // 2. Transmit payload to FastAPI threat analysis API
    const result = await analyzeURL(url);

    // 3. Formulate the final threat report
    const scanResultState = {
      tabId: tabId,
      url: url,
      expanded_url: result.expanded_url || url,
      hostname: parsed.hostname,
      status: "COMPLETED",
      threat_score: result.threat_score,
      threat_type: result.threat_type,
      severity: result.severity,
      is_malicious: result.is_malicious,
      matched_rules: result.matched_rules,
      explanations: result.explanations || [],
      timestamp: Date.now()
    };

    // 4. Save results to local storage
    await saveScanState(tabId, scanResultState);
    broadcastStateToPopup(scanResultState);

    // 5. If site triggers threat thresholds, instruct the Content Script to show warning banner
    if (result.threat_score > 0) {
      chrome.tabs.sendMessage(tabId, {
        action: "SHOW_WARNING_BANNER",
        threatData: result
      }, (response) => {
        // Handle runtime errors if content script is not yet injected
        if (chrome.runtime.lastError) {
          console.warn("[ThreatShield Background] Content script warning banner injection failed (tab may not be fully ready):", chrome.runtime.lastError.message);
        } else {
          console.log("[ThreatShield Background] Content banner injection response:", response);
        }
      });
    }

  } catch (err) {
    console.error(`[ThreatShield Background] Scanning exception for ${url}:`, err);
  } finally {
    // Release de-duplication lock
    scanningInProgress.delete(scanKey);
  }
}

/**
 * Persists tab scanning state inside chrome.storage.local.
 * 
 * @param {number} tabId - Unique tab key.
 * @param {object} state - The scan log payload.
 */
function saveScanState(tabId, state) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [`tab_${tabId}`]: state }, () => {
      resolve();
    });
  });
}

/**
 * Dispatches live status updates to popup runtime listeners.
 * 
 * @param {object} state - Live scanning details.
 */
function broadcastStateToPopup(state) {
  chrome.runtime.sendMessage({
    action: "STATUS_UPDATE",
    state: state
  }, () => {
    // Silence error triggered if popup is closed and not listening
    const err = chrome.runtime.lastError;
  });
}

/**
 * Handle incoming message requests from the Popup or Content scripts.
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "GET_TAB_STATUS") {
    // Read state from storage and send back to popup
    chrome.storage.local.get([`tab_${request.tabId}`], (result) => {
      const state = result[`tab_${request.tabId}`] || null;
      sendResponse({ state: state });
    });
    return true; // Keep message channel open for asynchronous sendResponse
  }
});

/**
 * ThreatShield Browser Extension - Content Script
 * Executes within the context of active web pages. Can read and modify the DOM.
 * 
 * CYBERSECURITY CONCEPT: ISOLATED WORLDS
 * Content scripts run in an "Isolated World" execution environment.
 * They share the raw DOM with the host web page but have isolated JavaScript variables,
 * objects, and APIs. This prevents scripts on the host page from tampering with the
 * extension's internal state or hijacking its communication tunnels.
 */

// Listener to capture alerts sent from the background service worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "SHOW_WARNING_BANNER") {
    injectSecurityBanner(message.threatData);
    sendResponse({ status: "BANNER_INJECTED" });
  }
  return true;
});

/**
 * Creates and injects a warning banner at the top of the host webpage.
 * 
 * CYBERSECURITY RULE: PREVENT DOM-BASED XSS (CWE-79)
 * When injecting HTML elements into arbitrary web pages, developers must NEVER use
 * unchecked string concatenation or `element.innerHTML` with untrusted data (like URLs,
 * headers, or threat verdicts). Attackers could exploit this to trigger secondary XSS.
 * 
 * We mitigate this by using:
 * 1. `document.createElement` to programmatically build elements.
 * 2. `element.textContent` to write text values, ensuring string values are parsed strictly
 *    as text nodes rather than executable code.
 * 
 * @param {object} threatData - Security parameters returned by the threat engine.
 */
function injectSecurityBanner(threatData) {
  // Prevent duplicate banners from cluttering the screen
  const existingBanner = document.getElementById("threatshield-warning-banner");
  if (existingBanner) {
    existingBanner.remove();
  }

  const { is_malicious, threat_score, threat_type, severity } = threatData;
  
  // Decide state and color palettes based on Phase 3 risk profile
  let state = "SAFE";
  let primaryColor = "#10b981"; // Emerald Green
  let textColor = "#ffffff";
  let message = "ThreatShield: This website has been scanned and verified as safe.";

  if (severity === "DANGEROUS") {
    state = "DANGEROUS";
    primaryColor = "#ef4444"; // Vivid Red
    message = `ThreatShield BLOCKADE: Critical threat [${threat_type}] detected! Risk Score: ${threat_score}/100. We recommend leaving this site immediately.`;
  } else if (severity === "HIGH RISK") {
    state = "HIGH RISK";
    primaryColor = "#f97316"; // Vibrant Orange
    message = `ThreatShield BLOCKADE: High-risk phishing or malicious domain detected! Risk Score: ${threat_score}/100. Do not input any credentials.`;
  } else if (severity === "SUSPICIOUS") {
    state = "SUSPICIOUS";
    primaryColor = "#eab308"; // Amber Yellow
    message = `ThreatShield WARNING: Suspicious activity/metadata [${threat_type}] flagged on this host (Score: ${threat_score}/100). Exercise caution.`;
  } else if (severity === "LOW RISK") {
    state = "LOW RISK";
    primaryColor = "#06b6d4"; // Cyan
    message = `ThreatShield INFO: Low risk scanning flags [${threat_type}] detected (Score: ${threat_score}/100).`;
  }

  // If the site is safe, do not inject banner to keep user experience clean
  if (state === "SAFE") {
    console.log("[ThreatShield Content] Site scanned. Status: SAFE.");
    return;
  }

  // programmatically construct the banner element
  const banner = document.createElement("div");
  banner.id = "threatshield-warning-banner";
  
  // Apply sandboxed inline styles to prevent host website CSS from breaking our design
  // We use reset properties to isolate our banner styles.
  Object.assign(banner.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100%",
    backgroundColor: primaryColor,
    color: textColor,
    fontFamily: "'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
    fontSize: "14px",
    fontWeight: "600",
    padding: "12px 24px",
    zIndex: "999999999", // Ensure it sits on top of all Z-indexed items
    boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    boxSizing: "border-box",
    transition: "transform 0.3s ease-in-out",
    borderBottom: "2px solid rgba(0,0,0,0.15)"
  });

  // Create text container element
  const textNode = document.createElement("span");
  textNode.style.display = "flex";
  textNode.style.alignItems = "center";
  textNode.style.gap = "8px";
  
  // Create status badge icon
  const badge = document.createElement("span");
  badge.textContent = `[${state}]`;
  badge.style.padding = "2px 6px";
  badge.style.backgroundColor = "rgba(0,0,0,0.2)";
  badge.style.borderRadius = "4px";
  badge.style.fontSize = "12px";

  // Use textContent to safely embed text payload
  const infoText = document.createElement("span");
  infoText.textContent = message;

  textNode.appendChild(badge);
  textNode.appendChild(infoText);
  banner.appendChild(textNode);

  // Programmatically create the Dismiss / Close Button
  const closeButton = document.createElement("button");
  closeButton.textContent = "Dismiss Warning";
  Object.assign(closeButton.style, {
    backgroundColor: "transparent",
    border: "1px solid rgba(255,255,255,0.6)",
    color: "#ffffff",
    borderRadius: "4px",
    padding: "4px 12px",
    cursor: "pointer",
    fontSize: "12px",
    fontWeight: "bold",
    marginLeft: "16px",
    transition: "all 0.2s"
  });

  // Hover animations
  closeButton.onmouseover = () => {
    closeButton.style.backgroundColor = "rgba(255,255,255,0.15)";
  };
  closeButton.onmouseout = () => {
    closeButton.style.backgroundColor = "transparent";
  };

  // Close event listener
  closeButton.addEventListener("click", () => {
    banner.style.transform = "translateY(-100%)";
    setTimeout(() => banner.remove(), 300);
  });

  banner.appendChild(closeButton);

  // Inject into document body
  // To avoid breaking host layout (some sites use absolute positioning on body),
  // we append it as the final child of document.documentElement (html tag)
  document.documentElement.appendChild(banner);
  
  // Shift host page content down to prevent banner from overlaying navigation bars
  // This is a layout helper but can be custom fit depending on host needs.
}

/**
 * ThreatShield Browser Extension - Popup Script
 * Coordinates UI updates, pulls current tab status, and queries the backend logs.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const activeTab = await getActiveTab();
  
  // UI Elements
  const connectionBadge = document.getElementById("connection-badge");
  const connectionText = document.getElementById("connection-text");
  const hostnameDisplay = document.getElementById("site-hostname");
  const timestampDisplay = document.getElementById("scan-timestamp");
  const riskScoreDisplay = document.getElementById("risk-score");
  const threatVerdictDisplay = document.getElementById("threat-verdict");
  const progressBar = document.getElementById("progress-bar");
  const engineResponseDisplay = document.getElementById("engine-response");
  const rulesList = document.getElementById("triggered-rules-list");
  const rescanBtn = document.getElementById("rescan-btn");
  const logsList = document.getElementById("recent-logs-list");

  // New UI Elements for Redirect Expansion
  const expandedUrlBox = document.getElementById("expanded-url-box");
  const expandedUrlDisplay = document.getElementById("expanded-url");

  // SVG ring circumference (r=50 -> 2 * PI * 50 = 314.16)
  const RING_CIRCUMFERENCE = 314.16;

  // Initialize checks
  await verifyBackendConnectivity();
  await refreshActiveTabStatus();
  await loadDatabaseAlertsFeed();

  // Set up Event Listeners
  rescanBtn.addEventListener("click", triggerManualRescan);

  // Listen for live scan status broadcasts from the background service worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "STATUS_UPDATE" && activeTab && message.state.tabId === activeTab.id) {
      updateDashboardUI(message.state);
    }
  });

  /**
   * Identifies the tab currently focused by the user.
   */
  function getActiveTab() {
    return new Promise((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        resolve(tabs[0] || null);
      });
    });
  }

  /**
   * Hits the health check router of our FastAPI backend to update the status indicator.
   */
  async function verifyBackendConnectivity() {
    const health = await checkBackendHealth();
    
    if (health.status === "HEALTHY") {
      connectionBadge.className = "connection-status online";
      connectionText.textContent = `Online (${health.services.database.latency_ms}ms DB RTT)`;
      engineResponseDisplay.textContent = "FastAPI Operational";
    } else {
      connectionBadge.className = "connection-status offline";
      connectionText.textContent = "Offline / Connection Error";
      engineResponseDisplay.textContent = "Unreachable";
    }
  }

  /**
   * Retrieves stored scan details for the active tab from background storage.
   */
  async function refreshActiveTabStatus() {
    if (!activeTab) return;
    
    const url = activeTab.url;
    const parsed = parseUrlComponents(url);
    
    // Set default hostname layout
    hostnameDisplay.textContent = parsed.hostname;

    // Send query to background script to get active tab scan data
    chrome.runtime.sendMessage({
      action: "GET_TAB_STATUS",
      tabId: activeTab.id
    }, (response) => {
      if (response && response.state) {
        updateDashboardUI(response.state);
      } else {
        // If no scan exists (e.g. internal pages), set clean default layout
        const defaultState = {
          hostname: parsed.hostname,
          url: url,
          expanded_url: url,
          status: "COMPLETED",
          threat_score: 0,
          threat_type: "BENIGN",
          severity: "SAFE",
          is_malicious: false,
          matched_rules: [],
          explanations: [],
          timestamp: Date.now()
        };
        updateDashboardUI(defaultState);
      }
    });
  }

  /**
   * Redraws the popup HTML dashboard metrics.
   * 
   * @param {object} state - Active scan status payload.
   */
  function updateDashboardUI(state) {
    if (!state) return;

    // 1. Update text fields
    hostnameDisplay.textContent = state.hostname;
    timestampDisplay.textContent = `Last scanned: ${formatTimestamp(state.timestamp)}`;
    riskScoreDisplay.textContent = state.threat_score;

    // 1b. Handle Expanded URL Destination display if redirect chain expanded the link
    if (state.expanded_url && state.expanded_url !== state.url) {
      expandedUrlBox.style.display = "block";
      try {
        const parsedExp = new URL(state.expanded_url);
        expandedUrlDisplay.textContent = parsedExp.hostname + (parsedExp.pathname !== "/" ? truncateText(parsedExp.pathname, 20) : "");
      } catch (e) {
        expandedUrlDisplay.textContent = truncateText(state.expanded_url, 35);
      }
    } else {
      expandedUrlBox.style.display = "none";
    }

    // 2. Adjust color gauge ring
    const strokeOffset = RING_CIRCUMFERENCE - (RING_CIRCUMFERENCE * state.threat_score) / 100;
    progressBar.style.strokeDashoffset = strokeOffset;

    // Set gauge stroke color dynamically (aligned with Phase 3 classifications)
    if (state.threat_score >= 85) {
      progressBar.style.stroke = "var(--color-red)";       // DANGEROUS
    } else if (state.threat_score >= 60) {
      progressBar.style.stroke = "var(--color-orange)";    // HIGH RISK
    } else if (state.threat_score >= 35) {
      progressBar.style.stroke = "var(--color-orange)";    // SUSPICIOUS
    } else if (state.threat_score >= 11) {
      progressBar.style.stroke = "var(--color-cyan)";      // LOW RISK
    } else {
      progressBar.style.stroke = "var(--color-green)";     // SAFE
    }

    // 3. Update Verdict and class badges
    threatVerdictDisplay.textContent = state.status === "SCANNING" ? "SCANNING..." : state.severity;
    threatVerdictDisplay.className = "verdict-text";

    if (state.status === "SCANNING") {
      threatVerdictDisplay.classList.add("verdict-suspicious");
    } else if (state.severity === "DANGEROUS" || state.severity === "HIGH RISK") {
      threatVerdictDisplay.classList.add("verdict-dangerous");
    } else if (state.severity === "SUSPICIOUS") {
      threatVerdictDisplay.classList.add("verdict-suspicious");
    } else {
      threatVerdictDisplay.classList.add("verdict-safe");
    }

    // 4. Render triggered rules / explanations list
    rulesList.innerHTML = "";
    const analysisItems = state.explanations && state.explanations.length > 0 ? state.explanations : state.matched_rules;
    
    if (analysisItems && analysisItems.length > 0) {
      analysisItems.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item;
        rulesList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.className = "empty-rules";
      li.textContent = "No vulnerabilities detected.";
      rulesList.appendChild(li);
    }
  }

  /**
   * Manually instructs the extension background script to re-run the scan.
   */
  async function triggerManualRescan() {
    if (!activeTab) return;
    
    // Set UI to loading state
    riskScoreDisplay.textContent = "--";
    progressBar.style.strokeDashoffset = RING_CIRCUMFERENCE;
    threatVerdictDisplay.textContent = "SCANNING...";
    threatVerdictDisplay.className = "verdict-text verdict-suspicious";
    expandedUrlBox.style.display = "none";
    
    // Injects reload actions
    chrome.runtime.sendMessage({
      action: "GET_TAB_STATUS", // Queries background to re-trigger analysis
      tabId: activeTab.id
    });
    
    // Fast reconnect to refresh status
    setTimeout(async () => {
      await refreshActiveTabStatus();
      await loadDatabaseAlertsFeed();
      await verifyBackendConnectivity();
    }, 1500);
  }

  /**
   * Fetches logged threat history from the central FastAPI database.
   */
  async function loadDatabaseAlertsFeed() {
    logsList.innerHTML = "";
    
    try {
      const reports = await fetchThreatReports();
      
      if (!reports || reports.length === 0) {
        const li = document.createElement("li");
        li.className = "log-empty";
        li.textContent = "Database log feed is currently empty.";
        logsList.appendChild(li);
        return;
      }

      reports.forEach(report => {
        const li = document.createElement("li");
        li.className = "log-item";

        // Create log description elements
        const detailsDiv = document.createElement("div");
        detailsDiv.className = "log-details";

        const typeSpan = document.createElement("span");
        typeSpan.className = "log-type";
        typeSpan.textContent = report.target_endpoint;

        const ipSpan = document.createElement("span");
        ipSpan.className = "log-ip";
        ipSpan.textContent = `${report.source_ip} • ${formatTimestamp(new Date(report.timestamp).getTime())}`;

        detailsDiv.appendChild(typeSpan);
        detailsDiv.appendChild(ipSpan);

        // Normalize severity to match css formatting rules (e.g. "HIGH RISK" -> "high-risk")
        const cssSeverity = report.severity.toLowerCase().replace(" ", "-");

        // Create threat badge level
        const badgeSpan = document.createElement("span");
        badgeSpan.className = `log-badge badge-${cssSeverity}`;
        badgeSpan.textContent = report.severity;

        li.appendChild(detailsDiv);
        li.appendChild(badgeSpan);
        logsList.appendChild(li);
      });
    } catch (err) {
      const li = document.createElement("li");
      li.className = "log-empty";
      li.textContent = "Failed to load central threat logs.";
      logsList.appendChild(li);
    }
  }
});

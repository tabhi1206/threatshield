/**
 * ThreatShield Browser Extension - Backend API Service
 * Handles HTTP communications with the FastAPI backend engine.
 */

// Configuration constants
const BACKEND_CONFIG = {
  BASE_URL: "https://threatshield-jinq.onrender.com",
  API_PREFIX: "/api/v1",
  TIMEOUT_MS: 5000,
  MAX_RETRIES: 2
};

/**
 * Enhanced fetch wrapper featuring custom timeouts and automatic retries.
 * 
 * CYBERSECURITY CONSIDERATION:
 * Network timeouts prevent the extension from stalling browser threads when the 
 * backend is under heavy load or subject to DDoS. Exponential backoff/retries ensure
 * scanning continuity without overloading server connections.
 * 
 * @param {string} endpoint - Path appending the base URL.
 * @param {object} options - Fetch standard options.
 * @param {number} retryCount - Current retry attempt tracker.
 * @returns {Promise<Response>} Fetch Response object.
 */
async function fetchWithTimeoutAndRetry(endpoint, options = {}, retryCount = 0) {
  const url = `${BACKEND_CONFIG.BASE_URL}${BACKEND_CONFIG.API_PREFIX}${endpoint}`;
  
  // Implement AbortController for network timeout enforcement
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), BACKEND_CONFIG.TIMEOUT_MS);
  
  const fetchOptions = {
    ...options,
    signal: controller.signal,
    headers: {
      "Content-Type": "application/json",
      ...options.headers
    }
  };

  try {
    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    
    // Check if error is timeout (AbortError) or standard connection issue
    const isTimeout = error.name === 'AbortError';
    
    if (retryCount < BACKEND_CONFIG.MAX_RETRIES) {
      console.warn(`[ThreatShield API] Retrying endpoint ${endpoint} (Attempt ${retryCount + 1}/${BACKEND_CONFIG.MAX_RETRIES}). Reason: ${isTimeout ? 'Timeout' : error.message}`);
      
      // Delay before retry (exponential backoff)
      const delay = Math.pow(2, retryCount) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
      
      return fetchWithTimeoutAndRetry(endpoint, options, retryCount + 1);
    }
    
    throw new Error(`API Connection Failed: ${error.message} (Timeout: ${isTimeout})`);
  }
}

/**
 * Checks FastAPI backend status by hitting the health check router.
 * 
 * @returns {Promise<object>} Status object representing server liveness.
 */
async function checkBackendHealth() {
  try {
    const response = await fetchWithTimeoutAndRetry("/health", { method: "GET" });
    if (!response.ok) throw new Error(`HTTP Status ${response.status}`);
    return await response.json();
  } catch (error) {
    return {
      status: "UNREACHABLE",
      error: error.message
    };
  }
}

/**
 * Sends a captured URL payload to the threat detection engine for assessment.
 * 
 * INTEGRATION / CYBERSECURITY LOGIC:
 * Maps URL attributes to the backend's ThreatScanRequest schema.
 * - 'source_ip' represents the client IP. Since the extension runs locally in the browser,
 *   we supply loopback IPs or fetch external IPs.
 * - 'target_endpoint' represents the active host site being evaluated.
 * - 'payload' carries the full URL string to check for nested SQLi, XSS, or Command Injection scripts in query args.
 * 
 * @param {string} tabUrl - The full web address of the active tab.
 * @returns {Promise<object>} Parsed scan analysis results.
 */
async function analyzeURL(tabUrl) {
  try {
    const urlObj = new URL(tabUrl);
    
    // Construct the payload matching the FastAPI backend ThreatScanRequest schema
    const scanRequestPayload = {
      source_ip: "127.0.0.1", // Standard local placeholder. Real IP can be retrieved from STUN/health checks.
      target_endpoint: urlObj.hostname, // Web site domain (e.g. malicious-site.com)
      payload: tabUrl // The raw URL containing parameters to scan for signature matching
    };

    const response = await fetchWithTimeoutAndRetry("/threats/scan", {
      method: "POST",
      body: JSON.stringify(scanRequestPayload)
    });

    if (!response.ok) {
      throw new Error(`HTTP Scan failure status ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("[ThreatShield API] Scanning failure:", error);
    // Graceful default bypass if the threat scanner fails, preventing browser blockades
    return {
      is_malicious: false,
      threat_score: 0,
      threat_type: "SCAN_ERROR",
      severity: "INFO",
      matched_rules: ["SCAN_FAILURE_FALLBACK"]
    };
  }
}

/**
 * Queries the database for logged threat history.
 * Used for building audit histories in the popup/extension interface.
 * 
 * @returns {Promise<Array>} List of logged alerts.
 */
async function fetchThreatReports() {
  try {
    const response = await fetchWithTimeoutAndRetry("/threats/alerts?limit=10", {
      method: "GET"
    });
    if (!response.ok) throw new Error(`HTTP Status ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error("[ThreatShield API] Fetch alerts failure:", error);
    return [];
  }
}

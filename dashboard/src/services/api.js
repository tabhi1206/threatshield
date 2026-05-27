// API abstraction for ThreatShield dashboard
// Handles all analytics and health API calls securely

const ENV_API_BASE =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL) || '';

const API_BASE_CANDIDATES = [
  ENV_API_BASE,
  'https://threatshield-jinq.onrender.com/api/v1',
].filter(Boolean);

let resolvedApiBase = null;

function buildUrl(base, endpoint) {
  const normalizedBase = base.endsWith('/') ? base.slice(0, -1) : base;
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${normalizedBase}${normalizedEndpoint}`;
}

async function fetchFromBase(base, endpoint, options = {}) {
  const headers = {
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...(options.headers || {}),
  };

  const res = await fetch(buildUrl(base, endpoint), {
    ...options,
    headers,
  });

  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
}

// Helper to fetch and handle errors
async function fetchAPI(endpoint, options = {}) {
  if (resolvedApiBase) {
    return fetchFromBase(resolvedApiBase, endpoint, options);
  }

  let lastError = null;
  for (const base of API_BASE_CANDIDATES) {
    try {
      const data = await fetchFromBase(base, endpoint, options);
      resolvedApiBase = base;
      return data;
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error('API unavailable');
}

export const getSummary = () => fetchAPI('/analytics/summary');
export const getTrends = () => fetchAPI('/analytics/trends');
export const getSeverityDist = () => fetchAPI('/analytics/severity-distribution');
export const getRecentIncidents = () => fetchAPI('/analytics/recent');
export const getBackendHealth = () => fetchAPI('/health');
export const scanUrl = (url) => fetchAPI('/threats/scan', { 
  method: 'POST', 
  body: JSON.stringify({ 
    source_ip: '127.0.0.1',
    target_endpoint: '/dashboard/scan',
    payload: url
  })
});

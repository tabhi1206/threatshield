/**
 * ThreatShield Browser Extension - Utility Helpers
 * Contains reusable, pure JavaScript helper functions.
 */

/**
 * Extracts key domain metadata from a raw URL.
 * 
 * CYBERSECURITY RELEVANCE:
 * Attackers leverage techniques like homograph attacks (using similar Unicode characters),
 * sub-domain spoofing (e.g., login.paypal.com.attacker.com), or abnormal protocols
 * (e.g., ftp://, data://) to mislead victims. Parsing these parameters isolates
 * the domain scope for targeted reputation checks.
 * 
 * @param {string} urlString - The complete URL string.
 * @returns {object} Parsed URL components.
 */
function parseUrlComponents(urlString) {
  try {
    const url = new URL(urlString);
    return {
      isValid: true,
      href: url.href,
      protocol: url.protocol, // e.g., 'https:' or 'http:'
      hostname: url.hostname, // e.g., 'example.com'
      pathname: url.pathname, // e.g., '/index.html'
      search: url.search,     // Query parameters containing potential XSS/SQLi vectors
      hash: url.hash          // Client-side routing metadata
    };
  } catch (error) {
    // If the URL fails parsing (e.g., chrome:// settings or file:// paths), return invalid
    return {
      isValid: false,
      href: urlString,
      protocol: '',
      hostname: 'Unknown/Internal',
      pathname: '',
      search: '',
      hash: ''
    };
  }
}

/**
 * Formats a Unix timestamp into a readable digital clock layout.
 * Used for displaying scan runtimes.
 * 
 * @param {number} timestamp - Epoch timestamp in milliseconds.
 * @returns {string} HH:MM:SS format representation.
 */
function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${hours}:${minutes}:${seconds}`;
}

/**
 * Truncates long string values safely to prevent layout breaking or text overflows.
 * 
 * @param {string} text - The input text.
 * @param {number} maxLength - Character threshold.
 * @returns {string} Truncated string appended with ellipses.
 */
function truncateText(text, maxLength = 50) {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
}

// Export functions for ES Module environment or expose globally in service workers
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    parseUrlComponents,
    formatTimestamp,
    truncateText
  };
}

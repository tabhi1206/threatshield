import React, { useMemo, useState } from 'react';
import { scanUrl } from '../services/api';

const getStatusBadge = (result) => {
  const severity = result?.severity?.toString()?.toUpperCase();
  const isMalicious = result?.is_malicious || severity === 'DANGEROUS' || severity === 'HIGH RISK' || severity === 'MALICIOUS';

  if (isMalicious) {
    return { label: 'Malicious', className: 'scan-chip-danger' };
  }
  if (severity === 'SUSPICIOUS' || severity === 'LOW RISK') {
    return { label: 'Suspicious', className: 'scan-chip-warning' };
  }
  return { label: 'Safe', className: 'scan-chip-safe' };
};

const getScoreColor = (score) => {
  if (score >= 85) return '#ff4c6d';
  if (score >= 60) return '#ffb347';
  if (score >= 35) return '#06b6d4';
  return '#00e676';
};

const formatTimestamp = (value) => {
  if (!value) return null;
  const parsed = typeof value === 'number' ? new Date(value) : new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toLocaleString();
};

function ManualThreatScan() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const statusBadge = useMemo(() => getStatusBadge(result || {}), [result]);
  const score = useMemo(() => {
    if (!result) return 0;
    return Number(result.threat_score ?? result.risk_score ?? result.score ?? 0);
  }, [result]);
  const indicators = useMemo(() => {
    if (!result) return [];
    return result.reasons || result.indicators || result.matched_rules || result.explanations || [];
  }, [result]);
  const classification = result?.severity || result?.threat_type || result?.classification || 'Unknown';
  const scannedAt = formatTimestamp(result?.timestamp ?? result?.scanned_at ?? result?.scan_time ?? result?.created_at);

  const validateUrl = (value) => {
    const trimmed = value.trim();
    if (!trimmed) return false;
    try {
      const parsed = new URL(trimmed);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  };

  const handleScan = async () => {
    if (!validateUrl(url)) {
      setError('Invalid URL. Please enter a valid https:// or http:// address.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await scanUrl(url.trim());
      setResult(data);
    } catch (err) {
      setError(err?.message || 'Backend unavailable. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass manual-scan-card">
      <div className="manual-scan-header">
        <div>
          <h2>Manual Threat Scan</h2>
          <p className="manual-scan-description">
            Enter a URL and scan it directly using the ThreatShield backend engine.
          </p>
        </div>
        <span className={`scan-chip ${statusBadge.className}`}>{statusBadge.label}</span>
      </div>

      <div className="manual-scan-controls">
        <input
          type="text"
          className="manual-scan-input"
          placeholder="https://example.com"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          disabled={loading}
        />
        <button type="button" className="manual-scan-button" onClick={handleScan} disabled={loading || !url.trim()}>
          {loading ? 'Scanning…' : 'Scan'}
        </button>
      </div>

      {error && <div className="scan-error">{error}</div>}

      {result && (
        <div className="manual-scan-result">
          <div className="scan-summary-grid">
            <div className="scan-score-panel">
              <div className="scan-score-label">Threat Score</div>
              <div className="scan-score-value" style={{ color: getScoreColor(score) }}>
                {Number.isFinite(score) ? score : 'N/A'}
              </div>
            </div>
            <div className="scan-classification-panel">
              <div className="scan-field-label">Risk classification</div>
              <div className="scan-field-value">{classification}</div>
              <div className="scan-progress-track">
                <div className="scan-progress-bar" style={{ width: `${Math.min(100, Math.max(0, score))}%`, backgroundColor: getScoreColor(score) }} />
              </div>
            </div>
          </div>

          <div className="scan-meta-row">
            <span className="scan-meta-label">URL scanned:</span>
            <span className="scan-meta-value">{result.url || url.trim()}</span>
          </div>
          {scannedAt && (
            <div className="scan-meta-row">
              <span className="scan-meta-label">Scanned at:</span>
              <span className="scan-meta-value">{scannedAt}</span>
            </div>
          )}

          <div className="scan-indicators-card">
            <div className="scan-indicators-title">Indicators & Reasons</div>
            {indicators.length > 0 ? (
              <ul className="scan-indicator-list">
                {indicators.map((indicator, idx) => (
                  <li key={`indicator-${idx}`} className="scan-indicator-item">
                    {indicator}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="scan-no-indicators">No threat indicators were returned by the backend.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default ManualThreatScan;

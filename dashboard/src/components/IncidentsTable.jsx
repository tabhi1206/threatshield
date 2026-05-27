import React, { useState } from 'react';
import PropTypes from 'prop-types';
import Skeleton from '@mui/material/Skeleton';

// Helper for severity color
const severityColor = (sev) => {
  if (sev === 'Malicious') return 'text-danger';
  if (sev === 'Suspicious') return 'text-warning';
  if (sev === 'Safe') return 'text-safe';
  return 'text-muted';
};

// IncidentsTable: Shows recent incidents with filtering and search
function IncidentsTable({ incidents, loading }) {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('All');

  // Filter and search logic
  const filtered = incidents.filter((i) =>
    (filter === 'All' || i.severity === filter) &&
    (i.source_ip?.includes(search) || i.target?.includes(search) || i.expanded_url?.includes(search))
  );

  const formatRules = (rules) => {
    if (Array.isArray(rules)) return rules.join(', ');
    if (typeof rules === 'string') return rules;
    return '-';
  };

  return (
    <div className="glass" style={{ marginTop: 32, padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h3 style={{ margin: 0 }}>Recent Incidents</h3>
        <div>
          <select value={filter} onChange={e => setFilter(e.target.value)} style={{ marginRight: 12 }}>
            <option>All</option>
            <option>Malicious</option>
            <option>Suspicious</option>
            <option>Safe</option>
          </select>
          <input
            type="text"
            placeholder="Search IP, URL, Target..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ padding: 6, borderRadius: 8, border: '1px solid #333', background: '#23272f', color: '#fff' }}
          />
        </div>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: 'rgba(255,255,255,0.03)' }}>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Target</th>
              <th>Severity</th>
              <th>Rules</th>
              <th>Expanded URL</th>
              <th>Redirect Depth</th>
            </tr>
          </thead>
          <tbody>
            {loading
              ? Array.from({ length: 6 }).map((_, i) => (
                  <tr key={i}>
                    <td colSpan={7}><Skeleton variant="rectangular" width={"100%"} height={28} /></td>
                  </tr>
                ))
              : filtered.map((inc, idx) => (
                  <tr key={idx}>
                    <td>{inc.timestamp}</td>
                    <td>{inc.source_ip}</td>
                    <td>{inc.target}</td>
                    <td className={severityColor(inc.severity)} style={{ fontWeight: 600 }}>{inc.severity}</td>
                    <td>{formatRules(inc.rules)}</td>
                    <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>{inc.expanded_url}</td>
                    <td>{inc.redirect_depth}</td>
                  </tr>
                ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

IncidentsTable.propTypes = {
  incidents: PropTypes.array,
  loading: PropTypes.bool,
};

export default IncidentsTable;

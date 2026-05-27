import React from 'react';
import PropTypes from 'prop-types';
import Skeleton from '@mui/material/Skeleton';

// SummaryCards: Shows total scans, malicious, suspicious, safe, top rules, redirect stats, homograph counts, blacklist matches
function SummaryCards({ summary, loading }) {
  // Card data config
  const cards = [
    { label: 'Total Scans', value: summary?.total_scans, color: 'text-accent' },
    { label: 'Malicious', value: summary?.malicious, color: 'text-danger' },
    { label: 'Suspicious', value: summary?.suspicious, color: 'text-warning' },
    { label: 'Safe', value: summary?.safe, color: 'text-safe' },
    { label: 'Top Rule', value: summary?.top_rule, color: 'text-accent' },
    { label: 'Redirects', value: summary?.redirects, color: 'text-warning' },
    { label: 'Homographs', value: summary?.homographs, color: 'text-danger' },
    { label: 'Blacklist Hits', value: summary?.blacklist, color: 'text-danger' },
  ];

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, margin: '2rem 0' }}>
      {cards.map((card, idx) => (
        <div
          key={card.label}
          className={`glass ${card.color}`}
          style={{ flex: '1 1 180px', minWidth: 180, padding: 24, textAlign: 'center' }}
        >
          <div style={{ fontSize: 18, fontWeight: 500 }}>{card.label}</div>
          <div style={{ fontSize: 32, fontWeight: 700, marginTop: 8 }}>
            {loading ? <Skeleton variant="text" width={60} /> : card.value ?? '-'}
          </div>
        </div>
      ))}
    </div>
  );
}

SummaryCards.propTypes = {
  summary: PropTypes.object,
  loading: PropTypes.bool,
};

export default SummaryCards;

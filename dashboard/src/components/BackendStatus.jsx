import React from 'react';
import PropTypes from 'prop-types';

// BackendStatus: Shows backend health indicator
function BackendStatus({ status }) {
  let color = '#ffb347';
  let text = 'Checking backend...';
  const normalized = (status || '').toString().toLowerCase();
  if (normalized === 'ok' || normalized === 'healthy' || normalized === 'up') {
    color = '#00e676';
    text = 'Backend: Healthy';
  } else if (normalized === 'degraded') {
    color = '#ffb347';
    text = 'Backend: Degraded';
  } else if (normalized === 'error' || normalized === 'unreachable') {
    color = '#ff4c6d';
    text = 'Backend: Unreachable';
  }
  return (
    <div style={{ display: 'flex', alignItems: 'center', marginBottom: 16 }}>
      <span style={{ width: 12, height: 12, borderRadius: '50%', background: color, display: 'inline-block', marginRight: 8 }}></span>
      <span style={{ color }}>{text}</span>
    </div>
  );
}

BackendStatus.propTypes = {
  status: PropTypes.string,
};

export default BackendStatus;

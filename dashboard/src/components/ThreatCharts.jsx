import React from 'react';
import PropTypes from 'prop-types';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
} from 'chart.js';
import Skeleton from '@mui/material/Skeleton';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement
);

// ThreatCharts: Visualizes severity, trends, categories, redirect activity, detection frequency
function ThreatCharts({ trends, severityDist, loading }) {
  // Chart data config
  const severityData = {
    labels: severityDist?.labels || [],
    datasets: [
      {
        label: 'Detections',
        data: severityDist?.data || [],
        backgroundColor: [
          '#ff4c6d', // Malicious
          '#ffb347', // Suspicious
          '#00e676', // Safe
        ],
      },
    ],
  };

  const trendsData = {
    labels: trends?.dates || [],
    datasets: [
      {
        label: 'Threats Over Time',
        data: trends?.counts || [],
        borderColor: '#00e6a8',
        backgroundColor: 'rgba(0,230,168,0.2)',
        tension: 0.3,
        fill: true,
      },
    ],
  };

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 32, marginBottom: 32 }}>
      <div className="glass" style={{ flex: 1, minWidth: 320, padding: 24 }}>
        <h3>Severity Distribution</h3>
        {loading ? <Skeleton variant="rectangular" width={260} height={180} /> : <Doughnut data={severityData} />}
      </div>
      <div className="glass" style={{ flex: 2, minWidth: 320, padding: 24 }}>
        <h3>Threat Trends</h3>
        {loading ? <Skeleton variant="rectangular" width={400} height={180} /> : <Line data={trendsData} />}
      </div>
    </div>
  );
}

ThreatCharts.propTypes = {
  trends: PropTypes.object,
  severityDist: PropTypes.object,
  loading: PropTypes.bool,
};

export default ThreatCharts;

import React, { useEffect, useState } from 'react';
import SummaryCards from '../components/SummaryCards';
import ThreatCharts from '../components/ThreatCharts';
import IncidentsTable from '../components/IncidentsTable';
import BackendStatus from '../components/BackendStatus';
import ManualThreatScan from '../components/ManualThreatScan';
import { getBackendHealth, getRecentIncidents, getSeverityDist, getSummary, getTrends } from '../services/api';
import '../styles/global.css';

// Main dashboard page for ThreatShield analytics
function DashboardPage() {
  // State for summary, charts, incidents, and backend status
  const [summary, setSummary] = useState(null);
  const [trends, setTrends] = useState(null);
  const [severityDist, setSeverityDist] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [backendStatus, setBackendStatus] = useState('loading');
  const [loading, setLoading] = useState(true);

  // Fetch dashboard data from backend APIs
  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const statusData = await getBackendHealth();
      setBackendStatus(statusData.status || 'ok');
    } catch (err) {
      setBackendStatus('error');
    }

    try {
      const [summaryData, trendsData, severityData, incidentsData] = await Promise.all([
        getSummary(),
        getTrends(),
        getSeverityDist(),
        getRecentIncidents(),
      ]);
      setSummary(summaryData);
      setTrends(trendsData);
      setSeverityDist(severityData);
      setIncidents(incidentsData);
    } catch (err) {
      // Keep health indicator based on /health endpoint only.
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchDashboardData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass fade-in" style={{ margin: '2rem auto', maxWidth: 1200, padding: '2rem' }}>
      <BackendStatus status={backendStatus} />
      <h1 style={{ fontWeight: 700, fontSize: '2.2rem', marginBottom: 8 }}>ThreatShield Analytics Dashboard</h1>
      <SummaryCards summary={summary} loading={loading} />
      <ManualThreatScan />
      <ThreatCharts trends={trends} severityDist={severityDist} loading={loading} />
      <IncidentsTable incidents={incidents} loading={loading} />
    </div>
  );
}

export default DashboardPage;

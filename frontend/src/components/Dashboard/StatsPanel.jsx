import React from 'react';

const StatsPanel = ({ stats }) => {
  return (
    <div className="stats-grid">
      <div className="stat-card">
        <h3>Active Devices</h3>
        <div className="stat-value">{stats.active_devices || 0}</div>
      </div>
      <div className={`stat-card ${stats.high_risk > 0 ? 'danger-pulse' : ''}`}>
        <h3>High Risk Alerts</h3>
        <div className="stat-value warning">{stats.high_risk || 0}</div>
      </div>
      <div className="stat-card">
        <h3>Total Flows (24h)</h3>
        <div className="stat-value">{stats.flows_24h || 0}</div>
      </div>
      <div className="stat-card">
        <h3>Bandwidth</h3>
        <div className="stat-value small">
          {stats.bandwidth || "0 MB"}
        </div>
      </div>
    </div>
  );
};

export default StatsPanel;

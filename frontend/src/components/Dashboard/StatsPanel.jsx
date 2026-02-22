import React from 'react';

const StatsPanel = ({ stats }) => {
  return (
    <div className="stats-grid">
      <div className="stat-card">
        <h3>Active Devices</h3>
        <div className="stat-value">{stats.devices || 0}</div>
      </div>
      <div className={`stat-card ${stats.vpn_alerts > 0 ? 'danger-pulse' : ''}`}>
        <h3>VPN Alerts</h3>
        <div className="stat-value warning">{stats.vpn_alerts || 0}</div>
      </div>
      <div className="stat-card">
        <h3>Total Traffic</h3>
        <div className="stat-value">{stats.bandwidth || "0 MB"}</div>
      </div>
      <div className="stat-card">
        <h3>Upload / Download</h3>
        <div className="stat-value small">
          {stats.upload_speed || 0} / {stats.download_speed || 0}
        </div>
      </div>
    </div>
  );
};

export default StatsPanel;

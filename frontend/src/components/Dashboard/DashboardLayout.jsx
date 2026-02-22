import React from 'react';

const DashboardLayout = ({ children }) => {
  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h1>Netvisor Dashboard</h1>
        <div className="status-badge">Live</div>
      </header>
      <main className="dashboard-content">
        {children}
      </main>
    </div>
  );
};

export default DashboardLayout;

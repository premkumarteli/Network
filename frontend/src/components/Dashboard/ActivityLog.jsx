import React from 'react';

const ActivityLog = ({ logs }) => {
  return (
    <div className="activity-log">
      <h3>Live Activity</h3>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Source IP</th>
            <th>Domain</th>
            <th>Protocol</th>
            <th>Size</th>
          </tr>
        </thead>
        <tbody>
          {logs.length === 0 ? (
            <tr>
              <td colspan="5" className="empty-state">Listening for traffic...</td>
            </tr>
          ) : (
            logs.map((log, index) => (
              <tr key={index} className="fade-in">
                <td className="mono muted">{log.time}</td>
                <td className="mono primary">{log.src_ip}</td>
                <td>{log.domain}</td>
                <td><span className="badge">{log.protocol}</span></td>
                <td className="mono">{log.size}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};

export default ActivityLog;

import React from 'react';

const DeviceTable = ({ devices }) => {
  return (
    <div className="activity-log">
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>MAC Address</th>
            <th>Risk Level</th>
            <th>Last Seen</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {devices.length === 0 ? (
            <tr>
              <td colSpan="6" className="empty-state">No devices found.</td>
            </tr>
          ) : (
            devices.map((device, index) => (
              <tr key={index} className="fade-in">
                <td className="mono primary">{device.ip}</td>
                <td>{device.hostname || "Unknown"}</td>
                <td className="mono muted">{device.mac_address || "-"}</td>
                <td>
                    <span className={`badge ${device.risk_level === 'HIGH' ? 'danger' : (device.risk_level === 'MEDIUM' ? 'warning' : 'success')}`}>
                        <i className={`ri-${device.risk_level === 'HIGH' ? 'error-warning' : (device.risk_level === 'MEDIUM' ? 'alert' : 'checkbox-circle')}-line`}></i> {device.risk_score || 0}% {device.risk_level || 'LOW'}
                    </span>
                </td>
                {/* last_seen is already formatted as a string by the backend in our new changes */}
                <td className="mono">{device.last_seen || "Unknown"}</td>
                <td>
                    <span className={`badge ${device.is_online ? 'success' : 'neutral'}`}>
                        {device.is_online ? 'Online' : 'Offline'}
                    </span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};

export default DeviceTable;

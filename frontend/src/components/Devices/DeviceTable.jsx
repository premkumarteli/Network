import { formatUtcTimestampToLocal } from '../../utils/time';

const DeviceTable = ({ devices, onDeviceSelect }) => {
  const getRiskTone = (riskLevel) => {
    if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') return 'danger';
    if (riskLevel === 'MEDIUM') return 'warning';
    return 'success';
  };

  const getStatusTone = (status) => {
    if (status === 'Online') return 'success';
    if (status === 'Idle') return 'warning';
    return 'danger';
  };

  const getStatusLabel = (status, isOnline) => {
    const resolved = status || (isOnline ? 'Online' : 'Offline');
    if (resolved === 'Offline') return 'Disconnected';
    return resolved;
  };

  const handleRowKeyDown = (event, device) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onDeviceSelect?.(device);
    }
  };

  return (
    <div className="activity-log">
      <table>
        <thead>
          <tr>
            <th>Device</th>
            <th>Mode</th>
            <th>Network</th>
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
              <tr
                key={device.id || device.ip || index}
                className={`fade-in ${onDeviceSelect ? 'clickable-row' : ''}`.trim()}
                onClick={() => onDeviceSelect?.(device)}
                onKeyDown={(event) => handleRowKeyDown(event, device)}
                role={onDeviceSelect ? 'button' : undefined}
                tabIndex={onDeviceSelect ? 0 : undefined}
                aria-label={onDeviceSelect ? `Open details for ${device.hostname || device.ip}` : undefined}
              >
                <td>
                  <div className="table-primary">
                    {device.hostname && device.hostname !== 'Unknown' ? device.hostname : 'Unnamed Device'}
                  </div>
                  <div className="table-meta">
                    {[device.vendor, device.device_type, device.os_family]
                      .filter((value) => value && value !== 'Unknown')
                      .join(' / ') || 'Unclassified host'}
                  </div>
                </td>
                <td>
                  <span className={`badge ${device.management_mode === 'managed' ? 'success' : 'neutral'}`}>
                    {device.management_mode === 'managed' ? 'Managed' : 'BYOD'}
                  </span>
                  <div className="table-meta">{device.confidence || 'medium'} confidence</div>
                </td>
                <td>
                  <div className="mono primary">{device.ip}</div>
                  <div className="mono muted">{device.mac || device.mac_address || "-"}</div>
                </td>
                <td>
                  <span className={`badge ${getRiskTone(device.risk_level)}`}>
                    {Math.round(device.risk_score || 0)}% {device.risk_level || 'LOW'}
                  </span>
                </td>
                <td className="mono">{formatUtcTimestampToLocal(device.last_seen)}</td>
                <td>
                  <span className={`badge ${getStatusTone(device.status || (device.is_online ? 'Online' : 'Offline'))}`}>
                    {getStatusLabel(device.status, device.is_online)}
                  </span>
                  {onDeviceSelect ? (
                    <div className="table-meta table-link-hint">
                      View details <i className="ri-arrow-right-line"></i>
                    </div>
                  ) : null}
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

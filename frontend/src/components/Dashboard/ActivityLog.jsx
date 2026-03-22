const ActivityLog = ({ logs }) => {
  return (
    <div className="activity-log">
      <div className="section-title-row">
        <h3>Recent Sessions</h3>
        <span className="table-caption">Most recent classified application events</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Source IP</th>
            <th>Application</th>
            <th>Mode</th>
            <th>Protocol</th>
            <th>Severity</th>
            <th>Size</th>
          </tr>
        </thead>
        <tbody>
          {logs.length === 0 ? (
            <tr>
              <td colSpan="7" className="empty-state">Listening for traffic...</td>
            </tr>
          ) : (
            logs.map((log, index) => (
              <tr key={index} className="fade-in">
                <td className="mono muted">{log.time}</td>
                <td className="mono primary">{log.src_ip}</td>
                <td>
                  <div>{log.application || 'Other'}</div>
                  <div className="table-caption">{log.domain || log.dst_ip || '-'}</div>
                </td>
                <td>
                  <span className={`badge ${log.management_mode === 'managed' ? 'success' : 'neutral'}`}>
                    {log.management_mode === 'managed' ? 'Managed' : 'BYOD'}
                  </span>
                </td>
                <td><span className="badge neutral">{log.protocol}</span></td>
                <td>
                  <span className={`badge ${log.severity === 'CRITICAL' || log.severity === 'HIGH' ? 'danger' : log.severity === 'MEDIUM' ? 'warning' : 'success'}`}>
                    {log.severity || 'LOW'}
                  </span>
                </td>
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

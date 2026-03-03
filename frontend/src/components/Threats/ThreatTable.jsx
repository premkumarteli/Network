import React from 'react';

const ThreatTable = ({ threats }) => {
  return (
    <div className="activity-log">      
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Target</th>
            <th>Identity</th>
            <th>Reasoning/Threat Intelligence</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {threats.length === 0 ? (
            <tr>
              <td colSpan="5" className="empty-state">No high-risk threats detected.</td>
            </tr>
          ) : (
            threats.map((t, index) => (
              <tr key={index} className="fade-in">
                <td className="mono muted">{t.timestamp || "N/A"}</td>
                <td className="mono primary">{t.device_ip || t.src_ip}</td>
                <td className="mono">{t.flow_id ? `Flow: ${t.flow_id.substring(0,8)}` : "-"}</td>
                <td>
                    <span className="text-warning small italic">
                        <i className="ri-information-line"></i> {t.message || "AI Detection: Suspicious Activity"}
                    </span>
                </td>
                <td>
                    <span className={`badge ${t.severity === 'CRITICAL' ? 'danger' : 'warning'}`}>{t.severity}</span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};

export default ThreatTable;

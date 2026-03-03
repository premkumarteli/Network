import React, { useState, useEffect } from 'react';
import { systemService } from '../services/api';
import ThreatTable from '../components/Threats/ThreatTable'; 

const ActivityPage = () => {
    const [traffic, setTraffic] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchTraffic();
        const interval = setInterval(fetchTraffic, 5000);
        return () => clearInterval(interval);
    }, []);

    const fetchTraffic = async () => {
        try {
            // Using getAlerts as a placeholder for live traffic since we don't have a dedicated live traffic endpoint yet
            const res = await systemService.getAlerts();
            setTraffic(res.data);
            setLoading(false);
        } catch (err) {
            console.error("Failed to fetch activity", err);
            setLoading(false);
        }
    };

    return (
        <div className="animate-fade">
             <div className="header">
                <h2>Live Network Traffic</h2>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                     <div className="status-badge pulse">Live Monitoring</div>
                </div>
            </div>

            {loading ? (
                <div className="loading-state">Loading live feed...</div>
            ) : (
                <div className="activity-log">      
                    <table>
                        <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Severity</th>
                            <th>Size</th>
                        </tr>
                        </thead>
                        <tbody>
                        {traffic.map((t, index) => (
                            <tr key={index} className="animate-fade">
                                <td className="mono muted">{t.timestamp || "N/A"}</td>
                                <td className="mono primary">{t.device_ip || t.src_ip}</td>
                                <td>{t.breakdown?.domain || "-"}</td>
                                <td><span className="badge neutral">TCP/UDP</span></td>
                                <td>
                                    <span className={`badge ${t.severity === 'CRITICAL' || t.severity === 'HIGH' ? 'danger' : t.severity === 'MEDIUM' ? 'warning' : 'success'}`}>
                                        {t.severity || 'LOW'}
                                    </span>
                                </td>
                                <td className="mono">{t.risk_score || "0"}</td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
};

export default ActivityPage;

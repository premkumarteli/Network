import { useCallback, useEffect, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';

const VPNPage = () => {
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);

    const fetchAlerts = useCallback(async ({ background = false } = {}) => {
        if (!background) {
            setLoading(true);
        }
        try {
            const res = await systemService.getVPNAlerts({
                resolved: false,
                hours: 24,
                limit: 100,
            });
            setAlerts(res.data || []);
        } catch (err) {
            console.error("Failed to fetch VPN alerts", err);
        } finally {
            if (!background) {
                setLoading(false);
            }
        }
    }, []);

    useEffect(() => {
        fetchAlerts();
    }, [fetchAlerts]);

    useVisibilityPolling(() => fetchAlerts({ background: true }), 15000);

    return (
        <div className="animate-fade">
            <div className="header">
                <h2>VPN & Threat Alerts</h2>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                     <div className="status-badge pulse">
                        <i className="ri-shield-check-line"></i> Monitoring
                     </div>
                </div>
            </div>

            {loading ? (
                <div className="loading-state">Scanning for VPN threats...</div>
            ) : alerts.length === 0 ? (
                <div className="glass-panel" style={{ textAlign: 'center', padding: '3rem' }}>
                    <i className="ri-shield-check-line" style={{ fontSize: '3rem', color: 'var(--success)', marginBottom: '1rem', display: 'block' }}></i>
                    <h3>No Active Threats Detected</h3>
                    <p style={{ color: 'var(--text-muted)' }}>Your network appears to be secure. The engine is monitoring for anomalies.</p>
                </div>
            ) : (
                <div className="activity-log">      
                    <table>
                        <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Risk Score</th>
                            <th>Reason</th>
                            <th>Action</th>
                        </tr>
                        </thead>
                        <tbody>
                        {alerts.map((a, index) => (
                            <tr key={index} className="fade-in" style={{ borderLeft: '2px solid var(--danger)', background: 'rgba(239, 68, 68, 0.05)' }}>
                                <td className="mono muted">{new Date(a.timestamp).toLocaleString()}</td>
                                <td className="mono primary">{a.device_ip}</td>
                                <td>
                                    <div className="progress-bar">
                                        <div className="fill danger" style={{ width: `${Math.min(Number(a.risk_score) || 0, 100)}%` }}></div>
                                    </div>
                                </td>
                                <td className="danger">{a.message || a.breakdown?.primary_detection || a.severity}</td>
                                <td>
                                    <button className="action-btn" onClick={() => window.alert(`Details: ${a.message || a.severity}`)}>
                                        <i className="ri-eye-line"></i>
                                    </button>
                                </td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
};

export default VPNPage;

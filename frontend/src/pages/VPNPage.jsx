import React, { useState, useEffect } from 'react';
import axios from 'axios';

const VPNPage = () => {
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchAlerts();
        const interval = setInterval(fetchAlerts, 5000);
        return () => clearInterval(interval);
    }, []);

    const fetchAlerts = async () => {
        try {
            const res = await axios.get('/api/logs'); // Reusing logs endpoint which returns vpn alerts
            setAlerts(res.data.vpn || []);
            setLoading(false);
        } catch (err) {
            console.error("Failed to fetch VPN alerts", err);
            setLoading(false);
        }
    };

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
                                <td className="mono muted">{new Date(a.time).toLocaleString()}</td>
                                <td className="mono primary">{a.src_ip}</td>
                                <td>
                                    <div className="progress-bar">
                                        <div className="fill danger" style={{ width: `${a.score * 100}%` }}></div>
                                    </div>
                                </td>
                                <td className="danger">{a.reason}</td>
                                <td>
                                    <button className="action-btn" onClick={() => alert(`Details: ${a.reason}`)}>
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

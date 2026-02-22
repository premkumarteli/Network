import React, { useState, useEffect } from 'react';
import axios from 'axios';

const SystemLogsPage = () => {
    const [logs, setLogs] = useState({ admin: [], vpn: [] });
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchLogs();
    }, []);

    const fetchLogs = async () => {
        try {
            const res = await axios.get('/api/logs');
            setLogs(res.data);
            setLoading(false);
        } catch (err) {
            console.error("Failed to fetch system logs", err);
            setLoading(false);
        }
    };

    return (
        <div className="animate-fade">
            <div className="header">
                <h2>System Logs</h2>
                <button className="action-btn" onClick={fetchLogs}>
                    <i className="ri-refresh-line"></i> Refresh
                </button>
            </div>

            <div className="stats-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                {/* Admin Logs */}
                <div className="activity-log">
                    <h3 style={{ marginBottom: '1rem', color: 'var(--text-main)' }}>
                        <i className="ri-admin-line"></i> Admin Events
                    </h3>
                    <table>
                        <thead>
                            <tr><th>Time</th><th>Action</th><th>Details</th></tr>
                        </thead>
                        <tbody>
                            {logs.admin.length === 0 ? (
                                <tr><td colSpan="3" className="empty-state">No admin events.</td></tr>
                            ) : logs.admin.map((l, i) => (
                                <tr key={i}>
                                    <td className="mono muted">{new Date(l.time).toLocaleString()}</td>
                                    <td><span className="badge neutral">{l.action}</span></td>
                                    <td className="small">{l.details}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* VPN Alerts */}
                <div className="activity-log">
                    <h3 style={{ marginBottom: '1rem', color: 'var(--danger)' }}>
                        <i className="ri-alarm-warning-line"></i> VPN Alerts
                    </h3>
                    <table>
                        <thead>
                            <tr><th>Time</th><th>Source</th><th>Score</th><th>Reason</th></tr>
                        </thead>
                        <tbody>
                            {logs.vpn.length === 0 ? (
                                <tr><td colSpan="4" className="empty-state">No VPN alerts.</td></tr>
                            ) : logs.vpn.map((l, i) => (
                                <tr key={i} style={{ borderLeft: '2px solid var(--danger)', background: 'rgba(239, 68, 68, 0.05)' }}>
                                    <td className="mono muted">{new Date(l.time).toLocaleString()}</td>
                                    <td className="mono primary">{l.src_ip}</td>
                                    <td>
                                        <div className="progress-bar">
                                            <div className="fill danger" style={{ width: `${l.score * 100}%` }}></div>
                                        </div>
                                    </td>
                                    <td className="small danger">{l.reason}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default SystemLogsPage;

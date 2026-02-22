import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ThreatTable from '../components/Threats/ThreatTable'; // Reusing table or creating a generic one

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
            const res = await axios.get('/api/activity');
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
                                <td className="mono muted">{t.time.split(" ")[1]}</td>
                                <td className="mono primary">{t.ip}</td>
                                <td>{t.domain !== "-" ? t.domain : t.dst_ip}</td>
                                <td><span className="badge neutral">{t.protocol}</span></td>
                                <td>
                                    <span className={`badge ${t.severity === 'HIGH' ? 'danger' : t.severity === 'MEDIUM' ? 'warning' : 'success'}`}>
                                        {t.severity || 'LOW'}
                                    </span>
                                </td>
                                <td className="mono">{t.size} B</td>
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

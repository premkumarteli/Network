import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ThreatTable from '../components/Threats/ThreatTable';

const ThreatsPage = () => {
    const [threats, setThreats] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchThreats();
        // Poll for threats every 10 seconds
        const interval = setInterval(fetchThreats, 10000);
        return () => clearInterval(interval);
    }, []);

    const fetchThreats = async () => {
        try {
            // Fetch only High Severity traffic
            const res = await axios.get('/api/activity?severity=HIGH');
            setThreats(res.data);
            setLoading(false);
        } catch (err) {
            console.error("Failed to fetch threats", err);
            setLoading(false);
        }
    };

    return (
        <div className="animate-fade">
            <div className="header">
                <h2>Security Threats</h2>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <span className="badge danger" style={{ fontSize: '1rem' }}>
                        {threats.length} Active
                    </span>
                    <button className="action-btn danger-hover" onClick={fetchThreats}>
                        <i className="ri-refresh-line"></i> Refresh
                    </button>
                </div>
            </div>
            
            {loading ? (
                <div className="loading-state">Scanning for threats...</div>
            ) : (
                <ThreatTable threats={threats} />
            )}
        </div>
    );
};

export default ThreatsPage;

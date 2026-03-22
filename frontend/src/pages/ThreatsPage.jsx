import { useCallback, useEffect, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import ThreatTable from '../components/Threats/ThreatTable';

const ThreatsPage = () => {
    const [threats, setThreats] = useState([]);
    const [threatCount, setThreatCount] = useState(0);
    const [loading, setLoading] = useState(true);

    const fetchThreats = useCallback(async ({ background = false } = {}) => {
        if (!background) {
            setLoading(true);
        }
        try {
            const [res, statsRes] = await Promise.all([
                systemService.getAlerts({
                    severity: 'HIGH,CRITICAL',
                    resolved: false,
                    hours: 24,
                    limit: 100,
                }),
                systemService.getStats(),
            ]);
            setThreats(res.data || []);
            setThreatCount(statsRes.data?.high_risk || 0);
        } catch (err) {
            console.error("Failed to fetch threats", err);
        } finally {
            if (!background) {
                setLoading(false);
            }
        }
    }, []);

    useEffect(() => {
        fetchThreats();
    }, [fetchThreats]);

    useVisibilityPolling(() => fetchThreats({ background: true }), 15000);

    return (
        <div className="animate-fade">
            <div className="header">
                <h2>Security Threats</h2>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <span className="badge danger" style={{ fontSize: '1rem' }}>
                        {threatCount} Active
                    </span>
                    <button className="action-btn danger-hover" onClick={() => fetchThreats()}>
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

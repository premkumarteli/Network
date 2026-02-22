import React, { useState, useEffect, useCallback } from 'react';
import { systemService } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import StatsPanel from '../components/Dashboard/StatsPanel';
import TrafficChart from '../components/Dashboard/TrafficChart';
import ActivityLog from '../components/Dashboard/ActivityLog';

const DashboardPage = () => {
    const [stats, setStats] = useState({});
    const [trafficData, setTrafficData] = useState({ labels: [], values: [] });
    const [logs, setLogs] = useState([]);

    const handlePacketEvent = useCallback((pkt) => {
        setLogs(prev => {
            const newLog = {
                time: pkt.time_str.split(" ")[1],
                src_ip: pkt.src_ip,
                domain: pkt.domain || "-",
                protocol: pkt.protocol || "Unknown",
                size: pkt.size
            };
            return [newLog, ...prev].slice(0, 15);
        });
    }, []);

    const { status: wsStatus } = useWebSocket('packet_event', handlePacketEvent);

    useEffect(() => {
        const fetchInitialData = async () => {
            try {
                const [statsRes, activityRes] = await Promise.all([
                    systemService.getStats(),
                    systemService.getActivity()
                ]);
                setStats(statsRes.data);
                setLogs(activityRes.data.slice(0, 15));
                updateTrafficChart(statsRes.data.bandwidth);
            } catch (err) {
                console.error("[Dashboard] Initial fetch failed:", err);
            }
        };

        fetchInitialData();
        const interval = setInterval(async () => {
            try {
                const res = await systemService.getStats();
                setStats(res.data);
                updateTrafficChart(res.data.bandwidth);
            } catch (err) {
                console.error("[Dashboard] Poll failed:", err);
            }
        }, 5000);

        return () => clearInterval(interval);
    }, []);

    const updateTrafficChart = (bandwidthStr) => {
        if (!bandwidthStr) return;
        const val = parseFloat(bandwidthStr);
        const now = new Date().toLocaleTimeString();

        setTrafficData(prev => {
            const newLabels = [...prev.labels, now].slice(-20);
            const newValues = [...prev.values, val].slice(-20);
            return { labels: newLabels, values: newValues };
        });
    };

    return (
        <div className="animate-fade">
            <div className="flex justify-between items-center" style={{ marginBottom: '1.5rem' }}>
                <h2 style={{ margin: 0 }}>Dashboard</h2>
                <span className={`ws-badge ${wsStatus}`}>
                    {wsStatus === 'connected' ? 'LIVE' : 'RECONNECTING'}
                </span>
            </div>
            
            <div className="animate-slide-up">
                <StatsPanel stats={stats} />
            </div>
            
            <div className="charts-section">
                <div className="chart-card">
                    <h3>Real-time Traffic</h3>
                    <TrafficChart data={trafficData} />
                </div>
            </div>
            
            <ActivityLog logs={logs} />
        </div>
    );
};

export default DashboardPage;

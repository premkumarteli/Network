import { useCallback, useEffect, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import TrafficChart from '../components/Dashboard/TrafficChart';
import ActivityLog from '../components/Dashboard/ActivityLog';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';

const ActivityPage = () => {
    const [stats, setStats] = useState({});
    const [logs, setLogs] = useState([]);
    const [trafficData, setTrafficData] = useState({ labels: [], values: [] });
    const [loading, setLoading] = useState(true);

    const updateTrafficChart = useCallback((bandwidthValue) => {
        if (bandwidthValue === null || bandwidthValue === undefined) {
            return;
        }

        const numericValue =
            typeof bandwidthValue === 'number' ? bandwidthValue : Number.parseFloat(bandwidthValue);
        if (Number.isNaN(numericValue)) {
            return;
        }

        const now = new Date().toLocaleTimeString();
        setTrafficData((prev) => ({
            labels: [...prev.labels, now].slice(-20),
            values: [...prev.values, numericValue].slice(-20),
        }));
    }, []);

    const fetchTraffic = useCallback(async (background = false) => {
        if (!background) {
            setLoading(true);
        }

        try {
            const [statsRes, activityRes] = await Promise.all([
                systemService.getStats(),
                systemService.getActivity(100),
            ]);
            const nextStats = statsRes.data || {};
            setStats(nextStats);
            setLogs(activityRes.data || []);
            updateTrafficChart(nextStats.bandwidth_value ?? nextStats.bandwidth);
        } catch (err) {
            console.error('Failed to fetch traffic activity', err);
        } finally {
            if (!background) {
                setLoading(false);
            }
        }
    }, [updateTrafficChart]);

    useEffect(() => {
        fetchTraffic();
    }, [fetchTraffic]);

    useVisibilityPolling(() => fetchTraffic(true), 15000);

    return (
        <div className="page-shell dashboard-shell">
            <div className="page-hero">
                <div>
                    <div className="page-eyebrow">Traffic Monitor</div>
                    <h2>Live Traffic Activity</h2>
                    <p className="page-subtitle">
                        This page mirrors the dashboard traffic KPIs and expands them into a live session feed.
                    </p>
                </div>
                <button className="action-btn" onClick={() => fetchTraffic()}>
                    <i className="ri-refresh-line"></i> Refresh
                </button>
            </div>

            {loading ? (
                <StatGridSkeleton count={4} />
            ) : (
                <div className="summary-grid">
                    <div className="summary-card">
                        <span className="summary-label">Flows (24h)</span>
                        <strong>{stats.flows_24h || 0}</strong>
                        <span className="summary-meta">same window as the dashboard live traffic KPI</span>
                    </div>
                    <div className="summary-card">
                        <span className="summary-label">Recent Sessions</span>
                        <strong>{logs.length}</strong>
                        <span className="summary-meta">latest classified flow events in the feed</span>
                    </div>
                    <div className="summary-card">
                        <span className="summary-label">Online Devices</span>
                        <strong>{stats.active_devices || 0}</strong>
                        <span className="summary-meta">{stats.total_devices || 0} tracked devices currently known</span>
                    </div>
                    <div className="summary-card">
                        <span className="summary-label">Bandwidth</span>
                        <strong>{stats.bandwidth || '0 B/s'}</strong>
                        <span className="summary-meta">rolling one-minute network throughput</span>
                    </div>
                </div>
            )}

            <div className="dashboard-grid">
                <div className="chart-card">
                    <div className="section-title-row">
                        <h3>Traffic Throughput</h3>
                        <span className="table-caption">rolling one-minute bandwidth estimate</span>
                    </div>
                    <TrafficChart data={trafficData} />
                </div>
            </div>

            {loading ? <TableSkeleton rows={8} /> : <ActivityLog logs={logs} />}
        </div>
    );
};

export default ActivityPage;

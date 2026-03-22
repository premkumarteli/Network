import { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import StatsPanel from '../components/Dashboard/StatsPanel';
import TrafficChart from '../components/Dashboard/TrafficChart';
import ActivityLog from '../components/Dashboard/ActivityLog';
import WebActivityLog from '../components/Dashboard/WebActivityLog';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';

const DashboardPage = () => {
    const navigate = useNavigate();
    const [stats, setStats] = useState({});
    const [appsSummary, setAppsSummary] = useState([]);
    const [trafficData, setTrafficData] = useState({ labels: [], values: [] });
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);

    const handlePacketEvent = useCallback((pkt) => {
        setLogs(prev => {
            const timeValue = pkt.time || pkt.time_str?.split(" ")[1] || new Date().toLocaleTimeString();
            const newLog = {
                time: timeValue,
                src_ip: pkt.src_ip,
                dst_ip: pkt.dst_ip,
                domain: pkt.domain || "-",
                application: pkt.application || "Other",
                protocol: pkt.protocol || "Unknown",
                size: pkt.size || "-",
                severity: pkt.severity || "LOW",
                management_mode: pkt.management_mode || "byod",
            };
            return [newLog, ...prev].slice(0, 15);
        });
    }, []);

    const { status: wsStatus } = useWebSocket('packet_event', handlePacketEvent);

    const fetchInitialData = useCallback(async () => {
        try {
            const [statsRes, activityRes, appsRes] = await Promise.all([
                systemService.getStats(),
                systemService.getActivity(),
                systemService.getAppsSummary(),
            ]);
            setStats(statsRes.data);
            setAppsSummary(appsRes.data || []);
            setLogs((activityRes.data || []).slice(0, 15));
            updateTrafficChart(statsRes.data.bandwidth_value ?? statsRes.data.bandwidth);
        } catch (err) {
            console.error("[Dashboard] Initial fetch failed:", err);
        } finally {
            setLoading(false);
        }
    }, []);

    const pollDashboard = useCallback(async () => {
        try {
            const [statsRes, appsRes] = await Promise.all([
                systemService.getStats(),
                systemService.getAppsSummary(),
            ]);
            setStats(statsRes.data);
            setAppsSummary(appsRes.data || []);
            updateTrafficChart(statsRes.data.bandwidth_value ?? statsRes.data.bandwidth);
        } catch (err) {
            console.error("[Dashboard] Poll failed:", err);
        }
    }, []);

    useEffect(() => {
        fetchInitialData();
    }, [fetchInitialData]);

    useVisibilityPolling(pollDashboard, 15000);

    const updateTrafficChart = (bandwidthStr) => {
        if (!bandwidthStr) return;
        const val = typeof bandwidthStr === "number" ? bandwidthStr : parseFloat(bandwidthStr);
        if (Number.isNaN(val)) return;
        const now = new Date().toLocaleTimeString();

        setTrafficData(prev => {
            const newLabels = [...prev.labels, now].slice(-20);
            const newValues = [...prev.values, val].slice(-20);
            return { labels: newLabels, values: newValues };
        });
    };

    const kpiCards = useMemo(() => ([
        {
            icon: 'ri-macbook-line',
            label: 'Devices',
            value: stats.total_devices || 0,
            meta: `${stats.active_devices || 0} online right now`,
            onClick: () => navigate('/devices'),
        },
        {
            icon: 'ri-apps-2-line',
            label: 'Applications',
            value: appsSummary.length,
            meta: `${appsSummary.filter((entry) => (entry.active_device_count || 0) > 0).length} active app groups right now`,
            onClick: () => navigate('/apps'),
            accent: '#22d3ee',
        },
        {
            icon: 'ri-alarm-warning-line',
            label: 'High Risk Alerts',
            value: stats.high_risk || 0,
            meta: 'investigate high and critical detections',
            onClick: () => navigate('/threats'),
            tone: (stats.high_risk || 0) > 0 ? 'danger' : 'default',
            accent: '#fb7185',
        },
        {
            icon: 'ri-exchange-box-line',
            label: 'Live Traffic',
            value: stats.flows_24h || 0,
            meta: 'open the session feed and traffic drill-down',
            onClick: () => navigate('/activity'),
            accent: '#60a5fa',
        },
        {
            icon: 'ri-speed-up-line',
            label: 'Bandwidth',
            value: stats.bandwidth || '0 MB',
            meta: 'rolling one-minute network throughput',
            onClick: () => navigate('/activity'),
            accent: '#34d399',
        },
    ]), [appsSummary, navigate, stats.active_devices, stats.bandwidth, stats.flows_24h, stats.high_risk, stats.total_devices]);

    return (
        <div className="page-shell dashboard-shell">
            <div className="page-hero">
                <div>
                    <div className="page-eyebrow">SOC Overview</div>
                    <h2>Threat Detection Dashboard</h2>
                    <p className="page-subtitle">
                        Real-time network posture across managed endpoints and metadata-only BYOD traffic.
                    </p>
                </div>
                <span className={`ws-badge ${wsStatus}`}>
                    {wsStatus === 'connected' ? 'LIVE' : 'RECONNECTING'}
                </span>
            </div>

            <div className="quick-actions">
                <button className="action-btn ghost" onClick={() => navigate('/devices')}>
                    <i className="ri-search-eye-line"></i> Investigate Devices
                </button>
                <button className="action-btn ghost" onClick={() => navigate('/apps')}>
                    <i className="ri-links-line"></i> Review Applications
                </button>
                <button className="action-btn ghost" onClick={() => navigate('/threats')}>
                    <i className="ri-shield-check-line"></i> Open Threat Queue
                </button>
            </div>

            {loading ? (
                <StatGridSkeleton count={5} />
            ) : (
                <StatsPanel cards={kpiCards} />
            )}

            <div className="signal-strip">
                {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((level) => (
                    <div key={level} className={`severity-chip ${level.toLowerCase()}`}>
                        <span>{level}</span>
                        <strong>{stats.risk_distribution?.[level] || 0}</strong>
                    </div>
                ))}
            </div>

            <div className="dashboard-grid">
                <div className="chart-card">
                    <div className="section-title-row">
                        <h3>Real-time Traffic</h3>
                        <span className="table-caption">rolling one-minute bandwidth estimate</span>
                    </div>
                    <TrafficChart data={trafficData} />
                </div>

                <div className="chart-card dashboard-callout">
                    <div className="section-title-row">
                        <h3>Quick Navigation</h3>
                        <span className="table-caption">Jump directly into the investigative flow</span>
                    </div>
                    <div className="callout-list">
                        <button type="button" className="callout-row" onClick={() => navigate('/devices')}>
                            <span><i className="ri-macbook-line"></i> Device inventory</span>
                            <strong>{stats.total_devices || 0}</strong>
                        </button>
                        <button type="button" className="callout-row" onClick={() => navigate('/apps')}>
                            <span><i className="ri-apps-2-line"></i> Classified applications</span>
                            <strong>{appsSummary.length}</strong>
                        </button>
                        <button type="button" className="callout-row" onClick={() => navigate('/activity')}>
                            <span><i className="ri-pulse-line"></i> Live activity feed</span>
                            <strong>{logs.length}</strong>
                        </button>
                    </div>
                </div>
            </div>

            <div className="drilldown-grid">
                {loading ? <TableSkeleton rows={5} /> : <ActivityLog logs={logs} />}
                <WebActivityLog />
            </div>
        </div>
    );
};

export default DashboardPage;

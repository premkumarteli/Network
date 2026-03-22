import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { formatRuntime, getApplicationVisual } from '../utils/apps';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';

const ApplicationsPage = () => {
    const navigate = useNavigate();
    const [applications, setApplications] = useState([]);
    const [loading, setLoading] = useState(true);

    const fetchApplications = useCallback(async () => {
        try {
            const res = await systemService.getAppsSummary();
            setApplications(res.data || []);
        } catch (err) {
            console.error('Failed to fetch applications', err);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchApplications();
    }, [fetchApplications]);

    useVisibilityPolling(fetchApplications, 5000);

    const totals = useMemo(() => {
        return applications.reduce(
            (acc, app) => {
                acc.deviceCount += app.device_count || 0;
                acc.activeDevices += app.active_device_count || 0;
                acc.bandwidthBytes += app.bandwidth_bytes || 0;
                return acc;
            },
            { deviceCount: 0, activeDevices: 0, bandwidthBytes: 0 },
        );
    }, [applications]);

    return (
        <div className="animate-fade">
            <div className="page-hero">
                <div>
                    <div className="page-eyebrow">Application Sessions</div>
                    <h2>Application Usage</h2>
                    <p className="page-subtitle">
                        Sessions are grouped by application and device over the last five minutes. Click an application to inspect the devices using it.
                    </p>
                </div>
                <button className="action-btn" onClick={fetchApplications}>
                    <i className="ri-refresh-line"></i> Refresh
                </button>
            </div>

            <div className="summary-grid">
                <div className="summary-card">
                    <span className="summary-label">Visible Applications</span>
                    <strong>{applications.length}</strong>
                    <span className="summary-meta">classified from DNS and TLS hostname hints</span>
                </div>
                <div className="summary-card">
                    <span className="summary-label">Devices In Window</span>
                    <strong>{totals.deviceCount}</strong>
                    <span className="summary-meta">{totals.activeDevices} active in the last 60 seconds</span>
                </div>
                <div className="summary-card">
                    <span className="summary-label">Traffic Volume</span>
                    <strong>{formatBandwidth(totals.bandwidthBytes)}</strong>
                    <span className="summary-meta">aggregated over the five minute app window</span>
                </div>
            </div>

            {loading ? (
                <>
                    <StatGridSkeleton count={3} />
                    <TableSkeleton rows={4} />
                </>
            ) : applications.length === 0 ? (
                <div className="empty-panel">
                    <h3>No application sessions yet</h3>
                    <p>Start the agent and gateway to populate the app dashboard.</p>
                </div>
            ) : (
                <div className="app-card-grid">
                    {applications.map((app) => (
                        <button
                            key={app.application}
                            type="button"
                            className="application-card"
                            onClick={() => navigate(`/apps/${encodeURIComponent(app.application)}`)}
                        >
                            <div className="application-card-header">
                                <div className="application-card-title">
                                    <div
                                        className="app-logo-shell"
                                        style={{
                                            color: getApplicationVisual(app.application).accent,
                                            background: getApplicationVisual(app.application).background,
                                            borderColor: `${getApplicationVisual(app.application).accent}33`,
                                        }}
                                    >
                                        <i className={getApplicationVisual(app.application).icon}></i>
                                    </div>
                                    <div>
                                    <span className="summary-label">Application</span>
                                    <h3>{app.application}</h3>
                                    </div>
                                </div>
                                <span className={`badge ${app.active_device_count > 0 ? 'success' : 'neutral'}`}>
                                    {app.active_device_count > 0 ? 'Active' : 'Idle'}
                                </span>
                            </div>
                            <div className="application-card-metric">
                                <strong>{app.device_count}</strong>
                                <span>devices</span>
                            </div>
                            <div className="application-card-footer">
                                <span>{app.active_device_count} active now</span>
                                <span>{app.bandwidth}</span>
                            </div>
                            <div className="application-card-caption">
                                Runtime {app.runtime || formatRuntime(app.runtime_seconds)}
                            </div>
                            <div className="application-card-caption">
                                Last seen {app.last_seen || 'N/A'}
                            </div>
                        </button>
                    ))}
                </div>
            )}
        </div>
    );
};

function formatBandwidth(byteCount) {
    if (byteCount >= 1024 * 1024) {
        return `${(byteCount / (1024 * 1024)).toFixed(2)} MB`;
    }
    if (byteCount >= 1024) {
        return `${(byteCount / 1024).toFixed(1)} KB`;
    }
    return `${Math.trunc(byteCount || 0)} B`;
}

export default ApplicationsPage;

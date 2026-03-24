import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { systemService } from '../services/api';
import { formatRuntime, getApplicationVisual } from '../utils/apps';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';

const ApplicationDevicesPage = () => {
    const navigate = useNavigate();
    const { appName } = useParams();
    const decodedAppName = decodeURIComponent(appName || 'Other');
    const [loading, setLoading] = useState(true);
    const [events, setEvents] = useState([]);

    const fetchDevices = useCallback(async () => {
        try {
            const res = await systemService.getAppDevices(decodedAppName);
            setDevices(res.data?.devices || []);
            const eventsRes = await systemService.getAppDpiEvents(decodedAppName);
            setEvents(eventsRes.data?.activity || []);
        } catch (err) {
            console.error('Failed to fetch application devices or events', err);
        } finally {
            setLoading(false);
        }
    }, [decodedAppName]);

    useEffect(() => {
        fetchDevices();
        const interval = setInterval(fetchDevices, 5000);
        return () => clearInterval(interval);
    }, [fetchDevices]);

    const stats = useMemo(() => {
        return devices.reduce(
            (acc, device) => {
                acc.total += 1;
                acc.active += device.status === 'Active' ? 1 : 0;
                acc.bandwidthBytes += device.bandwidth_bytes || 0;
                acc.runtimeSeconds += device.runtime_seconds || 0;
                return acc;
            },
            { total: 0, active: 0, bandwidthBytes: 0, runtimeSeconds: 0 },
        );
    }, [devices]);

    const visual = getApplicationVisual(decodedAppName);

    return (
        <div className="animate-fade">
            <div className="page-hero">
                <div>
                    <div className="page-eyebrow">Application Devices</div>
                    <div className="app-detail-hero">
                        <div
                            className="app-logo-shell large"
                            style={{
                                color: visual.accent,
                                background: visual.background,
                                borderColor: `${visual.accent}33`,
                            }}
                        >
                            <i className={visual.icon}></i>
                        </div>
                        <div>
                            <h2>{decodedAppName}</h2>
                            <p className="page-subtitle">
                                Devices with sessions for this application in the last five minutes. Active means seen within the last 60 seconds.
                            </p>
                        </div>
                    </div>
                </div>
                <div className="page-actions">
                    <Link className="action-btn ghost" to="/apps">
                        <i className="ri-arrow-left-line"></i> Back
                    </Link>
                    <button className="action-btn" onClick={fetchDevices}>
                        <i className="ri-refresh-line"></i> Refresh
                    </button>
                </div>
            </div>

            <div className="summary-grid">
                <div className="summary-card">
                    <span className="summary-label">Devices</span>
                    <strong>{stats.total}</strong>
                    <span className="summary-meta">{stats.active} active / {stats.total - stats.active} idle</span>
                </div>
                <div className="summary-card">
                    <span className="summary-label">Bandwidth</span>
                    <strong>{formatBandwidth(stats.bandwidthBytes)}</strong>
                    <span className="summary-meta">five minute application window</span>
                </div>
                <div className="summary-card">
                    <span className="summary-label">Runtime</span>
                    <strong>{formatRuntime(stats.runtimeSeconds)}</strong>
                    <span className="summary-meta">total session time across visible devices</span>
                </div>
                <div className="summary-card">
                    <span className="summary-label">Coverage</span>
                    <strong>{devices.filter((device) => device.management_mode === 'managed').length}</strong>
                    <span className="summary-meta">managed devices using {decodedAppName}</span>
                </div>
            </div>

            {loading ? (
                <>
                    <StatGridSkeleton count={4} />
                    <TableSkeleton rows={5} />
                </>
            ) : (
                <div className="activity-log">
                    <div className="section-title-row">
                        <h3>{decodedAppName} Device Sessions</h3>
                        <span className="table-caption">Grouped by device IP + application</span>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Device IP</th>
                                <th>Hostname</th>
                                <th>Mode</th>
                                <th>Status</th>
                                <th>Runtime</th>
                                <th>Bandwidth</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            {devices.length === 0 ? (
                                <tr>
                                    <td colSpan="7" className="empty-state">No devices are currently using this application.</td>
                                </tr>
                            ) : (
                                devices.map((device) => (
                                    <tr
                                        key={`${decodedAppName}-${device.device_ip}`}
                                        className="clickable-row"
                                        onClick={() => navigate(`/user/${encodeURIComponent(device.device_ip)}`)}
                                    >
                                        <td className="mono primary">{device.device_ip}</td>
                                        <td>{device.hostname || 'Unknown'}</td>
                                        <td>
                                            <span className={`badge ${device.management_mode === 'managed' ? 'success' : 'neutral'}`}>
                                                {device.management_mode === 'managed' ? 'Managed' : 'BYOD'}
                                            </span>
                                        </td>
                                        <td>
                                            <span className={`badge ${device.status === 'Active' ? 'success' : 'neutral'}`}>
                                                {device.status}
                                            </span>
                                        </td>
                                        <td className="mono">{device.runtime || formatRuntime(device.runtime_seconds)}</td>
                                        <td className="mono">{device.bandwidth}</td>
                                        <td className="mono muted">{device.last_seen || 'N/A'}</td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            )}

            {!loading && events.length > 0 && (
                <div className="activity-log mt-6">
                    <div className="section-title-row">
                        <h3>{decodedAppName} Web Activity</h3>
                        <span className="table-caption">Recent DPI inspections for this app</span>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Device IP</th>
                                <th>Domain</th>
                                <th>Title</th>
                                <th>Search Query</th>
                            </tr>
                        </thead>
                        <tbody>
                            {events.map((event, index) => (
                                <tr key={index}>
                                    <td>{new Date(event.last_seen || event.timestamp).toLocaleTimeString()}</td>
                                    <td className="mono primary">{event.device_ip}</td>
                                    <td>{event.base_domain || event.domain}</td>
                                    <td className="truncate max-w-xs">{event.page_title || event.title}</td>
                                    <td>{event.search_query || '-'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
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

export default ApplicationDevicesPage;

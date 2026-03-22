import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { agentService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';

const AgentDetailsPage = () => {
    const { agentId } = useParams();
    const decodedAgentId = decodeURIComponent(agentId || '');
    const [agent, setAgent] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const normalizedAgent = useMemo(() => {
        if (!agent || typeof agent !== 'object') {
            return null;
        }
        return {
            agent_id: agent.agent_id || decodedAgentId,
            hostname: agent.hostname || decodedAgentId || 'Unknown',
            ip_address: agent.ip_address || '-',
            status: agent.status === 'Online' ? 'Online' : 'Offline',
            last_seen: agent.last_seen || 'N/A',
            heartbeat_age_seconds:
                agent.heartbeat_age_seconds === null || agent.heartbeat_age_seconds === undefined
                    ? 'N/A'
                    : agent.heartbeat_age_seconds,
            device_count: Number(agent.device_count) || 0,
            os_family: agent.os_family || 'Unknown',
            version: agent.version || 'Unknown',
            inspection_enabled: Boolean(agent.inspection_enabled),
            inspection_status: agent.inspection_status || 'disabled',
            inspection_proxy_running: Boolean(agent.inspection_proxy_running),
            inspection_ca_installed: Boolean(agent.inspection_ca_installed),
            inspection_browsers: Array.isArray(agent.inspection_browsers) ? agent.inspection_browsers : [],
            inspection_last_error: agent.inspection_last_error || '',
            devices: Array.isArray(agent.devices)
                ? agent.devices
                    .filter((device) => device && typeof device === 'object')
                    .map((device) => ({
                        ...device,
                        status: device.status || (device.is_online ? 'Online' : 'Offline'),
                    }))
                : [],
        };
    }, [agent, decodedAgentId]);

    const fetchAgent = useCallback(async () => {
        try {
            const res = await agentService.getAgentDetails(decodedAgentId);
            setAgent(res.data && typeof res.data === 'object' ? res.data : null);
            setError('');
        } catch (err) {
            console.error('Failed to fetch agent details', err);
            setAgent(null);
            setError('Unable to load the selected agent right now.');
        } finally {
            setLoading(false);
        }
    }, [decodedAgentId]);

    useEffect(() => {
        fetchAgent();
    }, [fetchAgent]);

    useVisibilityPolling(fetchAgent, 15000);

    const stats = useMemo(() => {
        const devices = normalizedAgent?.devices || [];
        return {
            total: devices.length,
            online: devices.filter((device) => device.status === 'Online').length,
            idle: devices.filter((device) => device.status === 'Idle').length,
            observed: devices.filter((device) => device.management_mode === 'observed').length,
        };
    }, [normalizedAgent]);

    return (
        <div className="animate-fade">
            <div className="page-hero">
                <div>
                    <div className="page-eyebrow">Agent Detail</div>
                    <h2>{normalizedAgent?.hostname || decodedAgentId}</h2>
                    <p className="page-subtitle">
                        Live heartbeat profile for a single NetVisor agent, including the managed endpoint and all currently mapped discovered devices.
                    </p>
                </div>
                <div className="page-actions">
                    <Link className="action-btn ghost" to="/logs">
                        <i className="ri-arrow-left-line"></i> Back
                    </Link>
                    <button className="action-btn" onClick={fetchAgent}>
                        <i className="ri-refresh-line"></i> Refresh
                    </button>
                </div>
            </div>

            {loading ? (
                <div className="loading-state">Loading agent detail...</div>
            ) : error ? (
                <div className="empty-panel">
                    <h3>Agent feed unavailable</h3>
                    <p>{error}</p>
                </div>
            ) : !normalizedAgent ? (
                <div className="empty-panel">
                    <h3>Agent not found</h3>
                    <p>The selected agent is not available in the current monitoring window.</p>
                </div>
            ) : (
                <>
                    <div className="summary-grid">
                        <div className="summary-card">
                            <span className="summary-label">Agent ID</span>
                            <strong className="mono" style={{ fontSize: '1.05rem' }}>{normalizedAgent.agent_id}</strong>
                            <span className="summary-meta">{normalizedAgent.os_family} / {normalizedAgent.version}</span>
                        </div>
                        <div className="summary-card">
                            <span className="summary-label">Heartbeat Status</span>
                            <strong>{normalizedAgent.status}</strong>
                            <span className="summary-meta">Last seen {normalizedAgent.last_seen}</span>
                        </div>
                        <div className="summary-card">
                            <span className="summary-label">IP Address</span>
                            <strong className="mono">{normalizedAgent.ip_address}</strong>
                            <span className="summary-meta">{normalizedAgent.heartbeat_age_seconds}s since heartbeat</span>
                        </div>
                        <div className="summary-card">
                            <span className="summary-label">Associated Devices</span>
                            <strong>{normalizedAgent.device_count}</strong>
                            <span className="summary-meta">{stats.online} online / {stats.idle} idle / {Math.max(stats.total - stats.online - stats.idle, 0)} offline</span>
                        </div>
                        <div className="summary-card">
                            <span className="summary-label">Web Inspection</span>
                            <strong>{normalizedAgent.inspection_enabled ? 'Enabled' : 'Disabled'}</strong>
                            <span className="summary-meta">
                                {normalizedAgent.inspection_proxy_running ? 'Proxy running' : normalizedAgent.inspection_status}
                            </span>
                        </div>
                        <div className="summary-card">
                            <span className="summary-label">CA / Browsers</span>
                            <strong>{normalizedAgent.inspection_ca_installed ? 'Installed' : 'Missing'}</strong>
                            <span className="summary-meta">
                                {(normalizedAgent.inspection_browsers || []).join(', ') || 'Chrome / Edge'}
                            </span>
                        </div>
                    </div>

                    {normalizedAgent.inspection_last_error ? (
                        <div className="empty-panel" style={{ marginBottom: '1rem', textAlign: 'left' }}>
                            <h3>Inspection Degraded</h3>
                            <p>{normalizedAgent.inspection_last_error}</p>
                        </div>
                    ) : null}

                    <div className="activity-log">
                        <div className="section-title-row">
                            <h3>Agent Device Coverage</h3>
                            <span className="table-caption">{stats.observed} discovered assets plus the managed endpoint</span>
                        </div>
                        <table>
                            <thead>
                                <tr>
                                    <th>Device IP</th>
                                    <th>Hostname</th>
                                    <th>Mode</th>
                                    <th>Type</th>
                                    <th>OS</th>
                                    <th>Status</th>
                                    <th>Last Seen</th>
                                </tr>
                            </thead>
                            <tbody>
                                {normalizedAgent.devices.length === 0 ? (
                                    <tr>
                                        <td colSpan="7" className="empty-state">No devices are currently mapped to this agent.</td>
                                    </tr>
                                ) : (
                                    normalizedAgent.devices.map((device) => (
                                        <tr key={`${normalizedAgent.agent_id}-${device.ip || 'unknown-device'}`}>
                                            <td className="mono primary">{device.ip}</td>
                                            <td>{device.hostname || 'Unknown'}</td>
                                            <td>
                                                <span className={`badge ${device.management_mode === 'managed' ? 'success' : 'neutral'}`}>
                                                    {device.management_mode === 'managed' ? 'Managed' : 'Observed'}
                                                </span>
                                            </td>
                                            <td>{device.device_type || 'Unknown'}</td>
                                            <td>{device.os_family || 'Unknown'}</td>
                                            <td>
                                                <span
                                                    className={`badge ${
                                                        device.status === 'Online'
                                                            ? 'success'
                                                            : device.status === 'Idle'
                                                                ? 'warning'
                                                                : 'danger'
                                                    }`}
                                                >
                                                    {device.status}
                                                </span>
                                            </td>
                                            <td className="mono muted">{device.last_seen || 'N/A'}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </>
            )}
        </div>
    );
};

export default AgentDetailsPage;

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { agentService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';

const SystemLogsPage = () => {
    const navigate = useNavigate();
    const [agents, setAgents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const normalizedAgents = useMemo(() => {
        if (!Array.isArray(agents)) {
            return [];
        }
        return agents
            .filter((agent) => agent && typeof agent === 'object')
            .map((agent) => ({
                agent_id: agent.agent_id || 'Unknown',
                hostname: agent.hostname || 'Unknown',
                ip_address: agent.ip_address || '-',
                status: agent.status === 'Online' ? 'Online' : 'Offline',
                last_seen: agent.last_seen || 'N/A',
                device_count: Number(agent.device_count) || 0,
            }));
    }, [agents]);

    const fetchAgents = useCallback(async () => {
        try {
            const res = await agentService.getAgents();
            if (Array.isArray(res.data)) {
                setAgents(res.data);
                setError('');
            } else {
                setAgents([]);
                setError(res.data?.message || 'Unable to load agent heartbeat data right now.');
            }
        } catch (err) {
            console.error('Failed to fetch agents', err);
            setAgents([]);
            setError('Unable to load agent heartbeat data right now.');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchAgents();
    }, [fetchAgents]);

    useVisibilityPolling(fetchAgents, 15000);

    const stats = useMemo(() => {
        return normalizedAgents.reduce(
            (acc, agent) => {
                acc.total += 1;
                if (agent.status === 'Online') {
                    acc.online += 1;
                }
                acc.devices += agent.device_count || 0;
                return acc;
            },
            { total: 0, online: 0, devices: 0 },
        );
    }, [normalizedAgents]);

    return (
        <div className="animate-fade">
            <div className="page-hero">
                <div>
                    <div className="page-eyebrow">Agent Monitoring</div>
                    <h2>Connected Agents</h2>
                    <p className="page-subtitle">
                        Heartbeat-backed monitoring for active NetVisor agents. This view tracks which agents are online, when they last checked in, and how many devices each agent is currently covering.
                    </p>
                </div>
                <div className="page-actions">
                    <span className="status-badge pulse">
                        <i className="ri-radar-line"></i> LIVE HEARTBEATS
                    </span>
                    <button className="action-btn" onClick={fetchAgents}>
                        <i className="ri-refresh-line"></i> Refresh
                    </button>
                </div>
            </div>

            <div className="summary-grid">
                <div className="summary-card">
                    <span className="summary-label">Registered Agents</span>
                    <strong>{stats.total}</strong>
                    <span className="summary-meta">agents currently known to the backend</span>
                </div>
                <div className="summary-card">
                    <span className="summary-label">Online Agents</span>
                    <strong>{stats.online}</strong>
                    <span className="summary-meta">{Math.max(stats.total - stats.online, 0)} currently offline</span>
                </div>
                <div className="summary-card">
                    <span className="summary-label">Observed Devices</span>
                    <strong>{stats.devices}</strong>
                    <span className="summary-meta">managed endpoints plus discovered assets</span>
                </div>
            </div>

            {loading ? (
                <div className="loading-state">Loading connected agents...</div>
            ) : error ? (
                <div className="empty-panel">
                    <h3>Agent feed unavailable</h3>
                    <p>{error}</p>
                </div>
            ) : normalizedAgents.length === 0 ? (
                <div className="empty-panel">
                    <h3>No agents connected</h3>
                    <p>Start one or more NetVisor agents and wait for heartbeat registration to populate this page.</p>
                </div>
            ) : (
                <div className="activity-log">
                    <div className="section-title-row">
                        <h3>Agent Fleet</h3>
                        <span className="table-caption">Updated every 5 seconds from agent heartbeat data</span>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Agent ID</th>
                                <th>Host Name</th>
                                <th>IP Address</th>
                                <th>Status</th>
                                <th>Last Seen</th>
                                <th>Device Count</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {normalizedAgents.map((agent) => (
                                <tr key={agent.agent_id}>
                                    <td className="mono primary">{agent.agent_id}</td>
                                    <td>{agent.hostname || 'Unknown'}</td>
                                    <td className="mono">{agent.ip_address || '-'}</td>
                                    <td>
                                        <span className={`badge ${agent.status === 'Online' ? 'success' : 'danger'}`}>
                                            <i className={agent.status === 'Online' ? 'ri-checkbox-blank-circle-fill' : 'ri-close-circle-fill'}></i>
                                            {agent.status}
                                        </span>
                                    </td>
                                    <td className="mono muted">{agent.last_seen || 'N/A'}</td>
                                    <td>{agent.device_count}</td>
                                    <td>
                                        <button
                                            type="button"
                                            className="action-btn ghost"
                                            onClick={() => navigate(`/agents/${encodeURIComponent(agent.agent_id)}`)}
                                        >
                                            <i className="ri-arrow-right-up-line"></i> View details
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
};

export default SystemLogsPage;

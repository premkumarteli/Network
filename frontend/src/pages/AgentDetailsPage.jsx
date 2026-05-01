import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { agentService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import { getStatusTone } from '../utils/presentation';

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
      inspection_ca_status: agent.inspection_ca_status || '',
      inspection_proxy_pid: agent.inspection_proxy_pid ?? null,
      inspection_proxy_port: agent.inspection_proxy_port ?? null,
      inspection_queue_size: Number(agent.inspection_queue_size) || 0,
      inspection_spooled_event_count: Number(agent.inspection_spooled_event_count) || 0,
      inspection_dropped_event_count: Number(agent.inspection_dropped_event_count) || 0,
      inspection_uploaded_event_count: Number(agent.inspection_uploaded_event_count) || 0,
      inspection_upload_failures: Number(agent.inspection_upload_failures) || 0,
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

  const columns = [
    { key: 'ip', label: 'Device IP', render: (row) => <span className="mono">{row.ip}</span> },
    {
      key: 'hostname',
      label: 'Hostname',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.hostname || 'Unknown'}</div>
          <div className="nv-table__meta">{row.device_type || 'Unknown'} · {row.os_family || 'Unknown'}</div>
        </>
      ),
    },
    {
      key: 'mode',
      label: 'Mode',
      render: (row) => <StatusBadge tone={row.management_mode === 'managed' ? 'success' : 'neutral'}>{row.management_mode === 'managed' ? 'Managed' : 'Observed'}</StatusBadge>,
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => <StatusBadge tone={getStatusTone(row.status)}>{row.status}</StatusBadge>,
    },
    { key: 'last_seen', label: 'Last Seen', render: (row) => <span className="mono">{row.last_seen || 'N/A'}</span> },
  ];

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Inventory"
        title={normalizedAgent?.hostname || decodedAgentId}
        description="Inspect one agent’s heartbeat profile, proxy and certificate state, and the device coverage mapped to that agent."
        actions={(
          <>
            <Link className="nv-button nv-button--secondary" to="/agents">
              <i className="ri-arrow-left-line"></i>
              Back
            </Link>
            <button type="button" className="nv-button nv-button--secondary" onClick={fetchAgent}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
          </>
        )}
      />

      {loading ? (
        <div className="nv-metric-grid">
          <MetricCard icon="ri-loader-4-line" label="Loading" value="..." meta="Fetching agent detail" accent="#54c8e8" />
        </div>
      ) : error ? (
        <SectionCard title="Agent feed unavailable" caption="Load Error">
          <p>{error}</p>
        </SectionCard>
      ) : !normalizedAgent ? (
        <SectionCard title="Agent not found" caption="Inventory">
          <p>The selected agent is not available in the current monitoring window.</p>
        </SectionCard>
      ) : (
        <>
          <div className="nv-metric-grid">
            <MetricCard icon="ri-radar-line" label="Heartbeat" value={normalizedAgent.status} meta={`Last seen ${normalizedAgent.last_seen}`} accent="#54c8e8" />
            <MetricCard icon="ri-time-line" label="Heartbeat Age" value={normalizedAgent.heartbeat_age_seconds} meta="Seconds since last heartbeat" accent="#60a5fa" />
            <MetricCard icon="ri-macbook-line" label="Devices" value={normalizedAgent.device_count} meta={`${stats.online} online / ${stats.idle} idle / ${Math.max(stats.total - stats.online - stats.idle, 0)} offline`} accent="#2dd4bf" />
            <MetricCard icon="ri-navigation-line" label="Inspection" value={normalizedAgent.inspection_enabled ? 'Enabled' : 'Disabled'} meta={normalizedAgent.inspection_proxy_running ? 'Proxy running' : normalizedAgent.inspection_status} accent="#fbbf24" />
          </div>

          <div className="nv-grid nv-grid--equal">
            <SectionCard title="Agent Profile" caption="Runtime">
              <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
                <div className="nv-summary-tile">
                  <span>Agent ID</span>
                  <strong className="mono">{normalizedAgent.agent_id}</strong>
                  <p>{normalizedAgent.os_family} · {normalizedAgent.version}</p>
                </div>
                <div className="nv-summary-tile">
                  <span>IP Address</span>
                  <strong className="mono">{normalizedAgent.ip_address}</strong>
                  <p>{normalizedAgent.status}</p>
                </div>
              </div>
            </SectionCard>

            <SectionCard title="Inspection Health" caption="Proxy & CA">
              <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
                <div className="nv-summary-tile">
                  <span>Certificate</span>
                  <strong>{normalizedAgent.inspection_ca_status || (normalizedAgent.inspection_ca_installed ? 'Installed' : 'Missing')}</strong>
                  <p>{normalizedAgent.inspection_browsers.join(', ') || 'Chrome / Edge'}</p>
                </div>
                <div className="nv-summary-tile">
                  <span>Queue</span>
                  <strong>{normalizedAgent.inspection_queue_size}</strong>
                  <p>{normalizedAgent.inspection_uploaded_event_count} uploaded · {normalizedAgent.inspection_upload_failures} failed</p>
                </div>
              </div>
              {normalizedAgent.inspection_last_error ? (
                <StatusBadge tone="warning" icon="ri-error-warning-line">{normalizedAgent.inspection_last_error}</StatusBadge>
              ) : null}
            </SectionCard>
          </div>

          <SectionCard title="Agent Device Coverage" caption="Mapped Assets">
            <DataTable
              columns={columns}
              rows={normalizedAgent.devices}
              rowKey={(row) => `${normalizedAgent.agent_id}-${row.ip || 'unknown'}`}
              emptyTitle="No devices mapped to this agent"
              emptyDescription="The selected agent has not reported any covered devices in the current monitoring window."
            />
          </SectionCard>
        </>
      )}
    </div>
  );
};

export default AgentDetailsPage;

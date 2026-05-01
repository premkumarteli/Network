import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { agentService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import { TableSkeleton } from '../components/UI/Skeletons';
import { getStatusTone, formatPercent } from '../utils/presentation';

const AgentMonitoringPage = () => {
  const navigate = useNavigate();
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

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
        os_family: agent.os_family || 'Unknown',
        version: agent.version || 'Unknown',
        status: agent.status === 'Online' ? 'Online' : 'Offline',
        last_seen: agent.last_seen || 'N/A',
        device_count: Number(agent.device_count) || 0,
        cpu_usage: Number(agent.cpu_usage) || 0,
        ram_usage: Number(agent.ram_usage) || 0,
      }));
  }, [agents]);

  const currentAgent = normalizedAgents[0] || null;

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

  useVisibilityPolling(fetchAgents, 5000);

  const stats = useMemo(() => {
    return normalizedAgents.reduce(
      (acc, agent) => {
        acc.total += 1;
        if (agent.status === 'Online') {
          acc.online += 1;
          acc.avgCpu += agent.cpu_usage;
          acc.avgRam += agent.ram_usage;
        }
        acc.devices += agent.device_count || 0;
        return acc;
      },
      { total: 0, online: 0, devices: 0, avgCpu: 0, avgRam: 0 },
    );
  }, [normalizedAgents]);

  const visibleAgents = useMemo(() => {
    return normalizedAgents.filter((agent) => {
      const matchesStatus = statusFilter === 'all' || agent.status.toLowerCase() === statusFilter;
      const haystack = [agent.agent_id, agent.hostname, agent.ip_address, agent.os_family, agent.version]
        .join(' ')
        .toLowerCase();
      return matchesStatus && haystack.includes(search.trim().toLowerCase());
    });
  }, [normalizedAgents, search, statusFilter]);

  const columns = [
    {
      key: 'agent_id',
      label: 'Agent',
      render: (row) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <div>
            <div className="nv-table__primary mono">{row.agent_id}</div>
            <div className="nv-table__meta">{row.version}</div>
          </div>
          {currentAgent && row.agent_id === currentAgent.agent_id ? (
            <StatusBadge tone="success">Current</StatusBadge>
          ) : null}
        </div>
      ),
    },
    {
      key: 'endpoint',
      label: 'Endpoint',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.hostname}</div>
          <div className="nv-table__meta mono">{row.ip_address} | {row.os_family}</div>
        </>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => <StatusBadge tone={getStatusTone(row.status)}>{row.status}</StatusBadge>,
    },
    {
      key: 'resources',
      label: 'Resources',
      render: (row) => (
        <div className="nv-stack" style={{ gap: '0.45rem' }}>
          <div>
            <div className="nv-table__meta">CPU {formatPercent(row.cpu_usage)}</div>
            <div className="nv-progress">
              <div className="nv-progress__fill" style={{ width: `${Math.min(row.cpu_usage, 100)}%` }}></div>
            </div>
          </div>
          <div>
            <div className="nv-table__meta">RAM {formatPercent(row.ram_usage)}</div>
            <div className="nv-progress">
              <div className="nv-progress__fill" style={{ width: `${Math.min(row.ram_usage, 100)}%` }}></div>
            </div>
          </div>
        </div>
      ),
    },
    {
      key: 'device_count',
      label: 'Devices',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.device_count}</div>
          <div className="nv-table__meta">Covered assets</div>
        </>
      ),
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{row.last_seen}</span>,
    },
  ];

  return (
    <div className="nv-page nv-page--balanced">
      <PageHeader
        eyebrow="Inventory"
        title="Fleet Operations"
        description="Monitor agent health, resource usage, device coverage, and heartbeat quality from one operational table."
        actions={(
          <button type="button" className="nv-button nv-button--secondary" onClick={fetchAgents}>
            <i className="ri-refresh-line"></i>
            Refresh
          </button>
        )}
      >
        {currentAgent ? (
          <div className="nv-pill-card" style={{ width: 'fit-content' }}>
            <div className="nv-pill-card__icon" style={{ color: '#34d399', background: 'rgba(52, 211, 153, 0.14)', borderColor: 'rgba(52, 211, 153, 0.22)' }}>
              <i className="ri-radar-line"></i>
            </div>
            <div className="nv-pill-card__content">
              <strong>{currentAgent.hostname}</strong>
              <span>{currentAgent.agent_id} | {currentAgent.device_count} devices | {currentAgent.status}</span>
            </div>
            <StatusBadge tone={getStatusTone(currentAgent.status)}>
              {currentAgent.status}
            </StatusBadge>
          </div>
        ) : null}
      </PageHeader>

      <div className="nv-metric-grid">
        <MetricCard icon="ri-radar-line" label="Online Agents" value={`${stats.online} / ${stats.total}`} meta="Fleet heartbeat health" accent="#54c8e8" />
        <MetricCard icon="ri-cpu-line" label="Avg CPU" value={stats.online > 0 ? formatPercent(stats.avgCpu / stats.online) : '0%'} meta="Across online agents" accent="#60a5fa" />
        <MetricCard icon="ri-database-2-line" label="Avg RAM" value={stats.online > 0 ? formatPercent(stats.avgRam / stats.online) : '0%'} meta="Distributed memory footprint" accent="#2dd4bf" />
        <MetricCard icon="ri-macbook-line" label="Fleet Devices" value={stats.devices} meta="Total endpoints discovered" accent="#fbbf24" />
      </div>

      <SectionCard title="Agent Registry" caption="Heartbeat and Coverage" className="nv-section--balanced">
        <div className="nv-filterbar">
          <div className="nv-filterbar__group">
            <label className="nv-field nv-field--grow">
              <i className="ri-search-line"></i>
              <input
                type="search"
                placeholder="Search agent, hostname, IP, OS..."
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </label>
            <label className="nv-field">
              <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
                <option value="all">All Status</option>
                <option value="online">Online</option>
                <option value="offline">Offline</option>
              </select>
            </label>
          </div>
        </div>

        {loading ? (
          <div className="nv-scroll-region nv-scroll-region--xl">
            <TableSkeleton rows={6} />
          </div>
        ) : error ? (
          <div className="nv-empty" style={{ background: 'transparent', boxShadow: 'none', border: '0', padding: 0 }}>
            <div className="nv-empty__icon">
              <i className="ri-error-warning-line"></i>
            </div>
            <div className="nv-stack" style={{ gap: '0.5rem' }}>
              <h3 className="nv-empty__title">Fleet feed unavailable</h3>
              <p className="nv-empty__description">{error}</p>
            </div>
          </div>
        ) : (
          <div className="nv-scroll-region nv-scroll-region--xl">
            <DataTable
              columns={columns}
              rows={visibleAgents}
              rowKey={(row) => row.agent_id}
              onRowClick={(row) => navigate(`/agents/${encodeURIComponent(row.agent_id)}`)}
              emptyTitle="No agents in this view"
              emptyDescription="Start one or more NetVisor agents and wait for heartbeat registration to populate the fleet registry."
            />
          </div>
        )}
      </SectionCard>
    </div>
  );
};

export default AgentMonitoringPage;


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
  const [enrollmentRequests, setEnrollmentRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [actionLoading, setActionLoading] = useState('');

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
        enrollment_status: agent.enrollment_status || 'approved',
        enrollment_attempt_count: Number(agent.enrollment_attempt_count) || 0,
        enrollment_review_reason: agent.enrollment_review_reason || '',
        enrollment_request_id: agent.enrollment_request_id || null,
        enrollment_source_ip: agent.enrollment_source_ip || '',
        enrollment_bootstrap_method: agent.enrollment_bootstrap_method || 'bootstrap',
      }));
  }, [agents]);

  const currentAgent = normalizedAgents.find((agent) => agent.status === 'Online') || normalizedAgents[0] || null;

  const normalizedEnrollmentRequests = useMemo(() => {
    if (!Array.isArray(enrollmentRequests)) {
      return [];
    }
    return enrollmentRequests
      .filter((request) => request && typeof request === 'object')
      .map((request) => ({
        request_id: request.request_id || request.agent_id || 'Unknown',
        agent_id: request.agent_id || 'Unknown',
        hostname: request.hostname || 'Unknown',
        device_ip: request.device_ip || '-',
        device_mac: request.device_mac || '-',
        os_family: request.os_family || 'Unknown',
        agent_version: request.agent_version || 'Unknown',
        bootstrap_method: request.bootstrap_method || 'bootstrap',
        source_ip: request.source_ip || '-',
        machine_fingerprint: request.machine_fingerprint || '',
        status: request.status || 'pending_review',
        attempt_count: Number(request.attempt_count) || 0,
        first_seen: request.first_seen || 'N/A',
        last_seen: request.last_seen || 'N/A',
        expires_at: request.expires_at || null,
        reviewed_by: request.reviewed_by || '-',
        reviewed_at: request.reviewed_at || '-',
        review_reason: request.review_reason || '',
        credential_issued_at: request.credential_issued_at || null,
      }));
  }, [enrollmentRequests]);

  const pendingRequests = useMemo(
    () => normalizedEnrollmentRequests.filter((request) => String(request.status || '').toLowerCase() === 'pending_review'),
    [normalizedEnrollmentRequests],
  );

  const reviewedRequests = useMemo(
    () => normalizedEnrollmentRequests.filter((request) => String(request.status || '').toLowerCase() !== 'pending_review'),
    [normalizedEnrollmentRequests],
  );

  const fetchAgents = useCallback(async () => {
    try {
      const [agentsResult, requestsResult] = await Promise.allSettled([
        agentService.getAgents(),
        agentService.getEnrollmentRequests(),
      ]);

      const nextAgents = agentsResult.status === 'fulfilled' && Array.isArray(agentsResult.value.data)
        ? agentsResult.value.data
        : [];
      const nextRequests = requestsResult.status === 'fulfilled' && Array.isArray(requestsResult.value.data)
        ? requestsResult.value.data
        : [];

      setAgents(nextAgents);
      setEnrollmentRequests(nextRequests);

      const agentsFailed = agentsResult.status === 'rejected';
      const requestsFailed = requestsResult.status === 'rejected';
      if (agentsFailed && requestsFailed) {
        setError('Unable to load fleet and enrollment data right now.');
      } else if (agentsFailed) {
        setError('Unable to load agent heartbeat data right now.');
      } else {
        setError('');
      }
    } catch (err) {
      console.error('Failed to fetch agents', err);
      setAgents([]);
      setEnrollmentRequests([]);
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
      { total: 0, online: 0, devices: 0, avgCpu: 0, avgRam: 0, pendingEnrollments: pendingRequests.length },
    );
  }, [normalizedAgents, pendingRequests.length]);

  const visibleAgents = useMemo(() => {
    return normalizedAgents.filter((agent) => {
      const matchesStatus = statusFilter === 'all' || agent.status.toLowerCase() === statusFilter;
      const haystack = [agent.agent_id, agent.hostname, agent.ip_address, agent.os_family, agent.version, agent.enrollment_status]
        .join(' ')
        .toLowerCase();
      return matchesStatus && haystack.includes(search.trim().toLowerCase());
    });
  }, [normalizedAgents, search, statusFilter]);

  const formatEnrollmentStatus = useCallback((value) => {
    const normalized = String(value || 'approved').toLowerCase();
    if (normalized === 'pending_review' || normalized === 'pending') return 'Pending Approval';
    if (normalized === 'approved') return 'Approved';
    if (normalized === 'rejected') return 'Rejected';
    if (normalized === 'revoked') return 'Revoked';
    if (normalized === 'expired') return 'Expired';
    return normalized.replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
  }, []);

  const promptForReason = useCallback((actionLabel) => {
    const reason = window.prompt(`${actionLabel} reason is required.`, '');
    const normalized = String(reason || '').trim();
    if (!normalized) {
      return null;
    }
    return normalized;
  }, []);

  const handleEnrollmentAction = useCallback(async (requestId, action) => {
    const label = action === 'approve' ? 'Approve' : 'Reject';
    const reviewReason = promptForReason(label);
    if (!reviewReason) {
      return;
    }

    const loadingKey = `${action}:${requestId}`;
    setActionLoading(loadingKey);
    try {
      if (action === 'approve') {
        await agentService.approveEnrollmentRequest(requestId, reviewReason);
      } else {
        await agentService.rejectEnrollmentRequest(requestId, reviewReason);
      }
      await fetchAgents();
    } catch (err) {
      console.error(`Failed to ${action} enrollment request`, err);
      setError(`Unable to ${action} the enrollment request right now.`);
    } finally {
      setActionLoading('');
    }
  }, [fetchAgents, promptForReason]);

  const handleRevokeAgent = useCallback(async (agentId, agentLabel) => {
    const reviewReason = promptForReason(`Revoke access for ${agentLabel}`);
    if (!reviewReason) {
      return;
    }

    const loadingKey = `revoke:${agentId}`;
    setActionLoading(loadingKey);
    try {
      await agentService.revokeAgent(agentId, reviewReason);
      await fetchAgents();
    } catch (err) {
      console.error('Failed to revoke agent enrollment', err);
      setError('Unable to revoke the agent right now.');
    } finally {
      setActionLoading('');
    }
  }, [fetchAgents, promptForReason]);

  const pendingColumns = [
    {
      key: 'agent',
      label: 'Agent',
      render: (row) => (
        <div className="nv-stack" style={{ gap: '0.35rem' }}>
          <div className="nv-table__primary mono">{row.agent_id}</div>
          <div className="nv-table__meta">{row.agent_version}</div>
        </div>
      ),
    },
    {
      key: 'endpoint',
      label: 'Endpoint',
      render: (row) => (
        <div className="nv-stack" style={{ gap: '0.35rem' }}>
          <div className="nv-table__primary">{row.hostname}</div>
          <div className="nv-table__meta mono">{row.device_ip} | {row.os_family}</div>
          <div className="nv-table__meta mono">{row.device_mac} | src {row.source_ip}</div>
        </div>
      ),
    },
    {
      key: 'evidence',
      label: 'Trust Evidence',
      render: (row) => (
        <div className="nv-stack" style={{ gap: '0.35rem' }}>
          <div className="nv-table__meta">Bootstrapped via {row.bootstrap_method}</div>
          <div className="nv-table__meta mono">fp {String(row.machine_fingerprint || '').slice(0, 12) || '-'}</div>
          <div className="nv-table__meta">Attempts {row.attempt_count} | First seen {row.first_seen}</div>
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => <StatusBadge tone={getStatusTone(row.status)}>{formatEnrollmentStatus(row.status)}</StatusBadge>,
    },
    {
      key: 'action',
      label: 'Action',
      render: (row) => (
        <div className="nv-stack" style={{ gap: '0.45rem' }}>
          <button
            type="button"
            className="nv-button nv-button--primary"
            style={{ width: 'fit-content', padding: '0.45rem 0.8rem' }}
            onClick={(event) => {
              event.stopPropagation();
              handleEnrollmentAction(row.request_id, 'approve');
            }}
            disabled={actionLoading === `approve:${row.request_id}` || actionLoading === `reject:${row.request_id}`}
          >
            Approve
          </button>
          <button
            type="button"
            className="nv-button nv-button--danger"
            style={{ width: 'fit-content', padding: '0.45rem 0.8rem' }}
            onClick={(event) => {
              event.stopPropagation();
              handleEnrollmentAction(row.request_id, 'reject');
            }}
            disabled={actionLoading === `approve:${row.request_id}` || actionLoading === `reject:${row.request_id}`}
          >
            Reject
          </button>
        </div>
      ),
    },
  ];

  const historyColumns = [
    {
      key: 'agent',
      label: 'Agent',
      render: (row) => (
        <div className="nv-stack" style={{ gap: '0.35rem' }}>
          <div className="nv-table__primary mono">{row.agent_id}</div>
          <div className="nv-table__meta">{row.hostname} | {row.agent_version}</div>
        </div>
      ),
    },
    {
      key: 'decision',
      label: 'Decision',
      render: (row) => <StatusBadge tone={getStatusTone(row.status)}>{formatEnrollmentStatus(row.status)}</StatusBadge>,
    },
    {
      key: 'review',
      label: 'Reviewed',
      render: (row) => (
        <div className="nv-stack" style={{ gap: '0.35rem' }}>
          <div className="nv-table__meta">{row.reviewed_by}</div>
          <div className="nv-table__meta mono">{row.reviewed_at || 'N/A'}</div>
        </div>
      ),
    },
    {
      key: 'reason',
      label: 'Reason',
      render: (row) => (
        <div className="nv-table__meta" title={row.review_reason || ''}>
          {row.review_reason || 'No reason recorded'}
        </div>
      ),
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{row.last_seen}</span>,
    },
  ];

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
      key: 'enrollment_status',
      label: 'Enrollment',
      render: (row) => (
        <div className="nv-stack" style={{ gap: '0.4rem' }}>
          <StatusBadge tone={getStatusTone(row.enrollment_status)}>
            {formatEnrollmentStatus(row.enrollment_status)}
          </StatusBadge>
          <div className="nv-table__meta">
            {row.enrollment_attempt_count > 0 ? `${row.enrollment_attempt_count} request${row.enrollment_attempt_count === 1 ? '' : 's'}` : 'Fleet controlled'}
          </div>
          {row.enrollment_status === 'approved' ? (
            <button
              type="button"
              className="nv-button nv-button--danger"
              style={{ width: 'fit-content', padding: '0.45rem 0.8rem' }}
              onClick={(event) => {
                event.stopPropagation();
                handleRevokeAgent(row.agent_id, row.hostname);
              }}
              disabled={actionLoading === `revoke:${row.agent_id}`}
            >
              Revoke
            </button>
          ) : null}
        </div>
      ),
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
        {pendingRequests.length > 0 ? (
          <div className="nv-pill-card" style={{ width: 'fit-content' }}>
            <div className="nv-pill-card__icon" style={{ color: '#f59e0b', background: 'rgba(245, 158, 11, 0.14)', borderColor: 'rgba(245, 158, 11, 0.22)' }}>
              <i className="ri-shield-user-line"></i>
            </div>
            <div className="nv-pill-card__content">
              <strong>{pendingRequests.length} Pending Approval{pendingRequests.length === 1 ? '' : 's'}</strong>
              <span>New agents are waiting for Fleet review before they receive credentials.</span>
            </div>
            <StatusBadge tone="warning">
              Review Queue
            </StatusBadge>
          </div>
        ) : currentAgent ? (
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
        <MetricCard icon="ri-shield-user-line" label="Pending Approvals" value={pendingRequests.length} meta="Waiting for Fleet review" accent="#f59e0b" />
        <MetricCard icon="ri-macbook-line" label="Fleet Devices" value={stats.devices} meta="Total endpoints discovered" accent="#fbbf24" />
      </div>

      <SectionCard
        title="Pending Enrollment"
        caption="Fleet approval queue"
        className="nv-section--balanced"
      >
        <div className="nv-stack" style={{ gap: '1rem' }}>
          <div className="nv-table__meta" style={{ lineHeight: 1.6 }}>
            New agents stay here until an admin approves them. Approved agents receive signed credentials on their next bootstrap poll.
          </div>
          <div className="nv-scroll-region nv-scroll-region--xl">
            <DataTable
              columns={pendingColumns}
              rows={pendingRequests}
              rowKey={(row) => row.request_id}
              emptyTitle="No pending enrollment requests"
              emptyDescription="First-time agents will appear here when they contact the server for approval."
            />
          </div>
        </div>
      </SectionCard>

      {reviewedRequests.length > 0 ? (
        <SectionCard
          title="Enrollment History"
          caption="Reviewed requests"
          className="nv-section--balanced"
        >
          <div className="nv-scroll-region nv-scroll-region--xl">
            <DataTable
              columns={historyColumns}
              rows={reviewedRequests.slice(0, 8)}
              rowKey={(row) => row.request_id}
              emptyTitle="No reviewed enrollment requests"
              emptyDescription="Approved, rejected, expired, and revoked requests will appear here."
            />
          </div>
        </SectionCard>
      ) : null}

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


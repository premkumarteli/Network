import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWebSocket } from '../hooks/useWebSocket';
import { systemService } from '../services/api';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import WebEvidenceDrawer from '../components/DPI/WebEvidenceDrawer';
import { TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatBrowserLabel, getRiskTone } from '../utils/presentation';
import { getWebEvidencePrimaryLabel, getWebEvidenceScopeLabel, matchesWebEvidenceFilters, normalizeWebRiskLevel } from '../utils/webEvidence';

const MAX_EVENTS = 100;

const DpiDashboard = () => {
  const navigate = useNavigate();
  const [events, setEvents] = useState([]);
  const [evidenceGroups, setEvidenceGroups] = useState([]);
  const [status, setStatus] = useState({ state: 'disabled', proxy: 'stopped', certificate: 'not_installed', lastActivity: null, eps: 0 });
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ query: '', domain: '', risk: 'all' });
  const [selectedEvidence, setSelectedEvidence] = useState(null);

  const fetchData = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const [statusRes, eventsRes, groupsRes] = await Promise.all([
        systemService.getDpiGlobalStatus(),
        systemService.getGlobalWebActivity(100),
        systemService.getGlobalWebEvidenceGroups(50),
      ]);
      setStatus(statusRes.data || { state: 'disabled', proxy: 'stopped', certificate: 'not_installed', lastActivity: null, eps: 0 });
      const payload = Array.isArray(eventsRes.data) ? eventsRes.data : (eventsRes.data?.activity || []);
      setEvents(payload);
      const groupedPayload = Array.isArray(groupsRes.data) ? groupsRes.data : (groupsRes.data?.activity || []);
      setEvidenceGroups(groupedPayload);
    } catch (error) {
      console.error('Failed to load DPI dashboard', error);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleDpiEvent = useCallback((event) => {
    setEvents((prev) => [{ ...event, isNew: true }, ...prev].slice(0, MAX_EVENTS));
    setStatus((current) => ({ ...current, lastActivity: event.timestamp || event.last_seen }));
  }, []);

  const { status: wsStatus } = useWebSocket('dpi_event', handleDpiEvent);

  const filteredEvents = useMemo(
    () => events.filter((event) => matchesWebEvidenceFilters(event, filters)),
    [events, filters],
  );

  const filteredGroups = useMemo(
    () => evidenceGroups.filter((event) => matchesWebEvidenceFilters(event, filters)),
    [evidenceGroups, filters],
  );

  const groupedColumns = [
    {
      key: 'activity',
      label: 'Activity',
      render: (row) => (
        <>
          <div className="nv-table__primary">{getWebEvidencePrimaryLabel(row)}</div>
          <div className="nv-table__meta">{row.base_domain || row.page_url || '-'}</div>
          <div className="nv-table__meta">{getWebEvidenceScopeLabel(row).text}</div>
        </>
      ),
    },
    {
      key: 'device',
      label: 'Device',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.device_ip || '-'}</div>
          <div className="nv-table__meta">{formatBrowserLabel(row.browser_name, row.process_name)}</div>
        </>
      ),
    },
    {
      key: 'scope',
      label: 'Scope',
      render: (row) => (
        <>
          <div className="nv-table__primary">{getWebEvidenceScopeLabel(row).eventCount} event{getWebEvidenceScopeLabel(row).eventCount === 1 ? '' : 's'}</div>
          <div className="nv-table__meta">{row.content_id || row.content_category || 'web'}</div>
        </>
      ),
    },
    {
      key: 'risk',
      label: 'Risk',
      render: (row) => {
        const riskLevel = normalizeWebRiskLevel(row.risk_level);
        return <StatusBadge tone={getRiskTone(riskLevel)}>{riskLevel}</StatusBadge>;
      },
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen || row.timestamp || row.created_at)}</span>,
    },
  ];

  const rawColumns = [
    {
      key: 'activity',
      label: 'Activity',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.page_title || 'Untitled page'}</div>
          <div className="nv-table__meta">{row.page_url || row.base_domain || row.domain || '-'}</div>
        </>
      ),
    },
    {
      key: 'device',
      label: 'Device',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.device_ip || '-'}</div>
          <div className="nv-table__meta">{formatBrowserLabel(row.browser_name, row.process_name)}</div>
        </>
      ),
    },
    {
      key: 'category',
      label: 'Category',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.content_category || 'web'}</div>
          <div className="nv-table__meta">{row.search_query || row.content_id || '-'}</div>
        </>
      ),
    },
    {
      key: 'risk',
      label: 'Risk',
      render: (row) => {
        const riskLevel = normalizeWebRiskLevel(row.risk_level);
        return <StatusBadge tone={getRiskTone(riskLevel)}>{riskLevel}</StatusBadge>;
      },
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen || row.timestamp || row.created_at)}</span>,
    },
  ];

  return (
    <div className="nv-page nv-page--balanced">
      <PageHeader
        eyebrow="Investigation"
        title="Web Inspection"
        description="Operate the browser-inspection feed from one evidence-first workspace with consistent filters and direct device drill-down."
        actions={(
          <>
            <StatusBadge tone={wsStatus === 'connected' ? 'success' : 'warning'} icon="ri-broadcast-line">
              {wsStatus === 'connected' ? 'Live Feed' : 'Reconnecting'}
            </StatusBadge>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchData()}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
          </>
        )}
      />

      <div className="nv-metric-grid">
        <MetricCard icon="ri-navigation-line" label="Inspection State" value={status.state} meta="Global inspection posture" accent="#54c8e8" />
        <MetricCard icon="ri-route-line" label="Proxy" value={status.proxy} meta="Agent-side explicit proxy" accent="#60a5fa" />
        <MetricCard icon="ri-award-line" label="Certificate" value={status.certificate} meta="Root CA trust state" accent="#2dd4bf" />
        <MetricCard icon="ri-flashlight-line" label="Events / Sec" value={(Number(status.eps) || 0).toFixed(1)} meta={status.lastActivity ? `Last activity ${formatUtcTimestampToLocal(status.lastActivity)}` : 'No recent activity'} accent="#fbbf24" />
      </div>

      <SectionCard title="Evidence Groups" caption="Correlated Browser Sessions" className="nv-section--balanced">
        <div className="nv-filterbar">
          <div className="nv-filterbar__group">
            <label className="nv-field nv-field--grow">
              <i className="ri-search-line"></i>
              <input
                type="search"
                placeholder="Search title, URL, browser, query..."
                value={filters.query}
                onChange={(event) => setFilters((current) => ({ ...current, query: event.target.value }))}
              />
            </label>
            <label className="nv-field">
              <input
                type="text"
                placeholder="Domain..."
                value={filters.domain}
                onChange={(event) => setFilters((current) => ({ ...current, domain: event.target.value }))}
              />
            </label>
            <label className="nv-field">
              <select value={filters.risk} onChange={(event) => setFilters((current) => ({ ...current, risk: event.target.value }))}>
                <option value="all">All Risk</option>
                <option value="safe">Safe</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>
          </div>
        </div>

        <div className="nv-scroll-region nv-scroll-region--xl">
          {loading ? (
            <TableSkeleton rows={6} />
          ) : (
            <DataTable
              columns={groupedColumns}
              rows={filteredGroups}
              rowKey={(row, index) => row.group_key || `${row.page_url || row.base_domain}-${index}`}
              onRowClick={(row) => setSelectedEvidence(row)}
              emptyTitle="No grouped evidence detected"
              emptyDescription="Enable inspection on a managed device and browse through the NetVisor launchers to populate correlated evidence clusters."
            />
          )}
        </div>
      </SectionCard>

      <SectionCard title="Raw Browser Sessions" caption="Global Feed" className="nv-section--balanced">
        <div className="nv-scroll-region nv-scroll-region--xl">
          {loading ? (
            <TableSkeleton rows={6} />
          ) : (
            <DataTable
              columns={rawColumns}
              rows={filteredEvents}
              rowKey={(row, index) => row.id || `${row.page_url || row.base_domain}-${index}`}
              onRowClick={(row) => {
                if (row.device_ip) {
                  navigate(`/user/${encodeURIComponent(row.device_ip)}`);
                }
              }}
              emptyTitle="No DPI activity detected"
              emptyDescription="Ensure inspection is enabled on a managed device, the proxy is running, and browsing happens through the NetVisor launchers."
            />
          )}
        </div>
      </SectionCard>

      <WebEvidenceDrawer
        open={Boolean(selectedEvidence)}
        item={selectedEvidence}
        onClose={() => setSelectedEvidence(null)}
        footer={selectedEvidence ? (
          <div className="nv-inline-actions">
            {selectedEvidence.device_ip ? (
              <>
                <button type="button" className="nv-button nv-button--secondary" onClick={() => navigate(`/user/${encodeURIComponent(selectedEvidence.device_ip)}`)}>
                  Open Device
                </button>
                <button type="button" className="nv-button nv-button--primary" onClick={() => navigate(`/user/${encodeURIComponent(selectedEvidence.device_ip)}/web-activity`)}>
                  Open Deep Dive
                </button>
              </>
            ) : null}
          </div>
        ) : null}
      />
    </div>
  );
};

export default DpiDashboard;

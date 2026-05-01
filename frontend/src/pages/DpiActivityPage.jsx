import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { systemService } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import Tabs from '../components/V2/Tabs';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import WebEvidenceDrawer from '../components/DPI/WebEvidenceDrawer';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatBrowserLabel, getRiskTone } from '../utils/presentation';
import { getWebEvidencePrimaryLabel, getWebEvidenceScopeLabel, normalizeWebRiskLevel } from '../utils/webEvidence';

const DpiActivityPage = () => {
  const { deviceIp } = useParams();
  const decodedIp = decodeURIComponent(deviceIp);
  const [events, setEvents] = useState([]);
  const [evidenceGroups, setEvidenceGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [deviceInfo, setDeviceInfo] = useState(null);
  const [filter, setFilter] = useState('all');
  const [selectedEvent, setSelectedEvent] = useState(null);

  const fetchActivity = useCallback(async () => {
    try {
      const [activityRes, groupsRes] = await Promise.all([
        systemService.getDeviceWebActivity(decodedIp),
        systemService.getDeviceWebEvidenceGroups(decodedIp),
      ]);
      setEvents(activityRes.data?.activity || []);
      setEvidenceGroups(groupsRes.data?.activity || []);

      const devices = await systemService.getDevices();
      const device = (devices.data || []).find((entry) => entry.ip === decodedIp);
      setDeviceInfo(device || null);
    } catch (err) {
      console.error('Failed to fetch activity', err);
    } finally {
      setLoading(false);
    }
  }, [decodedIp]);

  useEffect(() => {
    fetchActivity();
  }, [fetchActivity]);

  const handleDpiEvent = useCallback((event) => {
    if (event.device_ip === decodedIp) {
      setEvents((prev) => [event, ...prev].slice(0, 100));
    }
  }, [decodedIp]);

  useWebSocket('dpi_event', handleDpiEvent);

  const filteredEvents = useMemo(() => {
    if (filter === 'all') return events;
    if (filter === 'threats') {
      return events.filter((entry) => normalizeWebRiskLevel(entry.risk_level) !== 'safe');
    }
    return events.filter((entry) => entry.content_category === filter);
  }, [events, filter]);

  const filteredGroups = useMemo(() => {
    if (filter === 'all') return evidenceGroups;
    if (filter === 'threats') return evidenceGroups.filter((entry) => normalizeWebRiskLevel(entry.risk_level) !== 'safe');
    return evidenceGroups.filter((entry) => entry.content_category === filter);
  }, [evidenceGroups, filter]);

  const stats = useMemo(() => {
    const total = events.length;
    const threats = events.filter((entry) => normalizeWebRiskLevel(entry.risk_level) !== 'safe').length;
    const streaming = events.filter((entry) => entry.content_category === 'streaming').length;
    return { total, threats, streaming };
  }, [events]);

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
      key: 'browser',
      label: 'Browser',
      render: (row) => (
        <>
          <div className="nv-table__primary">{formatBrowserLabel(row.browser_name, row.process_name)}</div>
          <div className="nv-table__meta">{row.process_name || '-'}</div>
        </>
      ),
    },
    {
      key: 'scope',
      label: 'Scope',
      render: (row) => (
        <>
          <div className="nv-table__primary">{getWebEvidenceScopeLabel(row).eventCount} event{getWebEvidenceScopeLabel(row).eventCount === 1 ? '' : 's'}</div>
          <div className="nv-table__meta">{row.content_category || row.content_id || 'web'}</div>
        </>
      ),
    },
    {
      key: 'risk',
      label: 'Security',
      render: (row) => {
        const riskLevel = normalizeWebRiskLevel(row.risk_level);
        return <StatusBadge tone={getRiskTone(riskLevel)}>{riskLevel}</StatusBadge>;
      },
    },
    {
      key: 'time',
      label: 'Last Seen',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen || row.timestamp)}</span>,
    },
  ];

  const rawColumns = [
    {
      key: 'activity',
      label: 'Activity',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.page_title || 'Untitled page'}</div>
          <div className="nv-table__meta">{row.page_url || row.base_domain || '-'}</div>
        </>
      ),
    },
    {
      key: 'domain',
      label: 'Domain',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.base_domain || row.domain || '-'}</div>
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
      key: 'time',
      label: 'Time',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen || row.timestamp)}</span>,
    },
    {
      key: 'risk',
      label: 'Security',
      render: (row) => {
        const riskLevel = normalizeWebRiskLevel(row.risk_level);
        return <StatusBadge tone={getRiskTone(riskLevel)}>{riskLevel}</StatusBadge>;
      },
    },
  ];

  return (
    <div className="nv-page nv-page--balanced">
      <PageHeader
        eyebrow="Investigation"
        title={`Browser Activity · ${deviceInfo?.hostname || decodedIp}`}
        description="Drill into one device’s inspected browser sessions with category filtering, security context, and redacted evidence on demand."
        actions={(
          <>
            <Link className="nv-button nv-button--secondary" to={`/user/${encodeURIComponent(decodedIp)}`}>
              <i className="ri-arrow-left-line"></i>
              Back
            </Link>
            <button type="button" className="nv-button nv-button--secondary" onClick={fetchActivity}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
          </>
        )}
      />

      <div className="nv-metric-grid">
        <MetricCard icon="ri-navigation-line" label="Total Requests" value={stats.total} meta="Captured in current session view" accent="#54c8e8" />
        <MetricCard icon="ri-shield-flash-line" label="Threats" value={stats.threats} meta="Blacklist or suspicious matches" accent="#fb7185" />
        <MetricCard icon="ri-video-line" label="Streaming" value={stats.streaming} meta="Video and media browsing sessions" accent="#60a5fa" />
        <MetricCard icon="ri-macbook-line" label="Device" value={deviceInfo?.ip || decodedIp} meta={deviceInfo?.hostname || 'Unknown host'} accent="#2dd4bf" />
      </div>

      <SectionCard title="Evidence Groups" caption="Device Deep Dive" className="nv-section--balanced">
        <Tabs
          value={filter}
          onChange={setFilter}
          items={[
            { value: 'all', label: 'All Traffic', icon: 'ri-apps-line' },
            { value: 'streaming', label: 'Streaming', icon: 'ri-movie-line' },
            { value: 'search', label: 'Search', icon: 'ri-search-line' },
            { value: 'ai', label: 'AI', icon: 'ri-robot-2-line' },
            { value: 'dev', label: 'Dev Tools', icon: 'ri-code-s-slash-line' },
            { value: 'threats', label: 'Threats', icon: 'ri-shield-flash-line' },
          ]}
        />

        <div className="nv-scroll-region nv-scroll-region--xl">
          <DataTable
            columns={groupedColumns}
            rows={loading ? [] : filteredGroups}
            rowKey={(row, index) => row.id || `${row.page_url || row.base_domain}-${index}`}
            onRowClick={(row) => setSelectedEvent(row)}
            emptyTitle={loading ? 'Loading browser activity' : 'No grouped evidence matches this filter'}
            emptyDescription={loading ? 'Collecting the current inspection window.' : 'Change the filter or wait for new inspected sessions to arrive.'}
          />
        </div>
      </SectionCard>

      <SectionCard title="Raw Sessions" caption="Device Deep Dive" className="nv-section--balanced">
        <div className="nv-scroll-region nv-scroll-region--xl">
          <DataTable
            columns={rawColumns}
            rows={loading ? [] : filteredEvents}
            rowKey={(row, index) => row.id || `${row.page_url || row.base_domain}-${index}`}
            onRowClick={(row) => setSelectedEvent(row)}
            emptyTitle={loading ? 'Loading browser activity' : 'No activity matches this filter'}
            emptyDescription={loading ? 'Collecting the current inspection window.' : 'Change the filter or wait for new inspected sessions to arrive.'}
          />
        </div>
      </SectionCard>

      <WebEvidenceDrawer
        open={Boolean(selectedEvent)}
        item={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        footer={selectedEvent?.device_ip ? (
          <div className="nv-inline-actions">
            <button
              type="button"
              className="nv-button nv-button--secondary"
              onClick={() => navigate(`/user/${encodeURIComponent(selectedEvent.device_ip)}`)}
            >
              Open Device Workspace
            </button>
          </div>
        ) : null}
      />
    </div>
  );
};

export default DpiActivityPage;


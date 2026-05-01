import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { useWebSocket } from '../hooks/useWebSocket';
import TrafficChart from '../components/Dashboard/TrafficChart';
import ThreatDistributionChart from '../components/Dashboard/ThreatDistributionChart';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import StatusBadge from '../components/V2/StatusBadge';
import Tabs from '../components/V2/Tabs';
import DataTable from '../components/V2/DataTable';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatBrowserLabel, formatByteCount, getRiskTone } from '../utils/presentation';
import EvidenceDrawer from '../components/V2/EvidenceDrawer';

const DashboardPage = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({});
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [activity, setActivity] = useState([]);
  const [webActivity, setWebActivity] = useState([]);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [analytics, setAnalytics] = useState({
    top_applications: [],
    top_devices: [],
    top_conversations: [],
    traffic_scopes: [],
    traffic_trend: [],
    uncategorized_domains: [],
    summary: {},
  });
  const [analyticsTab, setAnalyticsTab] = useState('applications');
  const [selectedEvent, setSelectedEvent] = useState(null);

  const fetchDashboard = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }

    try {
      const [statsRes, devicesRes, alertsRes, activityRes, webRes, historyRes, analyticsRes] = await Promise.all([
        systemService.getStats(),
        systemService.getDevices(),
        systemService.getAlerts({ severity: 'HIGH,CRITICAL', resolved: false, hours: 24, limit: 12 }),
        systemService.getActivity(18),
        systemService.getGlobalWebActivity(12),
        systemService.getTrafficHistory(24),
        systemService.getAnalyticsOverview(24, 6),
      ]);

      setStats(statsRes.data || {});
      setDevices(devicesRes.data || []);
      setAlerts(alertsRes.data || []);
      setActivity(activityRes.data || []);
      setWebActivity(Array.isArray(webRes.data) ? webRes.data : (webRes.data?.activity || []));
      setTrafficHistory(historyRes.data || []);
      setAnalytics(analyticsRes.data || {
        top_applications: [],
        top_devices: [],
        top_conversations: [],
        traffic_scopes: [],
        traffic_trend: [],
        uncategorized_domains: [],
        summary: {},
      });
    } catch (error) {
      console.error('Failed to load dashboard', error);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  useVisibilityPolling(() => fetchDashboard({ background: true }), 15000);

  const handlePacketEvent = useCallback((event) => {
    setActivity((current) => [event, ...current].slice(0, 18));
  }, []);

  const { status: wsStatus } = useWebSocket('packet_event', handlePacketEvent);

  const managedDevices = useMemo(
    () => devices.filter((device) => device.management_mode === 'managed'),
    [devices],
  );

  const inspectedCoverage = useMemo(() => {
    if (managedDevices.length === 0) {
      return 0;
    }
    const inspectedIps = new Set(webActivity.map((entry) => entry.device_ip).filter(Boolean));
    const covered = managedDevices.filter((device) => inspectedIps.has(device.ip)).length;
    return Math.round((covered / managedDevices.length) * 100);
  }, [managedDevices, webActivity]);

  const trafficChartData = useMemo(() => ({
    labels: trafficHistory.map((entry) => {
      const raw = String(entry.hour || '').split(' ').pop() || '';
      return raw.slice(0, 5);
    }),
    values: trafficHistory.map((entry) => Number(entry.byte_count || 0) / (1024 * 1024)),
  }), [trafficHistory]);

  const analyticsTabs = [
    { value: 'applications', label: 'Applications', icon: 'ri-apps-2-line' },
    { value: 'devices', label: 'Devices', icon: 'ri-macbook-line' },
    { value: 'conversations', label: 'Conversations', icon: 'ri-links-line' },
    { value: 'scopes', label: 'Scopes', icon: 'ri-radar-line' },
  ];

  const analyticsColumns = useMemo(() => {
    switch (analyticsTab) {
      case 'devices':
        return [
          {
            key: 'device',
            label: 'Device',
            render: (row) => (
              <>
                <div className="nv-table__primary mono">{row.hostname || row.device_ip || 'Unknown device'}</div>
                <div className="nv-table__meta mono">{row.device_ip || '-'}</div>
              </>
            ),
          },
          {
            key: 'coverage',
            label: 'Coverage',
            render: (row) => (
              <>
                <div className="nv-table__primary">{row.management_mode || 'byod'}</div>
                <div className="nv-table__meta">{row.status || 'Offline'} | {row.top_application || 'Other'}</div>
              </>
            ),
          },
          {
            key: 'bandwidth',
            label: 'Bandwidth',
            render: (row) => <span className="mono">{row.bandwidth || formatByteCount(row.bandwidth_bytes || 0)}</span>,
          },
          {
            key: 'last_seen',
            label: 'Last Seen',
            render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen)}</span>,
          },
        ];
      case 'conversations':
        return [
          {
            key: 'conversation',
            label: 'Conversation',
            render: (row) => (
              <>
                <div className="nv-table__primary mono">{row.src_ip || '-'} <span className="nv-table__meta">-&gt;</span> {row.dst_ip || '-'}</div>
                <div className="nv-table__meta">{row.host || '-'}</div>
              </>
            ),
          },
          {
            key: 'application',
            label: 'App / Proto',
            render: (row) => (
              <>
                <div className="nv-table__primary">{row.application || 'Other'}</div>
                <div className="nv-table__meta mono">{row.protocol || 'UNKNOWN'}</div>
              </>
            ),
          },
          {
            key: 'bandwidth',
            label: 'Bandwidth',
            render: (row) => <span className="mono">{row.bandwidth || formatByteCount(row.bandwidth_bytes || 0)}</span>,
          },
          {
            key: 'last_seen',
            label: 'Last Seen',
            render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen)}</span>,
          },
        ];
      case 'scopes':
        return [
          {
            key: 'scope',
            label: 'Scope',
            render: (row) => (
              <>
                <div className="nv-table__primary">{row.network_scope || 'unknown'}</div>
                <div className="nv-table__meta">Traffic edge summary</div>
              </>
            ),
          },
          {
            key: 'devices',
            label: 'Devices',
            render: (row) => (
              <>
                <div className="nv-table__primary">{row.device_count || 0}</div>
                <div className="nv-table__meta">{row.flow_count || 0} flows</div>
              </>
            ),
          },
          {
            key: 'bandwidth',
            label: 'Bandwidth',
            render: (row) => <span className="mono">{row.bandwidth || formatByteCount(row.bandwidth_bytes || 0)}</span>,
          },
          {
            key: 'last_seen',
            label: 'Last Seen',
            render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen)}</span>,
          },
        ];
      case 'applications':
      default:
        return [
          {
            key: 'application',
            label: 'Application',
            render: (row) => (
              <>
                <div className="nv-table__primary">{row.application || 'Other'}</div>
                <div className="nv-table__meta">{row.live_domain || row.last_seen || '24h window'}</div>
              </>
            ),
          },
          {
            key: 'devices',
            label: 'Devices',
            render: (row) => (
              <>
                <div className="nv-table__primary">{row.active_device_count || row.device_count || 0}</div>
                <div className="nv-table__meta">{row.device_count || 0} visible</div>
              </>
            ),
          },
          {
            key: 'bandwidth',
            label: 'Bandwidth',
            render: (row) => <span className="mono">{row.bandwidth || formatByteCount(row.bandwidth_bytes || 0)}</span>,
          },
          {
            key: 'last_seen',
            label: 'Last Seen',
            render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen)}</span>,
          },
        ];
    }
  }, [analyticsTab]);

  const analyticsRows = useMemo(() => {
    switch (analyticsTab) {
      case 'devices':
        return analytics.top_devices || [];
      case 'conversations':
        return analytics.top_conversations || [];
      case 'scopes':
        return analytics.traffic_scopes || [];
      case 'applications':
      default:
        return analytics.top_applications || [];
    }
  }, [analytics, analyticsTab]);

  const analyticsEmpty = useMemo(() => {
    switch (analyticsTab) {
      case 'devices':
        return {
          title: 'No device rollups yet',
          description: 'The current window does not have enough device-level flow data to rank endpoints.',
        };
      case 'conversations':
        return {
          title: 'No conversation rollups yet',
          description: 'Conversation summaries appear once the backend sees enough flow volume to group endpoints.',
        };
      case 'scopes':
        return {
          title: 'No traffic edge data yet',
          description: 'Scope summaries appear after managed or BYOD traffic reaches the backend.',
        };
      case 'applications':
      default:
        return {
          title: 'No application rollups yet',
          description: 'Application summaries appear once the backend has classified enough sessions in the current window.',
        };
    }
  }, [analyticsTab]);

  const alertColumns = [
    {
      key: 'threat',
      label: 'Threat',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.message || 'High-risk detection'}</div>
          <div className="nv-table__meta">{row.device_ip || row.src_ip || 'Unknown asset'} | {row.application || row.domain || 'network flow'}</div>
        </>
      ),
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (row) => <StatusBadge tone={getRiskTone(row.severity)}>{row.severity || 'HIGH'}</StatusBadge>,
    },
    {
      key: 'time',
      label: 'Last Seen',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.timestamp)}</span>,
    },
  ];

  const webColumns = [
    {
      key: 'page_title',
      label: 'Web Activity',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.page_title || row.base_domain || 'Untitled page'}</div>
          <div className="nv-table__meta">{row.page_url || row.base_domain || '-'}</div>
        </>
      ),
    },
    {
      key: 'context',
      label: 'Context',
      render: (row) => (
        <>
          <div className="nv-table__primary">{formatBrowserLabel(row.browser_name, row.process_name)}</div>
          <div className="nv-table__meta">{row.device_ip || 'Unknown device'}</div>
        </>
      ),
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen || row.created_at)}</span>,
    },
  ];

  const recentActivityColumns = [
    {
      key: 'application',
      label: 'Application',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.application || 'Other'}</div>
          <div className="nv-table__meta">{row.domain || row.host || row.dst_ip || '-'}</div>
        </>
      ),
    },
    {
      key: 'session',
      label: 'Session',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.src_ip || '-'}</div>
          <div className="nv-table__meta">{row.dst_ip || '-'}</div>
        </>
      ),
    },
    {
      key: 'severity',
      label: 'Signal',
      render: (row) => <StatusBadge tone={getRiskTone(row.severity)}>{row.severity || 'LOW'}</StatusBadge>,
    },
    {
      key: 'bytes',
      label: 'Bytes',
      render: (row) => <span className="mono">{formatByteCount(row.byte_count || row.size || 0)}</span>,
    },
  ];

  const handleOpenEvidence = (row) => {
    setSelectedEvent(row);
  };

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Overview"
        title="Operational Overview"
        description="Track the current security posture, prioritize high-risk detections, and move into investigation workflows without fighting dense dashboard noise."
        actions={(
          <>
            <StatusBadge tone={wsStatus === 'connected' ? 'success' : 'warning'} icon="ri-broadcast-line">
              {wsStatus === 'connected' ? 'Live Feed' : 'Reconnecting'}
            </StatusBadge>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchDashboard()}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
          </>
        )}
      />

      {loading ? (
        <StatGridSkeleton count={4} />
      ) : (
        <div className="nv-metric-grid">
          <MetricCard
            icon="ri-macbook-line"
            label="Active Devices"
            value={stats.active_devices || 0}
            meta={`${stats.total_devices || 0} visible assets in the current window`}
            accent="#54c8e8"
          />
          <MetricCard
            icon="ri-shield-flash-line"
            label="Active Threats"
            value={alerts.length || stats.high_risk || 0}
            meta="High and critical detections requiring review"
            accent="#fb7185"
          />
          <MetricCard
            icon="ri-exchange-box-line"
            label="Flows (24h)"
            value={stats.flows_24h || 0}
            meta={`${activity.length} recent sessions in live feed`}
            accent="#60a5fa"
          />
          <MetricCard
            icon="ri-navigation-line"
            label="Inspection Coverage"
            value={`${inspectedCoverage}%`}
            meta={`${webActivity.length} recent inspected browser events`}
            accent="#2dd4bf"
          />
        </div>
      )}

      <SectionCard
        title="Traffic Pressure"
        caption="Primary Intelligence"
        aside={<StatusBadge tone="accent" icon="ri-line-chart-line">24 hour window</StatusBadge>}
      >
        <TrafficChart data={trafficChartData} height={220} />
      </SectionCard>

      <SectionCard
        title="Traffic Intelligence"
        caption="ManageEngine-class rollups"
        aside={<StatusBadge tone="accent" icon="ri-dashboard-3-line">Derived from flow_logs and sessions</StatusBadge>}
      >
        <Tabs value={analyticsTab} onChange={setAnalyticsTab} items={analyticsTabs} />
        <div className="nv-scroll-region nv-scroll-region--lg" style={{ marginTop: '1rem' }}>
          <DataTable
            columns={analyticsColumns}
            rows={analyticsRows}
            rowKey={(row, index) => row.device_ip || row.src_ip || row.application || row.network_scope || `${analyticsTab}-${index}`}
            emptyTitle={analyticsEmpty.title}
            emptyDescription={analyticsEmpty.description}
          />
        </div>
      </SectionCard>

      {loading ? (
        <TableSkeleton rows={4} />
      ) : (
        <SectionCard
          title="Threat Summary"
          caption="What Needs Attention"
          aside={<button type="button" className="nv-button nv-button--ghost" onClick={() => navigate('/threats')}>Open Queue</button>}
        >
          <div className="nv-dashboard-pie">
            <ThreatDistributionChart
              distribution={stats.risk_distribution}
              height={208}
              legendPosition="bottom"
            />
          </div>
        </SectionCard>
      )}

      {loading ? (
        <TableSkeleton rows={5} />
      ) : (
        <SectionCard
          title="Recent Alerts"
          caption="Secondary Live Activity"
          aside={<button type="button" className="nv-button nv-button--ghost" onClick={() => navigate('/threats')}>Investigate</button>}
        >
          <div className="nv-scroll-region nv-scroll-region--lg">
            <DataTable
              columns={alertColumns}
              rows={alerts.slice(0, 12)}
              rowKey={(row, index) => row.id || `${row.timestamp}-${index}`}
              onRowClick={() => navigate('/threats')}
              emptyTitle="No active alerts"
              emptyDescription="The high-severity threat queue is currently quiet."
            />
          </div>
        </SectionCard>
      )}

      {loading ? (
        <TableSkeleton rows={5} />
      ) : (
        <SectionCard
          title="Recent Web Activity"
          caption="Inspection Feed"
          aside={<button type="button" className="nv-button nv-button--ghost" onClick={() => navigate('/dpi')}>Open Inspection</button>}
        >
          <div className="nv-scroll-region nv-scroll-region--lg">
            <DataTable
              columns={webColumns}
              rows={webActivity.slice(0, 10)}
              rowKey={(row, index) => row.id || `${row.page_url || row.base_domain}-${index}`}
              onRowClick={(row) => {
                if (row.device_ip) {
                  navigate(`/user/${encodeURIComponent(row.device_ip)}`);
                } else {
                  navigate('/dpi');
                }
              }}
              emptyTitle="No inspected sessions"
              emptyDescription="Enable agent-side inspection and browse through the managed wrappers to populate this feed."
            />
          </div>
        </SectionCard>
      )}

      <SectionCard
        title="Live Network Sessions"
        caption="Triage Feed"
        aside={<button type="button" className="nv-button nv-button--ghost" onClick={() => navigate('/activity')}>Open Traffic Feed</button>}
      >
        {loading ? (
          <TableSkeleton rows={6} />
        ) : (
          <div className="nv-scroll-region nv-scroll-region--xl">
            <DataTable
              columns={recentActivityColumns}
              rows={activity.slice(0, 14)}
              rowKey={(row, index) => row.id || `${row.timestamp || row.time}-${index}`}
              onRowClick={(row) => handleOpenEvidence(row)}
              emptyTitle="No session activity yet"
              emptyDescription="Once the agent or gateway starts sending flow records, the live triage feed will appear here."
            />
          </div>
        )}
      </SectionCard>

      <EvidenceDrawer
        open={Boolean(selectedEvent)}
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        footer={(
          <button type="button" className="nv-button nv-button--secondary" onClick={() => navigate('/activity')}>
            Open Traffic Feed
          </button>
        )}
      />
    </div>
  );
};

export default DashboardPage;

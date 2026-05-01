import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { systemService } from '../services/api';
import { formatRuntime, getApplicationVisual, isNetworkServiceApplication } from '../utils/apps';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatByteCount, getStatusTone } from '../utils/presentation';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';

const parseTimestampValue = (value) => {
  if (!value) {
    return 0;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
};

const aggregateDeviceRows = (rows) => {
  const grouped = new Map();

  rows.forEach((row) => {
    const deviceIp = row.device_ip;
    if (!deviceIp) {
      return;
    }

    const current = grouped.get(deviceIp) || {
      ...row,
      bandwidth_bytes: 0,
      runtime_seconds: 0,
      session_count: 0,
      active_session_count: 0,
      last_seen_value: 0,
    };

    current.bandwidth_bytes += Number(row.bandwidth_bytes) || 0;
    current.runtime_seconds = Math.max(current.runtime_seconds || 0, Number(row.runtime_seconds) || 0);
    current.session_count += Number(row.session_count) || 1;
    current.active_session_count += Number(row.active_session_count) || (row.status === 'Active' ? 1 : 0);

    const lastSeenValue = parseTimestampValue(row.last_seen);
    if (lastSeenValue >= (current.last_seen_value || 0)) {
      current.last_seen_value = lastSeenValue;
      current.last_seen = row.last_seen;
    }

    current.status = current.active_session_count > 0 ? 'Active' : 'Idle';
    current.hostname = current.hostname || row.hostname;
    current.management_mode = current.management_mode || row.management_mode;

    grouped.set(deviceIp, current);
  });

  return Array.from(grouped.values()).sort((left, right) => (
    (right.active_session_count || 0) - (left.active_session_count || 0)
    || (right.bandwidth_bytes || 0) - (left.bandwidth_bytes || 0)
    || (right.last_seen_value || 0) - (left.last_seen_value || 0)
    || String(left.device_ip).localeCompare(String(right.device_ip))
  ));
};

const ApplicationDevicesPage = () => {
  const navigate = useNavigate();
  const { appName } = useParams();
  const decodedAppName = decodeURIComponent(appName || 'Other');
  const isNetworkService = isNetworkServiceApplication(decodedAppName);
  const [loading, setLoading] = useState(true);
  const [devices, setDevices] = useState([]);
  const [events, setEvents] = useState([]);
  const deviceRows = useMemo(() => aggregateDeviceRows(devices), [devices]);

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
    return deviceRows.reduce(
      (acc, device) => {
        acc.total += 1;
        acc.active += device.status === 'Active' ? 1 : 0;
        acc.bandwidthBytes += device.bandwidth_bytes || 0;
        acc.runtimeSeconds += device.runtime_seconds || 0;
        return acc;
      },
      { total: 0, active: 0, bandwidthBytes: 0, runtimeSeconds: 0 },
    );
  }, [deviceRows]);

  const visual = getApplicationVisual(decodedAppName);
  const applicationKindLabel = isNetworkService ? 'Network service' : 'Product app';

  const deviceColumns = [
    {
      key: 'device_ip',
      label: 'Device',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.device_ip}</div>
          <div className="nv-table__meta">
            {row.hostname || 'Unknown host'}
            {row.session_count > 1 ? ` | ${row.session_count} sessions` : ''}
          </div>
        </>
      ),
    },
    {
      key: 'mode',
      label: 'Mode',
      render: (row) => <StatusBadge tone={row.management_mode === 'managed' ? 'success' : 'neutral'}>{row.management_mode === 'managed' ? 'Managed' : 'BYOD'}</StatusBadge>,
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => <StatusBadge tone={getStatusTone(row.status)}>{row.status}</StatusBadge>,
    },
    {
      key: 'runtime',
      label: 'Runtime',
      render: (row) => <span className="mono">{row.runtime || formatRuntime(row.runtime_seconds)}</span>,
    },
    {
      key: 'bandwidth',
      label: 'Bandwidth',
      render: (row) => <span className="mono">{row.bandwidth || formatByteCount(row.bandwidth_bytes)}</span>,
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{row.last_seen ? formatUtcTimestampToLocal(row.last_seen) : 'N/A'}</span>,
    },
  ];

  const webColumns = [
    {
      key: 'event',
      label: 'Web Event',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.page_title || row.title || 'Untitled page'}</div>
          <div className="nv-table__meta">{row.base_domain || row.domain || '-'}</div>
        </>
      ),
    },
    { key: 'device_ip', label: 'Device', render: (row) => <span className="mono">{row.device_ip}</span> },
    { key: 'search_query', label: 'Search Query', render: (row) => row.search_query || '-' },
    { key: 'time', label: 'Time', render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen || row.timestamp)}</span> },
  ];

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Inventory"
        title={decodedAppName}
        description={isNetworkService
          ? 'Inspect which devices are producing this service bucket, how active they are, and whether any associated browser inspection activity is already visible.'
          : 'Inspect which devices are using this application, how active they are, and whether any associated browser inspection activity is already visible.'}
        actions={(
          <>
            <Link className="nv-button nv-button--secondary" to="/apps">
              <i className="ri-arrow-left-line"></i>
              Back
            </Link>
            <button type="button" className="nv-button nv-button--secondary" onClick={fetchDevices}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
          </>
        )}
      >
        <div className="nv-pill-card" style={{ width: 'fit-content' }}>
          <div className="nv-pill-card__icon" style={{ color: visual.accent, background: visual.background, borderColor: `${visual.accent}33` }}>
            <i className={visual.icon}></i>
          </div>
          <div className="nv-pill-card__content">
            <strong>{decodedAppName}</strong>
            <span>{applicationKindLabel} coverage grouped by device across the last 24 hours</span>
          </div>
        </div>
      </PageHeader>

      {loading ? (
        <StatGridSkeleton count={4} />
      ) : (
        <div className="nv-metric-grid">
          <MetricCard icon="ri-macbook-line" label="Devices" value={stats.total} meta={`${stats.active} active / ${stats.total - stats.active} idle`} accent="#54c8e8" />
          <MetricCard icon="ri-exchange-funds-line" label="Bandwidth" value={formatByteCount(stats.bandwidthBytes)} meta="24 hour application window" accent="#2dd4bf" />
          <MetricCard icon="ri-time-line" label="Runtime" value={formatRuntime(stats.runtimeSeconds)} meta="Aggregated coverage span across visible devices" accent="#60a5fa" />
          <MetricCard icon="ri-shield-user-line" label="Managed Coverage" value={deviceRows.filter((device) => device.management_mode === 'managed').length} meta="Managed devices using this application" accent="#fbbf24" />
        </div>
      )}

      <SectionCard title="Device Coverage" caption="One row per device with repeated sessions folded together">
        {loading ? (
          <TableSkeleton rows={5} />
        ) : (
          <DataTable
            columns={deviceColumns}
            rows={deviceRows}
            rowKey={(row) => `${decodedAppName}-${row.device_ip}`}
            onRowClick={(row) => navigate(`/user/${encodeURIComponent(row.device_ip)}`)}
            emptyTitle="No devices are currently using this application"
            emptyDescription="Sessions for this application have not appeared in the current 24-hour window."
          />
        )}
      </SectionCard>

      <SectionCard title="Associated Web Activity" caption="Inspection Context">
        <DataTable
          columns={webColumns}
          rows={events}
          rowKey={(row, index) => row.id || `${row.device_ip || 'device'}-${index}`}
          onRowClick={(row) => navigate(`/user/${encodeURIComponent(row.device_ip)}`)}
          emptyTitle="No recent inspected web activity"
          emptyDescription="Either inspection is disabled for the relevant devices or this application does not currently map to allowlisted inspected traffic."
        />
      </SectionCard>
    </div>
  );
};

export default ApplicationDevicesPage;

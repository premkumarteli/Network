import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { useWebSocket } from '../hooks/useWebSocket';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { getRiskTone, getStatusTone } from '../utils/presentation';

const DevicesPage = () => {
  const navigate = useNavigate();
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchValue, setSearchValue] = useState('');
  const [modeFilter, setModeFilter] = useState('all');

  const fetchDevices = async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const res = await systemService.getDevices();
      setDevices(res.data || []);
    } catch (err) {
      console.error('Failed to fetch devices', err);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    fetchDevices();
  }, []);

  useVisibilityPolling(() => fetchDevices({ background: true }), 5000);

  const handleDeviceEvent = useCallback((eventData) => {
    const update = eventData?.data;
    if (!update || !update.ip) return;
    setDevices((prev) => {
      const idx = prev.findIndex((device) => device.ip === update.ip);
      if (idx >= 0) {
        const next = [...prev];
        next[idx] = { ...next[idx], ...update };
        return next;
      }
      return [update, ...prev];
    });
  }, []);

  useWebSocket('device_event', handleDeviceEvent);

  const stats = useMemo(() => {
    const named = devices.filter((device) => !['Unknown', 'Unknown-Device', '', null, undefined].includes(device.hostname)).length;
    const managed = devices.filter((device) => device.management_mode === 'managed').length;
    const highRisk = devices.filter((device) => ['HIGH', 'CRITICAL'].includes(device.risk_level)).length;
    return { named, managed, highRisk };
  }, [devices]);

  const visibleDevices = useMemo(() => {
    return devices.filter((device) => {
      const matchesMode = modeFilter === 'all' || device.management_mode === modeFilter;
      const haystack = [
        device.hostname,
        device.ip,
        device.mac,
        device.vendor,
        device.device_type,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      const matchesSearch = haystack.includes(searchValue.trim().toLowerCase());
      return matchesMode && matchesSearch;
    });
  }, [devices, modeFilter, searchValue]);

  const columns = [
    {
      key: 'device',
      label: 'Device',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.hostname && row.hostname !== 'Unknown' ? row.hostname : 'Unnamed Device'}</div>
          <div className="nv-table__meta">
            {[row.vendor, row.device_type, row.os_family].filter(Boolean).join(' · ') || 'Unclassified host'}
          </div>
        </>
      ),
    },
    {
      key: 'mode',
      label: 'Mode',
      render: (row) => (
        <>
          <StatusBadge tone={row.management_mode === 'managed' ? 'success' : 'neutral'}>
            {row.management_mode === 'managed' ? 'Managed' : 'BYOD'}
          </StatusBadge>
          <div className="nv-table__meta">{row.confidence || 'medium'} confidence</div>
        </>
      ),
    },
    {
      key: 'network',
      label: 'Network',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.ip}</div>
          <div className="nv-table__meta mono">{row.mac || row.mac_address || '-'}</div>
        </>
      ),
    },
    {
      key: 'top_activity',
      label: 'Top Activity',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.top_application || 'Idle'}</div>
          <div className="nv-table__meta">{row.top_domain || '-'}</div>
        </>
      ),
    },
    {
      key: 'risk',
      label: 'Risk',
      render: (row) => (
        <>
          <StatusBadge tone={getRiskTone(row.risk_level)}>{Math.round(row.risk_score || 0)}% {row.risk_level || 'LOW'}</StatusBadge>
        </>
      ),
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen)}</span>,
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => <StatusBadge tone={getStatusTone(row.status || (row.is_online ? 'Online' : 'Offline'))}>{row.status || (row.is_online ? 'Online' : 'Offline')}</StatusBadge>,
    },
  ];

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Inventory"
        title="Device Inventory"
        description="Manage the network inventory from one table-first surface with fast filtering, posture signals, and direct drill-down into a single device workspace."
        actions={(
          <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchDevices()}>
            <i className="ri-refresh-line"></i>
            Refresh
          </button>
        )}
      />

      {loading ? (
        <StatGridSkeleton count={3} />
      ) : (
        <div className="nv-metric-grid">
          <MetricCard icon="ri-radar-line" label="Visible Devices" value={devices.length} meta={`${stats.managed} managed / ${devices.length - stats.managed} BYOD`} accent="#54c8e8" />
          <MetricCard icon="ri-fingerprint-line" label="Resolved Names" value={stats.named} meta={`${devices.length - stats.named} devices still unnamed`} accent="#60a5fa" />
          <MetricCard icon="ri-shield-flash-line" label="High Risk" value={stats.highRisk} meta="Devices flagged high or critical" accent="#fb7185" />
          <MetricCard icon="ri-search-line" label="Filtered View" value={visibleDevices.length} meta="Assets matching current filter set" accent="#2dd4bf" />
        </div>
      )}

      <SectionCard title="Assets" caption="Table-first Inventory">
        <div className="nv-filterbar">
          <div className="nv-filterbar__group">
            <label className="nv-field nv-field--grow">
              <i className="ri-search-line"></i>
              <input
                type="search"
                value={searchValue}
                onChange={(event) => setSearchValue(event.target.value)}
                placeholder="Search hostname, IP, MAC, vendor..."
              />
            </label>
            <label className="nv-field">
              <select value={modeFilter} onChange={(event) => setModeFilter(event.target.value)}>
                <option value="all">All Modes</option>
                <option value="managed">Managed</option>
                <option value="byod">BYOD</option>
              </select>
            </label>
          </div>
        </div>

        {loading ? (
          <TableSkeleton rows={6} />
        ) : (
          <DataTable
            columns={columns}
            rows={visibleDevices}
            rowKey={(row, index) => row.id || row.ip || index}
            onRowClick={(row) => navigate(`/user/${encodeURIComponent(row.ip)}`)}
            emptyTitle="No devices found"
            emptyDescription="Adjust the current filters or wait for the latest discovery and traffic feeds to refresh."
          />
        )}
      </SectionCard>
    </div>
  );
};

export default DevicesPage;

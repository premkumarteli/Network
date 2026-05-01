import { useCallback, useEffect, useMemo, useState } from 'react';
import { systemService } from '../services/api';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatByteCount, getRiskTone } from '../utils/presentation';

const PAGE_LIMIT = 50;

const LogsPage = () => {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    src_ip: '',
    dst_ip: '',
    application: '',
    search: '',
  });
  const [stats, setStats] = useState({ top_apps: [], volume_trend: [] });

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * PAGE_LIMIT;
      const params = {
        limit: PAGE_LIMIT,
        offset,
        ...Object.fromEntries(Object.entries(filters).filter(([, value]) => value !== '')),
      };
      const response = await systemService.getFlowLogs(params);
      setLogs(response.data.results || []);
      setTotal(response.data.total || 0);
    } catch (error) {
      console.error('Error fetching logs:', error);
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  const fetchStats = useCallback(async () => {
    try {
      const response = await systemService.getFlowStats();
      setStats(response.data || { top_apps: [], volume_trend: [] });
    } catch (error) {
      console.error('Error fetching log stats:', error);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleFilterChange = (event) => {
    const { name, value } = event.target;
    setFilters((prev) => ({ ...prev, [name]: value }));
    setPage(1);
  };

  const handleExport = useCallback(async () => {
    setExporting(true);
    try {
      const response = await systemService.exportAnalyticsReport(
        'flows',
        {
          limit: 10000,
          ...Object.fromEntries(Object.entries(filters).filter(([, value]) => value !== '')),
        },
        'csv',
      );

      const blob = response.data instanceof Blob
        ? response.data
        : new Blob([response.data], { type: 'text/csv;charset=utf-8' });
      const disposition = response.headers?.['content-disposition'] || '';
      const match = disposition.match(/filename="([^"]+)"/i);
      const filename = match?.[1] || 'netvisor-flow-logs.csv';
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export flow logs', error);
    } finally {
      setExporting(false);
    }
  }, [filters]);

  const totalPages = Math.max(Math.ceil(total / PAGE_LIMIT), 1);
  const uniqueSources = useMemo(() => new Set(logs.map((log) => log.src_ip)).size, [logs]);

  const columns = [
    {
      key: 'timestamp',
      label: 'Timestamp',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen || row.timestamp)}</span>,
    },
    {
      key: 'source',
      label: 'Source',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.src_ip}</div>
          <div className="nv-table__meta mono">{row.src_mac || 'No MAC'}</div>
        </>
      ),
    },
    {
      key: 'destination',
      label: 'Destination',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.host || row.sni || row.domain || row.dst_ip}</div>
          <div className="nv-table__meta mono">{row.dst_ip || '-'}</div>
        </>
      ),
    },
    {
      key: 'proto',
      label: 'Port / Proto',
      render: (row) => <span className="mono">{row.dst_port}/{row.protocol}</span>,
    },
    {
      key: 'application',
      label: 'Application',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.application || 'Other'}</div>
          <div className="nv-table__meta">{row.management_mode || 'unknown mode'}</div>
        </>
      ),
    },
    {
      key: 'bytes',
      label: 'Bytes',
      render: (row) => <span className="mono">{formatByteCount(row.byte_count)}</span>,
    },
    {
      key: 'severity',
      label: 'Signal',
      render: (row) => <StatusBadge tone={getRiskTone(row.severity)}>{row.severity || 'LOW'}</StatusBadge>,
    },
  ];

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Operations"
        title="Flow Logs"
        description="Search and filter the raw session feed with one consistent table system instead of a separate visual language for operational pages."
        actions={(
          <>
            <button
              type="button"
              className="nv-button nv-button--secondary"
              onClick={() => {
                setFilters({ src_ip: '', dst_ip: '', application: '', search: '' });
                setPage(1);
              }}
            >
              <i className="ri-refresh-line"></i>
              Reset Filters
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={handleExport} disabled={exporting}>
              <i className="ri-download-line"></i>
              {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
          </>
        )}
      />

      <div className="nv-metric-grid">
        <MetricCard icon="ri-list-check-2" label="Total Events" value={total.toLocaleString()} meta="Current query result size" accent="#54c8e8" />
        <MetricCard icon="ri-earth-line" label="Unique Sources" value={uniqueSources} meta="Distinct source IPs on this page" accent="#60a5fa" />
        <MetricCard icon="ri-apps-line" label="Dominant App" value={stats.top_apps?.[0]?.application || 'Calculating...'} meta="Top application in the current stats window" accent="#2dd4bf" />
        <MetricCard icon="ri-error-warning-line" label="Active Alerts" value={logs.filter((log) => log.severity !== 'LOW').length} meta="Non-low signal on this page" accent="#fb7185" />
      </div>

      <SectionCard title="Network Event Logs" caption="Search and Filter">
        <div className="nv-filterbar">
          <div className="nv-filterbar__group">
            <label className="nv-field nv-field--grow">
              <i className="ri-search-line"></i>
              <input name="search" value={filters.search} onChange={handleFilterChange} placeholder="Global search..." />
            </label>
            <label className="nv-field">
              <input name="src_ip" value={filters.src_ip} onChange={handleFilterChange} placeholder="Source IP..." />
            </label>
            <label className="nv-field">
              <input name="dst_ip" value={filters.dst_ip} onChange={handleFilterChange} placeholder="Destination IP..." />
            </label>
            <label className="nv-field">
              <select name="application" value={filters.application} onChange={handleFilterChange}>
                <option value="">All Applications</option>
                {(stats.top_apps || []).map((app) => (
                  <option key={app.application} value={app.application}>{app.application}</option>
                ))}
              </select>
            </label>
          </div>
        </div>

        <DataTable
          columns={columns}
          rows={loading ? [] : logs}
          rowKey={(row, index) => row.id || `${row.last_seen || row.timestamp}-${index}`}
          emptyTitle={loading ? 'Loading flow records' : 'No logs found'}
          emptyDescription={loading ? 'The current filter set is being queried.' : 'No flow records match the current filters.'}
        />

        <div className="nv-inline-actions" style={{ justifyContent: 'space-between' }}>
          <p>Showing {(page - 1) * PAGE_LIMIT + 1} to {Math.min(page * PAGE_LIMIT, total)} of {total}</p>
          <div className="nv-inline-actions">
            <button
              type="button"
              className="nv-button nv-button--secondary"
              disabled={page === 1}
              onClick={() => setPage((current) => Math.max(1, current - 1))}
            >
              Previous
            </button>
            <StatusBadge tone="neutral">Page {page} / {totalPages}</StatusBadge>
            <button
              type="button"
              className="nv-button nv-button--secondary"
              disabled={page === totalPages}
              onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
            >
              Next
            </button>
          </div>
        </div>
      </SectionCard>
    </div>
  );
};

export default LogsPage;

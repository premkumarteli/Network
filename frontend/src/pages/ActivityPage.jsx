import { useCallback, useEffect, useMemo, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import TrafficChart from '../components/Dashboard/TrafficChart';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatByteCount, getRiskTone } from '../utils/presentation';
import EvidenceDrawer from '../components/V2/EvidenceDrawer';

const ActivityPage = () => {
  const [stats, setStats] = useState({});
  const [logs, setLogs] = useState([]);
  const [trafficData, setTrafficData] = useState({ labels: [], values: [] });
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState(null);

  const updateTrafficChart = useCallback((bandwidthValue) => {
    if (bandwidthValue === null || bandwidthValue === undefined) {
      return;
    }

    const numericValue = typeof bandwidthValue === 'number' ? bandwidthValue : Number.parseFloat(bandwidthValue);
    if (Number.isNaN(numericValue)) {
      return;
    }

    const now = new Date().toLocaleTimeString();
    setTrafficData((prev) => ({
      labels: [...prev.labels, now].slice(-20),
      values: [...prev.values, numericValue].slice(-20),
    }));
  }, []);

  const fetchTraffic = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }

    try {
      const [statsRes, activityRes] = await Promise.all([
        systemService.getStats(),
        systemService.getActivity(100),
      ]);
      const nextStats = statsRes.data || {};
      setStats(nextStats);
      setLogs(activityRes.data || []);
      updateTrafficChart(nextStats.bandwidth_value ?? nextStats.bandwidth);
    } catch (err) {
      console.error('Failed to fetch traffic activity', err);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, [updateTrafficChart]);

  useEffect(() => {
    fetchTraffic();
  }, [fetchTraffic]);

  useVisibilityPolling(() => fetchTraffic({ background: true }), 15000);

  const signalCounts = useMemo(() => ({
    high: logs.filter((entry) => entry.severity === 'HIGH' || entry.severity === 'CRITICAL').length,
    medium: logs.filter((entry) => entry.severity === 'MEDIUM').length,
  }), [logs]);

  const columns = [
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
      key: 'source',
      label: 'Source',
      render: (row) => <span className="mono">{row.src_ip || '-'}</span>,
    },
    {
      key: 'destination',
      label: 'Destination',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.domain || row.host || row.dst_ip || '-'}</div>
          <div className="nv-table__meta mono">{row.dst_ip || '-'}</div>
        </>
      ),
    },
    {
      key: 'protocol',
      label: 'Protocol',
      render: (row) => <span className="mono">{row.protocol || 'Unknown'}</span>,
    },
    {
      key: 'severity',
      label: 'Signal',
      render: (row) => <StatusBadge tone={getRiskTone(row.severity)}>{row.severity || 'LOW'}</StatusBadge>,
    },
    {
      key: 'size',
      label: 'Bytes',
      render: (row) => <span className="mono">{formatByteCount(row.byte_count || row.size || 0)}</span>,
    },
    {
      key: 'time',
      label: 'Time',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.timestamp || row.last_seen || row.time)}</span>,
    },
  ];

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Investigation"
        title="Traffic Activity"
        description="Use a cleaner live-session workspace to monitor recent network flows, watch throughput, and see which sessions deserve a deeper device investigation."
        actions={(
          <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchTraffic()}>
            <i className="ri-refresh-line"></i>
            Refresh
          </button>
        )}
      />

      {loading ? (
        <StatGridSkeleton count={4} />
      ) : (
        <div className="nv-metric-grid">
          <MetricCard icon="ri-exchange-box-line" label="Flows (24h)" value={stats.flows_24h || 0} meta="Same window as the overview dashboard" accent="#54c8e8" />
          <MetricCard icon="ri-pulse-line" label="Recent Sessions" value={logs.length} meta="Latest classified session feed" accent="#60a5fa" />
          <MetricCard icon="ri-macbook-line" label="Online Devices" value={stats.active_devices || 0} meta={`${stats.total_devices || 0} tracked assets`} accent="#2dd4bf" />
          <MetricCard icon="ri-alarm-warning-line" label="High Signal" value={signalCounts.high} meta={`${signalCounts.medium} medium-signal sessions also visible`} accent="#fb7185" />
        </div>
      )}

      <div className="nv-grid nv-grid--two">
        <SectionCard title="Traffic Throughput" caption="Rolling Network Pressure">
          <TrafficChart data={trafficData} height={220} />
        </SectionCard>

        <SectionCard title="Live Feed Context" caption="Current Window">
          <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
            <div className="nv-summary-tile">
              <span>Bandwidth</span>
              <strong>{stats.bandwidth || '0 B/s'}</strong>
              <p>Rolling throughput estimate</p>
            </div>
            <div className="nv-summary-tile">
              <span>Window</span>
              <strong>15s</strong>
              <p>Visibility polling cadence</p>
            </div>
          </div>
        </SectionCard>
      </div>

      <SectionCard title="Recent Sessions" caption="Raw Feed">
        {loading ? (
          <TableSkeleton rows={8} />
        ) : (
          <DataTable
            columns={columns}
            rows={logs}
            rowKey={(row, index) => row.id || `${row.timestamp || row.time}-${index}`}
            onRowClick={(row) => setSelectedEvent(row)}
            emptyTitle="No visible traffic sessions"
            emptyDescription="Once the gateway or agent sends activity, the live session feed will appear here."
          />
        )}
      </SectionCard>

      <EvidenceDrawer
        open={Boolean(selectedEvent)}
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
};

export default ActivityPage;

import { useCallback, useEffect, useMemo, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import { TableSkeleton } from '../components/UI/Skeletons';
import { formatUtcTimestampToLocal } from '../utils/time';
import { getRiskTone } from '../utils/presentation';

const ThreatsPage = () => {
  const [threats, setThreats] = useState([]);
  const [threatCount, setThreatCount] = useState(0);
  const [loading, setLoading] = useState(true);

  const fetchThreats = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const [res, statsRes] = await Promise.all([
        systemService.getAlerts({
          severity: 'HIGH,CRITICAL',
          resolved: false,
          hours: 24,
          limit: 100,
        }),
        systemService.getStats(),
      ]);
      setThreats(res.data || []);
      setThreatCount(statsRes.data?.high_risk || 0);
    } catch (err) {
      console.error('Failed to fetch threats', err);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  useVisibilityPolling(() => fetchThreats({ background: true }), 15000);

  const criticalCount = useMemo(
    () => threats.filter((entry) => entry.severity === 'CRITICAL').length,
    [threats],
  );

  const threatColumns = [
    {
      key: 'time',
      label: 'Time',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.timestamp)}</span>,
    },
    {
      key: 'target',
      label: 'Target',
      render: (row) => (
        <>
          <div className="nv-table__primary mono">{row.device_ip || row.src_ip || '-'}</div>
          <div className="nv-table__meta">{row.application || row.domain || 'Network activity'}</div>
        </>
      ),
    },
    {
      key: 'identity',
      label: 'Identity',
      render: (row) => <span className="mono">{row.flow_id ? `Flow ${String(row.flow_id).slice(0, 8)}` : '-'}</span>,
    },
    {
      key: 'reasoning',
      label: 'Reasoning',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.message || 'AI detection: suspicious activity'}</div>
          <div className="nv-table__meta">{row.breakdown?.primary_detection || row.severity || 'Threat intelligence match'}</div>
        </>
      ),
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (row) => <StatusBadge tone={getRiskTone(row.severity)}>{row.severity}</StatusBadge>,
    },
  ];

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Investigation"
        title="Threat Investigation"
        description="Prioritize high-risk detections, inspect the target and reasoning behind each alert, and keep the threat queue readable instead of visually noisy."
        actions={(
          <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchThreats()}>
            <i className="ri-refresh-line"></i>
            Refresh
          </button>
        )}
      />

      <div className="nv-metric-grid">
        <MetricCard icon="ri-shield-flash-line" label="Active Threats" value={threatCount} meta="Open high and critical detections" accent="#fb7185" />
        <MetricCard icon="ri-alarm-warning-line" label="Critical" value={criticalCount} meta="Priority incidents requiring fastest triage" accent="#f97316" />
        <MetricCard icon="ri-time-line" label="24h Window" value={threats.length} meta="High-severity detections in the last 24 hours" accent="#60a5fa" />
        <MetricCard icon="ri-focus-3-line" label="Queue State" value={threats.length > 0 ? 'Attention' : 'Quiet'} meta="Threat queue posture" accent="#2dd4bf" />
      </div>

      <SectionCard title="Threat Queue" caption="Table-first Investigation">
        {loading ? (
          <TableSkeleton rows={6} />
        ) : (
          <DataTable
            columns={threatColumns}
            rows={threats}
            rowKey={(row, index) => row.id || row.flow_id || `${row.timestamp}-${index}`}
            emptyTitle="No high-risk threats detected"
            emptyDescription="The high-severity queue is currently quiet. Continue monitoring the live feeds for new detections."
          />
        )}
      </SectionCard>
    </div>
  );
};

export default ThreatsPage;

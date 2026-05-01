import { useCallback, useEffect, useMemo, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import DataTable from '../components/V2/DataTable';
import StatusBadge from '../components/V2/StatusBadge';
import { formatUtcTimestampToLocal } from '../utils/time';
import { getRiskTone } from '../utils/presentation';

const VPNPage = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAlerts = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const res = await systemService.getVPNAlerts({
        resolved: false,
        hours: 24,
        limit: 100,
      });
      setAlerts(res.data || []);
    } catch (err) {
      console.error('Failed to fetch VPN alerts', err);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  useVisibilityPolling(() => fetchAlerts({ background: true }), 15000);

  const highRiskCount = useMemo(
    () => alerts.filter((entry) => Number(entry.risk_score) >= 70).length,
    [alerts],
  );

  const columns = [
    { key: 'time', label: 'Time', render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.timestamp)}</span> },
    { key: 'device_ip', label: 'Source IP', render: (row) => <span className="mono">{row.device_ip}</span> },
    {
      key: 'risk',
      label: 'Risk Score',
      render: (row) => (
        <div className="nv-stack" style={{ gap: '0.45rem' }}>
          <div className="nv-table__primary">{Math.round(Number(row.risk_score) || 0)}%</div>
          <div className="nv-progress">
            <div className="nv-progress__fill" style={{ width: `${Math.min(Number(row.risk_score) || 0, 100)}%` }}></div>
          </div>
        </div>
      ),
    },
    {
      key: 'reason',
      label: 'Reason',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.message || row.breakdown?.primary_detection || 'VPN or proxy anomaly'}</div>
          <div className="nv-table__meta">{row.severity || 'warning'}</div>
        </>
      ),
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (row) => <StatusBadge tone={getRiskTone(row.severity)}>{row.severity || 'warning'}</StatusBadge>,
    },
  ];

  return (
    <div className="nv-page nv-page--balanced">
      <PageHeader
        eyebrow="Operations"
        title="VPN Risk Feed"
        description="Track tunnel and proxy detections in a single operational table."
        actions={(
          <StatusBadge tone="success" icon="ri-shield-check-line">Monitoring</StatusBadge>
        )}
      />

      <div className="nv-metric-grid">
        <MetricCard icon="ri-shield-keyhole-line" label="Open VPN Alerts" value={alerts.length} meta="Current 24-hour unresolved queue" accent="#54c8e8" />
        <MetricCard icon="ri-alarm-warning-line" label="High Risk" value={highRiskCount} meta="Risk score above 70%" accent="#fb7185" />
        <MetricCard icon="ri-time-line" label="Window" value="24h" meta="Recent unresolved detections" accent="#60a5fa" />
        <MetricCard icon="ri-eye-line" label="Engine" value={loading ? 'Loading' : 'Watching'} meta="Anomaly monitoring state" accent="#2dd4bf" />
      </div>

      <SectionCard title="VPN & Proxy Alerts" caption="Operational Queue" className="nv-section--balanced">
        <div className="nv-scroll-region nv-scroll-region--xl">
          <DataTable
            columns={columns}
            rows={loading ? [] : alerts}
            rowKey={(row, index) => row.id || `${row.timestamp}-${index}`}
            emptyTitle={loading ? 'Loading alerts' : 'No active VPN threats detected'}
            emptyDescription={loading ? 'Collecting unresolved VPN and proxy detections.' : 'The anomaly engine is monitoring, but there are no unresolved VPN alerts in the current window.'}
          />
        </div>
      </SectionCard>
    </div>
  );
};

export default VPNPage;

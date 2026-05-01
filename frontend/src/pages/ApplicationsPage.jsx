import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { useWebSocket } from '../hooks/useWebSocket';
import { formatRuntime, getApplicationVisual, isNetworkServiceApplication } from '../utils/apps';
import { formatByteCount } from '../utils/presentation';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import StatusBadge from '../components/V2/StatusBadge';
import DataTable from '../components/V2/DataTable';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';

const parseByteValue = (value) => {
  if (typeof value === 'number') {
    return value;
  }
  if (typeof value !== 'string') {
    return 0;
  }

  const match = value.trim().match(/^([\d.]+)\s*(B|KB|MB|GB)?$/i);
  if (!match) {
    const fallback = Number.parseFloat(value);
    return Number.isFinite(fallback) ? fallback : 0;
  }

  const amount = Number.parseFloat(match[1]);
  const unit = (match[2] || 'B').toUpperCase();
  const scale = {
    B: 1,
    KB: 1024,
    MB: 1024 * 1024,
    GB: 1024 * 1024 * 1024,
  };
  return Math.round(amount * (scale[unit] || 1));
};

const sortApplications = (entries) => [...entries].sort((left, right) => (
  (right.live_event_count || 0) - (left.live_event_count || 0)
  || (right.active_device_count || 0) - (left.active_device_count || 0)
  || (right.bandwidth_bytes || 0) - (left.bandwidth_bytes || 0)
  || String(left.application).localeCompare(String(right.application))
));

const ApplicationsPage = () => {
  const navigate = useNavigate();
  const [applications, setApplications] = useState([]);
  const [liveFeed, setLiveFeed] = useState([]);
  const [analytics, setAnalytics] = useState({ uncategorized_domains: [] });
  const [loading, setLoading] = useState(true);

  const fetchApplications = useCallback(async () => {
    try {
      const [summaryRes, activityRes, analyticsRes] = await Promise.all([
        systemService.getAppsSummary(),
        systemService.getActivity(120),
        systemService.getAnalyticsOverview(24, 6),
      ]);
      setApplications(summaryRes.data || []);
      setLiveFeed(activityRes.data || []);
      setAnalytics(analyticsRes.data || { uncategorized_domains: [] });
    } catch (err) {
      console.error('Failed to fetch applications', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchApplications();
  }, [fetchApplications]);

  useVisibilityPolling(fetchApplications, 5000);

  const handlePacketEvent = useCallback((event) => {
    setLiveFeed((current) => [event, ...current].slice(0, 160));
  }, []);

  useWebSocket('packet_event', handlePacketEvent);

  const liveApplicationMap = useMemo(() => {
    return liveFeed.reduce((acc, entry) => {
      const application = entry.application || 'Other';
      const current = acc.get(application) || {
        event_count: 0,
        device_ips: new Set(),
        bandwidth_bytes: 0,
        last_seen: '',
        top_domain: '',
      };
      current.event_count += 1;
      if (entry.src_ip) {
        current.device_ips.add(entry.src_ip);
      }
      current.bandwidth_bytes += parseByteValue(entry.byte_count ?? entry.size ?? 0);
      current.last_seen = entry.timestamp || entry.time_str || entry.last_seen || current.last_seen;
      current.top_domain = entry.domain || current.top_domain;
      acc.set(application, current);
      return acc;
    }, new Map());
  }, [liveFeed]);

  const mergedApplications = useMemo(() => {
    const merged = new Map(
      applications.map((app) => [
        app.application,
        {
          ...app,
          live_event_count: 0,
          live_device_count: 0,
          live_domain: '',
          live_bandwidth_bytes: 0,
        },
      ]),
    );

    liveApplicationMap.forEach((entry, application) => {
      const existing = merged.get(application);
      if (existing) {
        merged.set(application, {
          ...existing,
          live_event_count: entry.event_count,
          live_device_count: entry.device_ips.size,
          live_domain: entry.top_domain,
          live_bandwidth_bytes: entry.bandwidth_bytes,
        });
        return;
      }

      merged.set(application, {
        application,
        device_count: entry.device_ips.size,
        active_device_count: entry.device_ips.size,
        bandwidth_bytes: entry.bandwidth_bytes,
        bandwidth: formatByteCount(entry.bandwidth_bytes),
        runtime_seconds: 0,
        runtime: 'Live now',
        last_seen: entry.last_seen || 'N/A',
        live_event_count: entry.event_count,
        live_device_count: entry.device_ips.size,
        live_domain: entry.top_domain,
        live_bandwidth_bytes: entry.bandwidth_bytes,
      });
    });

    return Array.from(merged.values()).sort((left, right) => (
      (isNetworkServiceApplication(left.application) ? 1 : 0) - (isNetworkServiceApplication(right.application) ? 1 : 0)
      || (right.live_event_count || 0) - (left.live_event_count || 0)
      || (right.active_device_count || 0) - (left.active_device_count || 0)
      || (right.bandwidth_bytes || 0) - (left.bandwidth_bytes || 0)
      || String(left.application).localeCompare(String(right.application))
    ));
  }, [applications, liveApplicationMap]);

  const { productApplications, networkApplications } = useMemo(() => {
    const products = [];
    const services = [];
    mergedApplications.forEach((app) => {
      if (isNetworkServiceApplication(app.application)) {
        services.push(app);
      } else {
        products.push(app);
      }
    });

    return {
      productApplications: sortApplications(products),
      networkApplications: sortApplications(services),
    };
  }, [mergedApplications]);

  const classificationRows = useMemo(() => analytics.uncategorized_domains || [], [analytics]);

  const totals = useMemo(() => {
    return mergedApplications.reduce(
      (acc, app) => {
        const isService = isNetworkServiceApplication(app.application);
        const isActive = (app.live_event_count || 0) > 0 || (app.active_device_count || 0) > 0;
        acc.deviceCount += app.device_count || 0;
        acc.bandwidthBytes += app.bandwidth_bytes || 0;
        if (isService) {
          acc.networkServices += 1;
          if (isActive) {
            acc.activeNetworkServices += 1;
          }
        } else {
          acc.productApps += 1;
          if (isActive) {
            acc.activeProductApps += 1;
          }
        }
        return acc;
      },
      {
        deviceCount: 0,
        bandwidthBytes: 0,
        productApps: 0,
        networkServices: 0,
        activeProductApps: 0,
        activeNetworkServices: 0,
      },
    );
  }, [mergedApplications]);

  const renderApplicationGrid = (entries, emptyTitle, emptyDescription) => {
    if (entries.length === 0) {
      return (
        <div className="nv-empty" style={{ background: 'transparent', boxShadow: 'none', border: '0', padding: 0 }}>
          <div className="nv-empty__icon">
            <i className="ri-apps-line"></i>
          </div>
          <div className="nv-stack" style={{ gap: '0.5rem' }}>
            <h3 className="nv-empty__title">{emptyTitle}</h3>
            <p className="nv-empty__description">{emptyDescription}</p>
          </div>
        </div>
      );
    }

    return (
      <div className="nv-card-grid">
        {entries.map((app) => {
          const visual = getApplicationVisual(app.application);
          const isLive = (app.live_event_count || 0) > 0 || (app.active_device_count || 0) > 0;
          const isService = isNetworkServiceApplication(app.application);
          return (
            <button
              key={app.application}
              type="button"
              className="nv-card-button"
              onClick={() => navigate(`/apps/${encodeURIComponent(app.application)}`)}
            >
              <div className="nv-card-button__header">
                <div className="nv-pill-card" style={{ padding: 0, border: '0', background: 'transparent' }}>
                  <div className="nv-pill-card__icon" style={{ color: visual.accent, background: visual.background, borderColor: `${visual.accent}33` }}>
                    <i className={visual.icon}></i>
                  </div>
                  <div className="nv-pill-card__content">
                    <strong>{app.application}</strong>
                    <span>{app.device_count} devices in 24h window</span>
                  </div>
                </div>
                <StatusBadge tone={isLive ? 'success' : 'neutral'}>
                  {isLive ? 'Active' : 'Idle'}
                </StatusBadge>
              </div>
              <div className="nv-card-button__value">{app.bandwidth || formatByteCount(app.bandwidth_bytes)}</div>
              <div className="nv-card-button__footer">
                <span>{app.live_event_count || app.active_device_count || 0} active now</span>
                <span>{app.runtime || formatRuntime(app.runtime_seconds)}</span>
              </div>
              <p style={{ marginTop: '0.75rem', color: 'var(--nv-text-muted)' }}>
                {isService ? 'Network service bucket' : 'Product app'}
                {app.last_seen ? ` | Last seen ${app.last_seen}` : ' | Last seen N/A'}
                {app.live_domain ? ` | ${app.live_domain}` : ''}
              </p>
            </button>
          );
        })}
      </div>
    );
  };

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Inventory"
        title="Application Coverage"
        description="See which products are active across the network, how much bandwidth they are consuming, and which transport buckets still need separate review."
        actions={(
          <button type="button" className="nv-button nv-button--secondary" onClick={fetchApplications}>
            <i className="ri-refresh-line"></i>
            Refresh
          </button>
        )}
      />

      {loading ? (
        <StatGridSkeleton count={4} />
      ) : (
        <div className="nv-metric-grid">
          <MetricCard
            icon="ri-apps-2-line"
            label="Visible Apps"
            value={mergedApplications.length}
            meta={`${totals.deviceCount} device associations | ${totals.productApps} product apps | ${totals.networkServices} service buckets`}
            accent="#54c8e8"
          />
          <MetricCard
            icon="ri-flashlight-line"
            label="Active Product Apps"
            value={totals.activeProductApps}
            meta={`${totals.activeNetworkServices} service buckets are active in the live feed`}
            accent="#22d3ee"
          />
          <MetricCard
            icon="ri-radar-line"
            label="Network Services"
            value={totals.networkServices}
            meta="Transport and control-plane buckets are grouped separately"
            accent="#8b5cf6"
          />
          <MetricCard
            icon="ri-exchange-funds-line"
            label="Traffic Volume"
            value={formatByteCount(totals.bandwidthBytes)}
            meta="Aggregated across the 24-hour application window"
            accent="#2dd4bf"
          />
        </div>
      )}

      <SectionCard title="Product Apps" caption="Product-level traffic with concrete application identity">
        {loading ? (
          <TableSkeleton rows={4} />
        ) : (
          renderApplicationGrid(
            productApplications,
            'No product applications yet',
            'Start the gateway or agent and allow some traffic to flow. Product apps are grouped from the last 24 hours of visible sessions.',
          )
        )}
      </SectionCard>

      <SectionCard
        title="Network Services"
        caption="Transport, control, and unclassified buckets shown apart from product apps"
      >
        {loading ? (
          <TableSkeleton rows={4} />
        ) : (
          renderApplicationGrid(
            networkApplications,
            'No network services yet',
            'Protocol-level buckets such as HTTPS, DNS, QUIC, NBNS, Other, and Unknown will appear here when the agent has seen control-plane traffic.',
          )
        )}
      </SectionCard>

      <SectionCard
        title="Needs Classification"
        caption="Known hosts that are still rolling up as Other or Unknown"
        aside={<StatusBadge tone="warning">{classificationRows.length} hosts</StatusBadge>}
      >
        <div className="nv-scroll-region nv-scroll-region--lg">
          <DataTable
            columns={[
              {
                key: 'host',
                label: 'Host',
                render: (row) => (
                  <>
                    <div className="nv-table__primary">{row.base_domain || row.host || '-'}</div>
                    <div className="nv-table__meta mono">{row.host || '-'}</div>
                  </>
                ),
              },
              {
                key: 'flow_count',
                label: 'Flows',
                render: (row) => <span className="mono">{row.flow_count || 0}</span>,
              },
              {
                key: 'bandwidth',
                label: 'Bandwidth',
                render: (row) => <span className="mono">{row.bandwidth || formatByteCount(row.bandwidth_bytes || 0)}</span>,
              },
              {
                key: 'last_seen',
                label: 'Last Seen',
                render: (row) => <span className="mono">{row.last_seen || 'N/A'}</span>,
              },
            ]}
            rows={classificationRows}
            rowKey={(row, index) => `${row.base_domain || row.host || 'unknown'}-${index}`}
            emptyTitle="No classification gaps"
            emptyDescription="The current 24-hour window does not have enough uncategorized hosts to surface here."
          />
        </div>
      </SectionCard>
    </div>
  );
};

export default ApplicationsPage;

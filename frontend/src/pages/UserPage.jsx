import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { systemService } from '../services/api';
import { isAdminRole } from '../utils/roles';
import { formatRuntime, getApplicationVisual } from '../utils/apps';
import { formatUtcTimestampToLocal } from '../utils/time';
import { formatBrowserLabel, formatByteCount, getRiskTone, getStatusTone } from '../utils/presentation';
import { DetailSkeleton } from '../components/UI/Skeletons';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import StatusBadge from '../components/V2/StatusBadge';
import Tabs from '../components/V2/Tabs';
import DataTable from '../components/V2/DataTable';
import InsightList from '../components/V2/InsightList';
import DpiSetupGuide from '../components/DPI/DpiSetupGuide';
import WebEvidenceDrawer from '../components/DPI/WebEvidenceDrawer';
import { getWebEvidencePrimaryLabel, getWebEvidenceScopeLabel, matchesWebEvidenceFilters, normalizeWebRiskLevel } from '../utils/webEvidence';

const emptySummary = {
  safety_score: null,
  recent_activity: [],
  transparency_log: [],
  scoped: false,
};

const formatConfidence = (value) => {
  const score = Number(value) || 0;
  if (score >= 0.8) {
    return `High (${score.toFixed(2)})`;
  }
  if (score >= 0.55) {
    return `Medium (${score.toFixed(2)})`;
  }
  return `Low (${score.toFixed(2)})`;
};

const UserPage = () => {
  const { deviceIp } = useParams();
  const normalizedDeviceIp = deviceIp ? decodeURIComponent(deviceIp) : null;

  if (normalizedDeviceIp) {
    return <DeviceWorkspace deviceIp={normalizedDeviceIp} />;
  }

  return <AccountWorkspace />;
};

const AccountWorkspace = () => {
  const { user } = useAuth();
  const [summary, setSummary] = useState(emptySummary);

  useEffect(() => {
    if (!user) {
      return;
    }

    if (!isAdminRole(user.role)) {
      setSummary(emptySummary);
      return;
    }

    systemService.getUserSummary(user.role)
      .then((res) => setSummary(res.data || emptySummary))
      .catch(() => setSummary(emptySummary));
  }, [user]);

  const displayUser = user || {
    username: 'User',
    role: 'viewer',
    email: 'user@netvisor.local',
  };

  const transparencyColumns = [
    { key: 'src_ip', label: 'Source', render: (row) => <span className="mono">{row.src_ip || '-'}</span> },
    { key: 'dst_ip', label: 'Destination', render: (row) => <span className="mono">{row.dst_ip || '-'}</span> },
    { key: 'domain', label: 'Domain', render: (row) => row.domain || '-' },
    { key: 'timestamp', label: 'Timestamp', render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.timestamp)}</span> },
  ];

  const recentItems = summary.recent_activity.slice(0, 6).map((entry, index) => ({
    key: `${entry.src_ip || 'src'}-${entry.dst_ip || 'dst'}-${index}`,
    icon: entry.severity === 'HIGH' || entry.severity === 'CRITICAL' ? 'ri-alert-line' : 'ri-links-line',
    title: entry.application || entry.domain || 'Observed activity',
    description: `${entry.src_ip || '-'} → ${entry.dst_ip || '-'}`,
    meta: entry.severity || 'LOW',
  }));

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Personal Workspace"
        title="My Security Profile"
        description="Review your current account posture, recent scoped activity, and the metadata transparency log associated with your account."
      />

      <section className="nv-section nv-identity-card">
        <div className="nv-identity-card__main">
          <div className="nv-identity-card__eyebrow">User Identity</div>
          <div className="nv-identity-card__value">{displayUser.username}</div>
          <p className="nv-identity-card__meta">{displayUser.email || `${displayUser.username}@netvisor.local`}</p>
        </div>
        <div className="nv-identity-card__aside">
          <div className="nv-stack">
            <StatusBadge tone="accent" icon="ri-user-star-line">{displayUser.role}</StatusBadge>
            <StatusBadge tone={summary.scoped ? 'success' : 'warning'} icon="ri-shield-check-line">
              {summary.scoped ? 'Scoped Activity Available' : 'Awaiting Device Link'}
            </StatusBadge>
          </div>
        </div>
      </section>

      <div className="nv-metric-grid">
        <MetricCard
          icon="ri-shield-check-line"
          label="Safety Score"
          value={summary.safety_score ?? '--'}
          meta={summary.safety_score === null ? 'Linked device telemetry required' : 'Higher is better'}
          accent="#2dd4bf"
        />
        <MetricCard
          icon="ri-history-line"
          label="Recent Events"
          value={summary.recent_activity.length}
          meta="Scoped activity visible to this account"
          accent="#60a5fa"
        />
        <MetricCard
          icon="ri-eye-line"
          label="Transparency Entries"
          value={summary.transparency_log.length}
          meta="Metadata-only transparency feed"
          accent="#54c8e8"
        />
        <MetricCard
          icon="ri-shield-user-line"
          label="Role Context"
          value={displayUser.role}
          meta={summary.scoped ? 'Security telemetry is visible' : 'Privilege does not imply device visibility'}
          accent="#fbbf24"
        />
      </div>

      <div className="nv-grid nv-grid--equal">
        <SectionCard title="Recent Activity" caption="Investigation Snapshot">
          {summary.scoped ? (
            <InsightList items={recentItems} />
          ) : (
            <div className="nv-empty" style={{ background: 'transparent', boxShadow: 'none', border: '0' }}>
              <div className="nv-empty__icon">
                <i className="ri-shield-user-line"></i>
              </div>
              <div className="nv-stack" style={{ gap: '0.5rem' }}>
                <h3 className="nv-empty__title">No linked device yet</h3>
                <p className="nv-empty__description">Personal activity will appear here after a managed device is linked to this account.</p>
              </div>
            </div>
          )}
        </SectionCard>

        <SectionCard title="Transparency Log" caption="Metadata Feed">
          <DataTable
            columns={transparencyColumns}
            rows={summary.transparency_log.slice(0, 8)}
            rowKey={(row, index) => `${row.src_ip || 'src'}-${row.dst_ip || 'dst'}-${index}`}
            emptyTitle={summary.scoped ? 'No recent activity' : 'No linked device activity'}
            emptyDescription={summary.scoped ? 'There are no transparency entries in the current window.' : 'Link a device to expose metadata entries here.'}
          />
        </SectionCard>
      </div>
    </div>
  );
};

const DeviceWorkspace = ({ deviceIp }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [profile, setProfile] = useState(null);
  const [policyUpdating, setPolicyUpdating] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [webFilters, setWebFilters] = useState({
    query: '',
    browser: 'all',
    domain: 'all',
    risk: 'all',
  });
  const [selectedWebEvent, setSelectedWebEvent] = useState(null);

  const fetchProfile = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const res = await systemService.getDeviceProfile(deviceIp);
      setProfile(res.data);
    } catch (error) {
      console.error('Failed to fetch device profile', error);
      setProfile(null);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, [deviceIp]);

  useEffect(() => {
    fetchProfile();
  }, [fetchProfile]);

  useVisibilityPolling(() => fetchProfile({ background: true }), 15000);

  const inspectionStatus = profile?.inspection_status || null;
  const webActivity = useMemo(() => profile?.web_activity || [], [profile?.web_activity]);
  const webEvidenceGroups = useMemo(() => profile?.web_evidence_groups || [], [profile?.web_evidence_groups]);
  const availableBrowsers = useMemo(
    () => [...new Set(webActivity.map((entry) => entry.browser_name || entry.process_name).filter(Boolean))].sort(),
    [webActivity],
  );
  const availableDomains = useMemo(
    () => [...new Set(webActivity.map((entry) => entry.base_domain).filter(Boolean))].sort(),
    [webActivity],
  );

  const filteredWebActivity = useMemo(() => {
    return webActivity.filter((entry) => matchesWebEvidenceFilters(entry, webFilters));
  }, [webActivity, webFilters]);

  const filteredWebEvidenceGroups = useMemo(
    () => webEvidenceGroups.filter((entry) => matchesWebEvidenceFilters(entry, webFilters)),
    [webEvidenceGroups, webFilters],
  );

  const applicationInsights = useMemo(
    () => (profile?.applications || []).map((entry) => ({
      key: `${profile?.device_ip || 'device'}-${entry.application}`,
      icon: getApplicationVisual(entry.application).icon,
      title: entry.application,
      description: `${entry.bandwidth} · ${entry.event_count} recent events`,
      meta: entry.last_seen ? formatUtcTimestampToLocal(entry.last_seen) : entry.runtime || formatRuntime(entry.runtime_seconds),
      onClick: () => navigate(`/apps/${encodeURIComponent(entry.application)}`),
    })),
    [navigate, profile?.applications, profile?.device_ip],
  );

  const recentSessionItems = useMemo(
    () => (profile?.recent_events || []).slice(0, 8).map((entry, index) => ({
      key: `${entry.src_ip || 'src'}-${entry.dst_ip || 'dst'}-${index}`,
      icon: entry.severity === 'HIGH' || entry.severity === 'CRITICAL' ? 'ri-alarm-warning-line' : 'ri-links-line',
      title: entry.application || entry.domain || 'Observed session',
      description: `${entry.src_ip === profile?.device_ip ? entry.dst_ip : entry.src_ip} · ${entry.protocol || 'Unknown'} · ${formatByteCount(entry.byte_count || entry.size || 0)}`,
      meta: formatUtcTimestampToLocal(entry.timestamp || entry.last_seen || entry.time_str || entry.time),
    })),
    [profile?.device_ip, profile?.recent_events],
  );

  const groupedWebColumns = [
    {
      key: 'page_title',
      label: 'Evidence',
      render: (row) => (
        <>
          <div className="nv-table__primary">{getWebEvidencePrimaryLabel(row)}</div>
          <div className="nv-table__meta">{row.base_domain || row.page_url || '-'}</div>
          <div className="nv-table__meta">{getWebEvidenceScopeLabel(row).text}</div>
        </>
      ),
    },
    {
      key: 'browser_name',
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
      key: 'risk_level',
      label: 'Risk',
      render: (row) => {
        const riskLevel = normalizeWebRiskLevel(row.risk_level);
        return (
          <>
            <StatusBadge tone={getRiskTone(riskLevel)}>{riskLevel}</StatusBadge>
            <div className="nv-table__meta">{formatConfidence(row.confidence_score)}</div>
          </>
        );
      },
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen)}</span>,
    },
  ];

  const rawWebColumns = [
    {
      key: 'page_title',
      label: 'Evidence',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.page_title || 'Untitled'}</div>
          <div className="nv-table__meta">{row.page_url || row.base_domain}</div>
        </>
      ),
    },
    {
      key: 'browser_name',
      label: 'Browser',
      render: (row) => (
        <>
          <div className="nv-table__primary">{formatBrowserLabel(row.browser_name, row.process_name)}</div>
          <div className="nv-table__meta">{row.base_domain || '-'}</div>
        </>
      ),
    },
    {
      key: 'risk_level',
      label: 'Risk',
      render: (row) => {
        const riskLevel = normalizeWebRiskLevel(row.risk_level);
        return (
          <>
            <StatusBadge tone={getRiskTone(riskLevel)}>{riskLevel}</StatusBadge>
            <div className="nv-table__meta">{formatConfidence(row.confidence_score)}</div>
          </>
        );
      },
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{formatUtcTimestampToLocal(row.last_seen)}</span>,
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (row) => (
        <button type="button" className="nv-button nv-button--secondary" onClick={(event) => {
          event.stopPropagation();
          setSelectedWebEvent(row);
        }}>
          View Evidence
        </button>
      ),
    },
  ];

  const applicationColumns = [
    {
      key: 'application',
      label: 'Application',
      render: (row) => {
        const visual = getApplicationVisual(row.application);
        return (
          <div className="nv-pill-card" style={{ padding: 0, border: 0, background: 'transparent' }}>
            <div className="nv-pill-card__icon" style={{ color: visual.accent, background: visual.background, borderColor: `${visual.accent}33` }}>
              <i className={visual.icon}></i>
            </div>
            <div className="nv-pill-card__content">
              <strong>{row.application}</strong>
              <span>{row.bandwidth}</span>
            </div>
          </div>
        );
      },
    },
    {
      key: 'events',
      label: 'Activity',
      render: (row) => (
        <>
          <div className="nv-table__primary">{row.event_count} recent events</div>
          <div className="nv-table__meta">{row.runtime || formatRuntime(row.runtime_seconds)}</div>
        </>
      ),
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (row) => <span className="mono">{row.last_seen ? formatUtcTimestampToLocal(row.last_seen) : 'Unknown'}</span>,
    },
  ];

  const toggleInspection = useCallback(async () => {
    if (!inspectionStatus?.agent_id) {
      return;
    }

    setPolicyUpdating(true);
    try {
      await systemService.updateInspectionPolicy(inspectionStatus.agent_id, {
        device_ip: deviceIp,
        inspection_enabled: !inspectionStatus.inspection_enabled,
      });
      await fetchProfile({ background: true });
    } catch (error) {
      console.error('Failed to update inspection policy', error);
    } finally {
      setPolicyUpdating(false);
    }
  }, [deviceIp, fetchProfile, inspectionStatus]);

  if (loading) {
    return <DetailSkeleton />;
  }

  if (!profile) {
    return (
      <div className="nv-page">
        <SectionCard title="Device unavailable" caption="Investigation Blocked">
          <div className="nv-empty" style={{ background: 'transparent', boxShadow: 'none', border: '0', padding: 0 }}>
            <div className="nv-empty__icon">
              <i className="ri-device-line"></i>
            </div>
            <div className="nv-stack" style={{ gap: '0.5rem' }}>
              <h3 className="nv-empty__title">We could not build a device profile</h3>
              <p className="nv-empty__description">The current inventory and activity feeds do not contain enough data for {deviceIp}.</p>
            </div>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => navigate('/devices')}>
              Back to Devices
            </button>
          </div>
        </SectionCard>
      </div>
    );
  }

  const device = profile.device || {};

  const overviewTiles = [
    { label: 'Status', value: profile.status, meta: profile.management_mode === 'managed' ? 'Managed endpoint' : 'Observed or BYOD' },
    { label: 'Risk', value: `${Math.round(Number(profile.risk_score) || 0)}%`, meta: String(profile.risk_level || 'LOW').toUpperCase() },
    { label: 'Runtime', value: profile.runtime || formatRuntime(profile.runtime_seconds), meta: 'Derived from recent visible activity' },
    { label: 'Bandwidth', value: profile.bandwidth, meta: `${(profile.applications || []).length} application groups` },
  ];

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Investigation Workspace"
        title={profile.hostname || 'Unknown Device'}
        description="Review device identity, recent sessions, application usage, inspected browser activity, and operational inspection health from one structured workspace."
        actions={(
          <>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => navigate('/devices')}>
              <i className="ri-arrow-left-line"></i>
              Back to Devices
            </button>
            <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchProfile()}>
              <i className="ri-refresh-line"></i>
              Refresh
            </button>
            <Link className="nv-button nv-button--primary" to={`/user/${encodeURIComponent(deviceIp)}/web-activity`}>
              <i className="ri-navigation-line"></i>
              Deep Dive
            </Link>
          </>
        )}
      />

      <section className="nv-section nv-identity-card">
        <div className="nv-identity-card__main">
          <div className="nv-identity-card__eyebrow">Device Identity</div>
          <div className="nv-identity-card__value mono">{profile.device_ip}</div>
          <p className="nv-identity-card__meta">{device.vendor || device.device_type || device.os_family || 'Observed endpoint'}</p>
        </div>
        <div className="nv-identity-card__aside">
          <div className="nv-identity-card__stack">
            <StatusBadge tone={getStatusTone(profile.status)} icon="ri-checkbox-circle-line">{profile.status}</StatusBadge>
            <StatusBadge tone={profile.management_mode === 'managed' ? 'success' : 'neutral'} icon="ri-fingerprint-line">
              {profile.management_mode === 'managed' ? 'Managed' : 'BYOD'}
            </StatusBadge>
            <StatusBadge tone={inspectionStatus?.inspection_enabled ? 'accent' : 'neutral'} icon="ri-navigation-line">
              {inspectionStatus?.inspection_enabled ? 'Inspection Enabled' : 'Inspection Disabled'}
            </StatusBadge>
          </div>
        </div>
      </section>

      <div className="nv-summary-strip">
        {overviewTiles.map((tile) => (
          <div key={tile.label} className="nv-summary-tile">
            <span>{tile.label}</span>
            <strong>{tile.value}</strong>
            <p>{tile.meta}</p>
          </div>
        ))}
      </div>

      <Tabs
        value={activeTab}
        onChange={setActiveTab}
        items={[
          { value: 'overview', label: 'Overview', icon: 'ri-dashboard-line' },
          { value: 'applications', label: 'Applications', icon: 'ri-apps-2-line' },
          { value: 'web', label: 'Web Activity', icon: 'ri-navigation-line' },
          { value: 'inspection', label: 'Inspection Health', icon: 'ri-shield-check-line' },
        ]}
      />

      {activeTab === 'overview' ? (
        <div className="nv-grid nv-grid--equal">
          <SectionCard title="Recent Sessions" caption="Network Context">
            <div className="nv-timeline">
              {recentSessionItems.length > 0 ? (
                recentSessionItems.map((item) => (
                  <div key={item.key} className="nv-timeline-row">
                    <div className="nv-timeline-row__icon">
                      <i className={item.icon}></i>
                    </div>
                    <div>
                      <div className="nv-timeline-row__title">{item.title}</div>
                      <div className="nv-timeline-row__meta">{item.description}</div>
                    </div>
                    <div className="nv-timeline-row__aside">{item.meta}</div>
                  </div>
                ))
              ) : (
                <div className="nv-empty" style={{ background: 'transparent', boxShadow: 'none', border: '0', padding: 0 }}>
                  <div className="nv-empty__icon">
                    <i className="ri-pulse-line"></i>
                  </div>
                  <div className="nv-stack" style={{ gap: '0.5rem' }}>
                    <h3 className="nv-empty__title">No recent sessions</h3>
                    <p className="nv-empty__description">This device has no visible recent session activity in the current investigation window.</p>
                  </div>
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard title="Application Summary" caption="Ranked Usage">
            <InsightList items={applicationInsights.slice(0, 8)} />
          </SectionCard>
        </div>
      ) : null}

      {activeTab === 'applications' ? (
        <SectionCard title="Applications" caption="Ranked by Activity">
          <DataTable
            columns={applicationColumns}
            rows={profile.applications}
            rowKey={(row) => row.application}
            onRowClick={(row) => navigate(`/apps/${encodeURIComponent(row.application)}`)}
            emptyTitle="No application activity"
            emptyDescription="This device does not have visible application sessions in the current window."
          />
        </SectionCard>
      ) : null}

      {activeTab === 'web' ? (
        <div className="nv-stack" style={{ gap: '1rem' }}>
          <SectionCard
            title="Evidence Groups"
            caption="Correlated Browser Sessions"
            aside={(
              <div className="nv-inline-actions">
                <Link className="nv-button nv-button--ghost" to={`/user/${encodeURIComponent(profile.device_ip)}/web-activity`}>
                  Open Deep Dive
                </Link>
              </div>
            )}
          >
            <div className="nv-filterbar">
              <div className="nv-filterbar__group">
                <label className="nv-field nv-field--grow">
                  <i className="ri-search-line"></i>
                  <input
                    type="search"
                    value={webFilters.query}
                    onChange={(event) => setWebFilters((current) => ({ ...current, query: event.target.value }))}
                    placeholder="Filter title, URL, content id, query..."
                  />
                </label>
                <label className="nv-field">
                  <select value={webFilters.browser} onChange={(event) => setWebFilters((current) => ({ ...current, browser: event.target.value }))}>
                    <option value="all">All Browsers</option>
                    {availableBrowsers.map((browser) => (
                      <option key={browser} value={browser}>{browser}</option>
                    ))}
                  </select>
                </label>
                <label className="nv-field">
                  <select value={webFilters.domain} onChange={(event) => setWebFilters((current) => ({ ...current, domain: event.target.value }))}>
                    <option value="all">All Domains</option>
                    {availableDomains.map((domain) => (
                      <option key={domain} value={domain}>{domain}</option>
                    ))}
                  </select>
                </label>
                <label className="nv-field">
                  <select value={webFilters.risk} onChange={(event) => setWebFilters((current) => ({ ...current, risk: event.target.value }))}>
                    <option value="all">All Risk</option>
                    <option value="safe">Safe</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </label>
              </div>
            </div>

            <DataTable
              columns={groupedWebColumns}
              rows={filteredWebEvidenceGroups}
              rowKey={(row, index) => row.group_key || `${row.page_url || row.base_domain}-${row.last_seen || index}`}
              onRowClick={(row) => setSelectedWebEvent(row)}
              emptyTitle="No grouped evidence"
              emptyDescription="Use the NetVisor browser wrappers and approved inspection domains to populate this evidence stream."
            />
          </SectionCard>

          <SectionCard title="Raw Browser Sessions" caption="Inspected Sessions">
            <DataTable
              columns={rawWebColumns}
              rows={filteredWebActivity}
              rowKey={(row, index) => row.id || `${row.page_url || row.base_domain}-${row.last_seen || index}`}
              onRowClick={(row) => setSelectedWebEvent(row)}
              emptyTitle="No inspected web activity"
              emptyDescription="Use the NetVisor browser wrappers and approved inspection domains to populate this evidence stream."
            />
          </SectionCard>
        </div>
      ) : null}

      {activeTab === 'inspection' ? (
        <SectionCard title="Inspection Health" caption="Agent-side Proxy and CA State">
          <div className="nv-summary-strip">
            <div className="nv-summary-tile">
              <span>Inspection</span>
              <strong>{inspectionStatus?.inspection_enabled ? 'Enabled' : 'Disabled'}</strong>
              <p>{inspectionStatus?.agent_id ? `Agent ${inspectionStatus.agent_id}` : 'No managing agent available'}</p>
            </div>
            <div className="nv-summary-tile">
              <span>Proxy</span>
              <strong>{inspectionStatus?.proxy_running ? 'Running' : 'Stopped'}</strong>
              <p>{inspectionStatus?.status || 'disabled'} · port {inspectionStatus?.proxy_port || 8899}</p>
            </div>
            <div className="nv-summary-tile">
              <span>Certificate</span>
              <strong>{inspectionStatus?.ca_status || (inspectionStatus?.ca_installed ? 'Installed' : 'Missing')}</strong>
              <p>{inspectionStatus?.browser_support?.join(', ') || 'Chrome / Edge wrappers'}</p>
            </div>
            <div className="nv-summary-tile">
              <span>Queue & Upload</span>
              <strong>{inspectionStatus?.queue_size ?? 0}</strong>
              <p>{inspectionStatus?.uploaded_event_count ?? 0} uploaded · {inspectionStatus?.upload_failures ?? 0} failed</p>
            </div>
          </div>

          <div className="nv-inline-actions">
            <button
              type="button"
              className={`nv-button ${inspectionStatus?.inspection_enabled ? 'nv-button--danger' : 'nv-button--primary'}`}
              onClick={toggleInspection}
              disabled={!inspectionStatus?.agent_id || policyUpdating}
            >
              <i className={inspectionStatus?.inspection_enabled ? 'ri-shield-close-line' : 'ri-shield-check-line'}></i>
              {policyUpdating ? 'Updating…' : inspectionStatus?.inspection_enabled ? 'Disable Inspection' : 'Enable Inspection'}
            </button>
          </div>

          {inspectionStatus?.last_error ? (
            <StatusBadge tone="warning" icon="ri-error-warning-line">{inspectionStatus.last_error}</StatusBadge>
          ) : null}

          {inspectionStatus?.drop_reasons && Object.keys(inspectionStatus.drop_reasons).length > 0 ? (
            <div className="nv-inline-actions">
              {Object.entries(inspectionStatus.drop_reasons).map(([reason, count]) => (
                <StatusBadge key={reason} tone="neutral">{reason.replace(/_/g, ' ')} · {count}</StatusBadge>
              ))}
            </div>
          ) : null}

          {webActivity.length === 0 ? (
            <DpiSetupGuide deviceIp={profile.device_ip} inspectionStatus={inspectionStatus} />
          ) : null}
        </SectionCard>
      ) : null}

      <SidePanel
        open={Boolean(selectedWebEvent)}
        title={selectedWebEvent?.page_title || selectedWebEvent?.base_domain || 'Evidence'}
        description="Redacted summary only. No full payload bodies are stored."
        onClose={() => setSelectedWebEvent(null)}
        footer={selectedWebEvent ? (
          <StatusBadge tone={getRiskTone(selectedWebEvent.risk_level)}>
            {selectedWebEvent.risk_level || 'safe'} · {formatConfidence(selectedWebEvent.confidence_score)}
          </StatusBadge>
        ) : null}
      >
        {selectedWebEvent ? (
          <div className="nv-evidence-grid">
            <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
              <div className="nv-summary-tile">
                <span>Browser</span>
                <strong>{formatBrowserLabel(selectedWebEvent.browser_name, selectedWebEvent.process_name)}</strong>
                <p>{selectedWebEvent.base_domain || '-'}</p>
              </div>
              <div className="nv-summary-tile">
                <span>Last Seen</span>
                <strong>{formatUtcTimestampToLocal(selectedWebEvent.last_seen)}</strong>
                <p>First seen {formatUtcTimestampToLocal(selectedWebEvent.first_seen)}</p>
              </div>
              <div className="nv-summary-tile">
                <span>Content</span>
                <strong>{selectedWebEvent.content_id || selectedWebEvent.content_category || 'web'}</strong>
                <p>{selectedWebEvent.content_type || 'text/html'}</p>
              </div>
              <div className="nv-summary-tile">
                <span>Traffic</span>
                <strong>{selectedWebEvent.response_bytes_formatted || formatByteCount(selectedWebEvent.response_bytes)}</strong>
                <p>{selectedWebEvent.http_method || 'GET'} · {selectedWebEvent.status_code || 'n/a'} · {selectedWebEvent.event_count || 1} event(s)</p>
              </div>
            </div>
            <SectionCard title="URL" caption="Observed Location">
              <code className="nv-code-block">{selectedWebEvent.page_url || 'No URL captured'}</code>
            </SectionCard>
            <SectionCard title="Redacted Snippet" caption="Evidence">
              <pre className="nv-code-block">{selectedWebEvent.snippet_redacted || 'No textual snippet captured for this event.'}</pre>
            </SectionCard>
            {selectedWebEvent.threat_msg ? (
              <SectionCard title="Threat Note" caption="Detection Context">
                <p>{selectedWebEvent.threat_msg}</p>
              </SectionCard>
            ) : null}
          </div>
        ) : null}
      </SidePanel>
    </div>
  );
};

export default UserPage;

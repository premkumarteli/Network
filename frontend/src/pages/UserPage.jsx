import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import { systemService } from '../services/api';
import { isAdminRole } from '../utils/roles';
import { formatRuntime, getApplicationVisual } from '../utils/apps';
import { formatUtcTimestampToLocal } from '../utils/time';
import KpiCard from '../components/UI/KpiCard';
import { DetailSkeleton } from '../components/UI/Skeletons';

const emptySummary = {
  safety_score: null,
  recent_activity: [],
  transparency_log: [],
  scoped: false,
};

const UserPage = () => {
  const { deviceIp } = useParams();
  const normalizedDeviceIp = deviceIp ? decodeURIComponent(deviceIp) : null;

  if (normalizedDeviceIp) {
    return <DeviceDrilldownView deviceIp={normalizedDeviceIp} />;
  }

  return <AccountSecurityView />;
};

const AccountSecurityView = () => {
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
    username: '...',
    role: 'viewer',
    email: '...',
  };

  return (
    <div className="page-shell">
      <div className="page-hero">
        <div>
          <div className="page-eyebrow">User Workspace</div>
          <h2>My Security Profile</h2>
          <p className="page-subtitle">
            Review your current account posture, recent activity, and metadata transparency log.
          </p>
        </div>
      </div>

      <div className="profile-banner glass-panel">
        <div className="profile-avatar">{displayUser.username[0]?.toUpperCase() || 'U'}</div>
        <div>
          <h3>{displayUser.username}</h3>
          <p>{displayUser.email || `${displayUser.username}@netvisor.local`}</p>
        </div>
        <span className="badge success">{displayUser.role}</span>
      </div>

      <div className="kpi-grid compact">
        <KpiCard
          icon="ri-shield-check-line"
          label="Safety Score"
          value={summary.safety_score ?? '--'}
          meta={summary.safety_score === null ? 'Awaiting device link' : 'higher is better'}
          accent="#34d399"
        />
        <KpiCard
          icon="ri-history-line"
          label="Recent Events"
          value={summary.recent_activity.length}
          meta="recent items visible to this account"
          accent="#60a5fa"
        />
        <KpiCard
          icon="ri-eye-line"
          label="Transparency Entries"
          value={summary.transparency_log.length}
          meta={summary.scoped ? 'metadata-only transparency feed' : 'device link required'}
          accent="#22d3ee"
        />
      </div>

      <div className="detail-grid">
        <div className="chart-card">
          <div className="section-title-row">
            <h3>Recent Activity</h3>
            <span className="table-caption">latest events scoped to your account</span>
          </div>
          {!summary.scoped ? (
            <div className="empty-panel">
              <h3>No linked device yet</h3>
              <p>Personal activity will appear here after a managed device is linked to this account.</p>
            </div>
          ) : (
            <div className="activity-mini-list">
              {summary.recent_activity.slice(0, 6).map((entry, index) => (
                <div key={`${entry.src_ip}-${entry.dst_ip}-${index}`} className="activity-mini-list__row">
                  <div>
                    <strong>{entry.application || entry.domain || 'Other'}</strong>
                    <p>{entry.domain || entry.dst_ip || '-'}</p>
                  </div>
                  <span className={`badge ${entry.severity === 'HIGH' || entry.severity === 'CRITICAL' ? 'danger' : entry.severity === 'MEDIUM' ? 'warning' : 'success'}`}>
                    {entry.severity || 'LOW'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="chart-card">
          <div className="section-title-row">
            <h3>Transparency Log</h3>
            <span className="table-caption">source, destination, domain, timestamp</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Domain</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {!summary.scoped || summary.transparency_log.length === 0 ? (
                <tr>
                  <td colSpan="4" className="empty-state">
                    {summary.scoped ? 'No recent activity.' : 'No linked device activity yet.'}
                  </td>
                </tr>
              ) : (
                summary.transparency_log.slice(0, 8).map((entry, index) => (
                  <tr key={`${entry.src_ip}-${entry.dst_ip}-${index}`}>
                    <td className="mono">{entry.src_ip}</td>
                    <td className="mono">{entry.dst_ip}</td>
                    <td>{entry.domain || '-'}</td>
                    <td className="mono muted">{entry.timestamp}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const DeviceDrilldownView = ({ deviceIp }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [profile, setProfile] = useState(null);
  const [policyUpdating, setPolicyUpdating] = useState(false);

  const fetchProfile = useCallback(async (background = false) => {
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

  useVisibilityPolling(() => fetchProfile(true), 15000);

  const applicationCount = profile?.applications?.length || 0;
  const activeAppCount = useMemo(
    () => (profile?.applications || []).filter((entry) => entry.event_count > 0).length,
    [profile?.applications],
  );
  const inspectionStatus = profile?.inspection_status || null;

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
      await fetchProfile(true);
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
      <div className="page-shell">
        <div className="empty-panel">
          <h3>Device data unavailable</h3>
          <p>We could not build a profile for {deviceIp} from the current inventory and activity feeds.</p>
          <button className="action-btn" onClick={() => navigate('/devices')}>
            Back to Devices
          </button>
        </div>
      </div>
    );
  }

  const device = profile.device || {};

  return (
    <div className="page-shell">
      <div className="page-hero">
        <div>
          <div className="page-eyebrow">Device Drill-down</div>
          <h2>{profile.hostname || 'Unknown Device'}</h2>
          <p className="page-subtitle">
            Single-device view with recent application activity, runtime, bandwidth, and operational status.
          </p>
        </div>
        <div className="page-actions">
          <Link className="action-btn ghost" to="/devices">
            <i className="ri-arrow-left-line"></i> Back
          </Link>
          <button className="action-btn" onClick={() => navigate('/apps')}>
            <i className="ri-apps-2-line"></i> Applications
          </button>
        </div>
      </div>

      <div className="device-banner glass-panel">
        <div>
          <span className="summary-label">Device IP</span>
          <h3 className="mono">{profile.device_ip}</h3>
          <p>{device.vendor || device.device_type || 'Observed endpoint'}</p>
        </div>
        <div className="device-banner__status">
          <span className={`badge ${profile.status === 'Online' ? 'success' : profile.status === 'Idle' ? 'warning' : 'neutral'}`}>
            {profile.status}
          </span>
          <span className={`badge ${profile.management_mode === 'managed' ? 'success' : 'neutral'}`}>
            {profile.management_mode === 'managed' ? 'Managed' : 'BYOD'}
          </span>
        </div>
      </div>

      <div className="kpi-grid compact">
        <KpiCard
          icon="ri-time-line"
          label="Runtime"
          value={profile.runtime || formatRuntime(profile.runtime_seconds)}
          meta="derived from recent visible activity"
          accent="#60a5fa"
        />
        <KpiCard
          icon="ri-exchange-funds-line"
          label="Bandwidth"
          value={profile.bandwidth}
          meta="aggregated from recent sessions"
          accent="#34d399"
        />
        <KpiCard
          icon="ri-layout-grid-line"
          label="Applications"
          value={applicationCount}
          meta={`${activeAppCount} active application groups`}
          accent="#22d3ee"
        />
        <KpiCard
          icon="ri-pulse-line"
          label="Last Seen"
          value={formatUtcTimestampToLocal(profile.last_seen)}
          meta="latest event or device presence update"
          accent="#fbbf24"
        />
      </div>

      <div className="detail-grid">
        <div className="chart-card">
          <div className="section-title-row">
            <h3>Applications Used</h3>
            <span className="table-caption">bandwidth-weighted application summary</span>
          </div>
          <div className="app-pill-grid">
            {profile.applications.length === 0 ? (
              <div className="empty-panel">
                <h3>No application activity</h3>
                <p>This device has no visible application sessions in the current activity window.</p>
              </div>
            ) : (
              profile.applications.map((entry) => {
                const visual = getApplicationVisual(entry.application);
                return (
                  <div key={`${profile.device_ip}-${entry.application}`} className="app-pill-card">
                    <div
                      className="app-logo-shell"
                      style={{
                        color: visual.accent,
                        background: visual.background,
                        borderColor: `${visual.accent}33`,
                      }}
                    >
                      <i className={visual.icon}></i>
                    </div>
                    <div className="app-pill-card__content">
                      <strong>{entry.application}</strong>
                      <span>{entry.bandwidth}</span>
                      <span className="table-caption">{entry.event_count} recent events</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        <div className="chart-card">
          <div className="section-title-row">
            <h3>Recent Events</h3>
            <span className="table-caption">latest activity touching {profile.device_ip}</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Application</th>
                <th>Remote</th>
                <th>Protocol</th>
                <th>Severity</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {profile.recent_events.length === 0 ? (
                <tr>
                  <td colSpan="5" className="empty-state">No recent sessions available.</td>
                </tr>
              ) : (
                profile.recent_events.map((entry, index) => (
                  <tr key={`${entry.src_ip}-${entry.dst_ip}-${index}`}>
                    <td>{entry.application || 'Other'}</td>
                    <td className="mono">{entry.src_ip === profile.device_ip ? entry.dst_ip : entry.src_ip}</td>
                    <td>{entry.protocol || 'Unknown'}</td>
                    <td>
                      <span className={`badge ${entry.severity === 'HIGH' || entry.severity === 'CRITICAL' ? 'danger' : entry.severity === 'MEDIUM' ? 'warning' : 'success'}`}>
                        {entry.severity || 'LOW'}
                      </span>
                    </td>
                    <td className="mono muted">{formatUtcTimestampToLocal(entry.timestamp || entry.last_seen || entry.time_str || entry.time || '-')}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="detail-grid">
        <div className="chart-card">
          <div className="section-title-row">
            <h3>Inspection Status</h3>
            <span className="table-caption">agent-only web visibility for this device</span>
          </div>
          <div className="summary-grid">
            <div className="summary-card">
              <span className="summary-label">Inspection</span>
              <strong>{inspectionStatus?.inspection_enabled ? 'Enabled' : 'Disabled'}</strong>
              <span className="summary-meta">
                {inspectionStatus?.agent_id ? `Agent ${inspectionStatus.agent_id}` : 'No managing agent available'}
              </span>
            </div>
            <div className="summary-card">
              <span className="summary-label">Proxy</span>
              <strong>{inspectionStatus?.proxy_running ? 'Running' : 'Stopped'}</strong>
              <span className="summary-meta">{inspectionStatus?.status || 'disabled'}</span>
            </div>
            <div className="summary-card">
              <span className="summary-label">CA Status</span>
              <strong>{inspectionStatus?.ca_installed ? 'Installed' : 'Missing'}</strong>
              <span className="summary-meta">
                {inspectionStatus?.browser_support?.join(', ') || 'Chrome / Edge'}
              </span>
            </div>
            <div className="summary-card">
              <span className="summary-label">Recent Web Events</span>
              <strong>{inspectionStatus?.recent_event_count ?? 0}</strong>
              <span className="summary-meta">
                {inspectionStatus?.last_event_at ? formatUtcTimestampToLocal(inspectionStatus.last_event_at) : 'No recent inspection activity'}
              </span>
            </div>
          </div>
          <div className="quick-actions">
            <button
              className="action-btn"
              onClick={toggleInspection}
              disabled={!inspectionStatus?.agent_id || policyUpdating}
            >
              <i className={inspectionStatus?.inspection_enabled ? 'ri-shield-close-line' : 'ri-shield-check-line'}></i>
              {policyUpdating ? 'Updating...' : inspectionStatus?.inspection_enabled ? 'Disable Inspection' : 'Enable Inspection'}
            </button>
          </div>
          {inspectionStatus?.last_error ? (
            <div className="empty-panel" style={{ marginTop: '1rem', textAlign: 'left' }}>
              <h3>Inspection Degraded</h3>
              <p>{inspectionStatus.last_error}</p>
            </div>
          ) : null}
        </div>

        <div className="chart-card">
          <div className="section-title-row">
            <h3>Web Activity</h3>
            <span className="table-caption">recent inspected browser sessions</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Domain</th>
                <th>Browser</th>
                <th>Content</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {(profile.web_activity || []).length === 0 ? (
                <tr>
                  <td colSpan="5" className="empty-state">No recent inspected web activity.</td>
                </tr>
              ) : (
                profile.web_activity.map((entry, index) => (
                  <tr key={`${entry.page_url}-${index}`}>
                    <td>
                      <div className="table-primary">{entry.page_title || 'Untitled'}</div>
                      <div className="table-meta mono">{entry.page_url}</div>
                    </td>
                    <td>{entry.base_domain}</td>
                    <td>{entry.browser_name || entry.process_name}</td>
                    <td>
                      <div>{entry.content_category || 'web'}</div>
                      <div className="table-meta mono">{entry.content_id || entry.response_bytes_formatted}</div>
                    </td>
                    <td className="mono muted">{formatUtcTimestampToLocal(entry.last_seen)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default UserPage;

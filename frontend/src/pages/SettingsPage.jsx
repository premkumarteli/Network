import { useCallback, useEffect, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import PageHeader from '../components/V2/PageHeader';
import SectionCard from '../components/V2/SectionCard';
import MetricCard from '../components/V2/MetricCard';
import StatusBadge from '../components/V2/StatusBadge';

const SettingsPage = () => {
  const [stats, setStats] = useState({ cpu_percent: 0, mem_used_mb: 0, mem_total_mb: 1024, maintenance_mode: false });
  const [systemActive, setSystemActive] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async ({ background = false } = {}) => {
    if (!background) {
      setLoading(true);
    }
    try {
      const [statsRes, sysRes] = await Promise.all([
        systemService.getAdminStats(),
        systemService.getSystemStatus(),
      ]);
      setStats(statsRes.data || { cpu_percent: 0, mem_used_mb: 0, mem_total_mb: 1024, maintenance_mode: false });
      setSystemActive(Boolean(sysRes.data?.runtime?.active ?? sysRes.data?.active));
    } catch (err) {
      console.error('Failed to fetch settings data', err);
    } finally {
      if (!background) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useVisibilityPolling(() => fetchData({ background: true }), 20000);

  const toggleMaintenance = async () => {
    try {
      await systemService.setMaintenanceMode(!stats.maintenance_mode);
      await fetchData();
    } catch {
      window.alert('Failed to toggle maintenance mode');
    }
  };

  const toggleMonitoring = async () => {
    try {
      await systemService.setMonitoring(!systemActive);
      await fetchData();
    } catch {
      window.alert('Failed to toggle monitoring');
    }
  };

  const triggerScan = async () => {
    try {
      const res = await systemService.triggerScan();
      window.alert(res.data.message);
    } catch {
      window.alert('Failed to trigger scan');
    }
  };

  const resetDatabase = async () => {
    if (!window.confirm('CRITICAL WARNING: This will wipe ALL traffic logs. Are you sure?')) return;
    try {
      const res = await systemService.resetDatabase();
      window.alert(res.data.message);
      window.location.reload();
    } catch {
      window.alert('Failed to reset database');
    }
  };

  return (
    <div className="nv-page">
      <PageHeader
        eyebrow="Operations"
        title="System Controls"
        description="Group runtime controls, inspection posture, operational actions, and dangerous resets into one structured administration surface."
        actions={(
          <button type="button" className="nv-button nv-button--secondary" onClick={() => fetchData()}>
            <i className="ri-refresh-line"></i>
            Refresh
          </button>
        )}
      />

      <div className="nv-metric-grid">
        <MetricCard icon="ri-cpu-line" label="CPU Load" value={`${Math.round(stats.cpu_percent || 0)}%`} meta="Server load" accent="#54c8e8" />
        <MetricCard icon="ri-database-2-line" label="Memory" value={`${(stats.mem_used_mb / 1024).toFixed(1)} GB`} meta={`${(stats.mem_total_mb / 1024).toFixed(1)} GB total`} accent="#60a5fa" />
        <MetricCard icon="ri-radar-line" label="Monitoring" value={systemActive ? 'Active' : 'Paused'} meta="Packet and activity collection" accent="#2dd4bf" />
        <MetricCard icon="ri-tools-line" label="Maintenance" value={stats.maintenance_mode ? 'Enabled' : 'Disabled'} meta="Restricted access mode" accent="#fbbf24" />
      </div>

      {!loading ? (
        <div className="nv-grid nv-grid--three">
          <SectionCard title="System Controls" caption="Runtime">
            <div className="nv-inline-actions" style={{ justifyContent: 'space-between' }}>
              <div>
                <div className="nv-table__primary">Monitoring Engine</div>
                <div className="nv-table__meta">{systemActive ? 'Capturing and classifying traffic' : 'Collection paused'}</div>
              </div>
              <button type="button" className={`nv-button ${systemActive ? 'nv-button--secondary' : 'nv-button--primary'}`} onClick={toggleMonitoring}>
                {systemActive ? 'Pause' : 'Resume'}
              </button>
            </div>
            <div className="nv-inline-actions" style={{ justifyContent: 'space-between' }}>
              <div>
                <div className="nv-table__primary">Maintenance Mode</div>
                <div className="nv-table__meta">{stats.maintenance_mode ? 'Restricted access and controlled changes' : 'Normal access'}</div>
              </div>
              <button type="button" className={`nv-button ${stats.maintenance_mode ? 'nv-button--secondary' : 'nv-button--primary'}`} onClick={toggleMaintenance}>
                {stats.maintenance_mode ? 'Disable' : 'Enable'}
              </button>
            </div>
          </SectionCard>

          <SectionCard title="Operational Actions" caption="Safe Actions">
            <div className="nv-inline-actions">
              <button type="button" className="nv-button nv-button--secondary" onClick={triggerScan}>
                <i className="ri-radar-line"></i>
                Force Network Scan
              </button>
              <StatusBadge tone="accent" icon="ri-shield-check-line">Runtime healthy</StatusBadge>
            </div>
          </SectionCard>

          <SectionCard title="Danger Zone" caption="Destructive Actions">
            <div className="nv-stack">
              <p>Resetting the runtime database clears traffic logs and alerts while preserving users. Use only when you explicitly want a fresh evidence window.</p>
              <button type="button" className="nv-button nv-button--danger" onClick={resetDatabase}>
                <i className="ri-delete-bin-2-line"></i>
                Reset Database
              </button>
            </div>
          </SectionCard>
        </div>
      ) : null}
    </div>
  );
};

export default SettingsPage;

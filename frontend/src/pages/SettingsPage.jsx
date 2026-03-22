import { useCallback, useEffect, useState } from 'react';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';

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
                systemService.getSystemStatus()
            ]);
            setStats(statsRes.data || { cpu_percent: 0, mem_used_mb: 0, mem_total_mb: 1024, maintenance_mode: false });
            setSystemActive(Boolean(sysRes.data?.active));
        } catch (err) {
            console.error("Failed to fetch settings data", err);
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
            window.alert("Failed to toggle maintenance mode");
        }
    };

    const toggleMonitoring = async () => {
        try {
            await systemService.setMonitoring(!systemActive);
            await fetchData();
        } catch {
            window.alert("Failed to toggle monitoring");
        }
    };

    const triggerScan = async () => {
        try {
            const res = await systemService.triggerScan();
            window.alert(res.data.message);
        } catch {
            window.alert("Failed to trigger scan");
        }
    };

    const resetDatabase = async () => {
        if (!window.confirm("CRITICAL WARNING: This will wipe ALL traffic logs. Are you sure?")) return;
        try {
            const res = await systemService.resetDatabase();
            window.alert(res.data.message);
            window.location.reload();
        } catch {
            window.alert("Failed to reset database");
        }
    };

    return (
        <div className="page-shell animate-fade">
            <div className="page-hero">
                <div>
                    <div className="page-eyebrow">System Control</div>
                    <h2>System Settings</h2>
                    <p className="page-subtitle">
                        Manage server state, maintenance mode, runtime monitoring, and operational data resets.
                    </p>
                </div>
                <button className="action-btn" onClick={() => fetchData()}>
                    <i className="ri-refresh-line"></i> Refresh
                </button>
            </div>
            
            {loading ? (
                <div className="loading-state">Loading system settings...</div>
            ) : (
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
                
                {/* Server Status */}
                <div className="stat-card">
                    <h3><i className="ri-server-line"></i> Server Resources</h3>
                    <div style={{ marginTop: '1rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                            <span>CPU Load</span>
                            <span>{stats.cpu_percent}%</span>
                        </div>
                        <div className="progress-bar">
                            <div className="fill secondary" style={{ width: `${stats.cpu_percent}%` }}></div>
                        </div>
                        
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', marginTop: '1rem' }}>
                            <span>Memory</span>
                            <span>{(stats.mem_used_mb / 1024).toFixed(1)} / {(stats.mem_total_mb / 1024).toFixed(1)} GB</span>
                        </div>
                        <div className="progress-bar">
                            <div className="fill primary" style={{ width: `${stats.mem_total_mb ? (stats.mem_used_mb / stats.mem_total_mb) * 100 : 0}%` }}></div>
                        </div>
                    </div>
                </div>

                {/* System Control */}
                <div className="stat-card">
                    <h3><i className="ri-cpu-line"></i> System Control</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1rem' }}>
                        
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.05)', padding: '1rem', borderRadius: '8px' }}>
                            <div>
                                <div style={{ fontWeight: 600 }}>Monitoring Engine</div>
                                <div className="small muted">{systemActive ? "Active - Capturing" : "Paused"}</div>
                            </div>
                            <label className="switch">
                                <input type="checkbox" checked={systemActive} onChange={toggleMonitoring} />
                                <span className="slider round"></span>
                            </label>
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.05)', padding: '1rem', borderRadius: '8px' }}>
                            <div>
                                <div style={{ fontWeight: 600 }}>Maintenance Mode</div>
                                <div className="small muted">{stats.maintenance_mode ? "Restricted Access" : "Public Access"}</div>
                            </div>
                            <label className="switch">
                                <input type="checkbox" checked={stats.maintenance_mode} onChange={toggleMaintenance} />
                                <span className="slider round"></span>
                            </label>
                        </div>

                        <button className="action-btn" onClick={triggerScan}>
                            <i className="ri-radar-line"></i> Force Network Scan
                        </button>
                    </div>
                </div>

                {/* Data Management */}
                <div className="stat-card">
                     <h3><i className="ri-database-2-line"></i> Data Management</h3>
                     <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1rem', height: '100%', justifyContent: 'center' }}>
                        <button className="action-btn danger-hover" onClick={resetDatabase} style={{ border: '1px solid var(--danger)' }}>
                            <i className="ri-delete-bin-2-line"></i> Reset Database
                        </button>
                        <p className="small muted" style={{ textAlign: 'center' }}>
                            Clears all traffic logs and alerts. Users are preserved.
                        </p>
                     </div>
                </div>

            </div>
            )}
        </div>
    );
};

export default SettingsPage;

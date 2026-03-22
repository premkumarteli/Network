import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { systemService } from '../services/api';
import { useVisibilityPolling } from '../hooks/useVisibilityPolling';
import DeviceTable from '../components/Devices/DeviceTable';
import KpiCard from '../components/UI/KpiCard';
import { StatGridSkeleton, TableSkeleton } from '../components/UI/Skeletons';

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
            console.error("Failed to fetch devices", err);
        } finally {
            if (!background) {
                setLoading(false);
            }
        }
    };

    useEffect(() => {
        fetchDevices();
    }, []);

    useVisibilityPolling(() => {
        fetchDevices({ background: true });
    }, 15000);

    const namedDevices = devices.filter((device) => !['Unknown', 'Unknown-Device', '', null, undefined].includes(device.hostname)).length;
    const managedCount = devices.filter((device) => device.management_mode === 'managed').length;
    const highRiskCount = devices.filter((device) => ['HIGH', 'CRITICAL'].includes(device.risk_level)).length;
    const visibleDevices = devices.filter((device) => {
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

    const openDevice = (device) => {
        if (!device?.ip) {
            return;
        }
        navigate(`/user/${encodeURIComponent(device.ip)}`);
    };

    return (
        <div className="page-shell devices-shell">
            <div className="page-hero">
                <div>
                    <div className="page-eyebrow">Asset Visibility</div>
                    <h2>Network Devices</h2>
                    <p className="page-subtitle">
                        Managed endpoints come from agent registration. BYOD and observed hosts are enriched from traffic and local discovery.
                    </p>
                </div>
                <button className="action-btn" onClick={fetchDevices}>
                    <i className="ri-refresh-line"></i> Refresh
                </button>
            </div>

            {loading ? (
                <StatGridSkeleton count={3} />
            ) : (
                <div className="kpi-grid compact">
                    <KpiCard
                        icon="ri-radar-line"
                        label="Visible Devices"
                        value={devices.length}
                        meta={`${managedCount} managed / ${devices.length - managedCount} BYOD`}
                    />
                    <KpiCard
                        icon="ri-fingerprint-line"
                        label="Resolved Names"
                        value={namedDevices}
                        meta={`${devices.length - namedDevices} still unnamed`}
                        accent="#60a5fa"
                    />
                    <KpiCard
                        icon="ri-shield-flash-line"
                        label="High Risk"
                        value={highRiskCount}
                        meta="devices flagged high or critical"
                        tone={highRiskCount > 0 ? 'danger' : 'default'}
                        accent="#fb7185"
                    />
                </div>
            )}

            <div className="panel-controls">
                <div className="search-shell">
                    <i className="ri-search-line"></i>
                    <input
                        className="search-input"
                        type="search"
                        value={searchValue}
                        onChange={(event) => setSearchValue(event.target.value)}
                        placeholder="Search hostname, IP, MAC, vendor..."
                    />
                </div>
                <div className="filter-group">
                    <button
                        className={`filter-pill ${modeFilter === 'all' ? 'active' : ''}`}
                        onClick={() => setModeFilter('all')}
                    >
                        All
                    </button>
                    <button
                        className={`filter-pill ${modeFilter === 'managed' ? 'active' : ''}`}
                        onClick={() => setModeFilter('managed')}
                    >
                        Managed
                    </button>
                    <button
                        className={`filter-pill ${modeFilter === 'byod' ? 'active' : ''}`}
                        onClick={() => setModeFilter('byod')}
                    >
                        BYOD
                    </button>
                </div>
            </div>

            {loading ? (
                <TableSkeleton rows={6} />
            ) : (
                <DeviceTable devices={visibleDevices} onDeviceSelect={openDevice} />
            )}
        </div>
    );
};

export default DevicesPage;

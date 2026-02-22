import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { useNavigate, useLocation } from 'react-router-dom';

const Header = () => {
    const [user, setUser] = useState({ username: 'Guest', role: 'Viewer' });
    const [systemHealth, setSystemHealth] = useState({ status: 'Operational', cpu: 0, session: 'Active' });
    const [menuOpen, setMenuOpen] = useState(false);
    const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
    const menuRef = useRef(null);
    const navigate = useNavigate();
    const location = useLocation();

    // Mapping routes to titles
    const getTitle = () => {
        const path = location.pathname;
        if (path === '/') return 'Dashboard';
        if (path === '/devices') return 'Devices';
        if (path === '/threats') return 'Threats';
        if (path === '/activity') return 'Live Traffic';
        if (path === '/logs') return 'System Logs';
        if (path === '/vpn') return 'VPN & Threats';
        if (path === '/settings') return 'Settings';
        return 'NetVisor';
    };

    useEffect(() => {
        // Fetch User Info
        axios.get('/api/me').then(res => {
            if (res.data.authenticated) {
                setUser({ 
                    username: res.data.username || 'Admin', 
                    role: res.data.role || 'Administrator' 
                });
            }
        });

        // Theme Init
        document.documentElement.setAttribute('data-theme', theme);
        
        // Click setup
        const handleClickOutside = (event) => {
            if (menuRef.current && !menuRef.current.contains(event.target)) {
                setMenuOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);

        // System Health Polling
        const fetchHealth = async () => {
            try {
                const res = await axios.get('/api/system-health');
                setSystemHealth({
                    status: res.data.status,
                    cpu: res.data.cpu_usage,
                    session: 'Active' // Placeholder as per legacy behavior
                });
            } catch (err) {
                console.error("Health fetch failed", err);
            }
        };
        fetchHealth();
        const interval = setInterval(fetchHealth, 5000);

        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
            clearInterval(interval);
        };
    }, [theme]);

    const toggleTheme = () => {
        const newTheme = theme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
    };

    const handleLogout = async () => {
        await axios.get('/logout'); // Assuming backend handles session clear
        navigate('/login');
    };

    const getStatusColor = (status) => {
        if (status === 'Operational') return 'var(--success)';
        if (status === 'High Load') return '#f59e0b';
        return 'var(--danger)';
    };

    return (
        <div className="header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <h2 style={{ margin: 0 }}>{getTitle()}</h2>
                <div className="status-badge" style={{ background: 'rgba(6, 182, 212, 0.1)', color: 'var(--primary)', border: '1px solid rgba(6, 182, 212, 0.2)', fontSize: '0.7rem' }}>
                    <span className="terminal-cursor">SYS_MONITORING: ACTIVE</span>
                </div>
            </div>

            <div style={{ position: 'relative' }} ref={menuRef}>
                <div 
                    onClick={() => setMenuOpen(!menuOpen)}
                    style={{ 
                        display: 'flex', gap: '1rem', alignItems: 'center', 
                        cursor: 'pointer', userSelect: 'none' 
                    }}
                >
                    <button 
                        className="action-btn" 
                        onClick={(e) => { e.stopPropagation(); toggleTheme(); }}
                        title="Toggle Theme"
                        style={{ marginRight: '0.5rem' }}
                    >
                        <i className={theme === 'light' ? "ri-moon-line" : "ri-sun-line"}></i>
                    </button>

                    <div style={{ textAlign: 'right' }}>
                        <div style={{ fontWeight: 700, color: 'var(--primary)' }}>
                            {user.username}
                        </div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                            {user.role}
                        </div>
                    </div>

                    <div 
                        onClick={() => navigate('/user')}
                        style={{ 
                            width: '40px', height: '40px', background: 'var(--primary)', 
                            borderRadius: '50%', display: 'flex', alignItems: 'center', 
                            justifyContent: 'center', color: 'black', fontWeight: 'bold' 
                        }}
                    >
                        {user.username[0].toUpperCase()}
                    </div>
                    
                    <i className={`ri-arrow-down-s-line ${menuOpen ? 'rotate-180' : ''}`} style={{ transition: 'transform 0.3s' }}></i>
                </div>

                {/* Dropdown Menu */}
                <div className={`dropdown-menu ${menuOpen ? 'active' : ''}`}>
                    <div className="dropdown-header">
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>
                            Admin Info
                        </span>
                    </div>
                    
                    <div className="dropdown-item link" onClick={() => navigate('/user')}>
                        <i className="ri-shield-user-line"></i>
                        <div><strong>Role:</strong> {user.role}</div>
                    </div>
                    
                    <div className="dropdown-item">
                         <i className="ri-checkbox-circle-fill" style={{ color: getStatusColor(systemHealth.status) }}></i>
                         <div>
                            <strong>System:</strong> <span style={{ color: getStatusColor(systemHealth.status) }}>
                                {systemHealth.status} (CPU: {systemHealth.cpu}%)
                            </span>
                         </div>
                    </div>

                    <div className="dropdown-item">
                        <i className="ri-map-pin-line"></i>
                        <div><strong>IP:</strong> 127.0.0.1</div>
                    </div>

                    <div className="dropdown-item">
                        <i className="ri-time-line"></i>
                        <div>
                            <strong>Session:</strong> <span style={{ color: 'var(--success)' }}>{systemHealth.session}</span>
                        </div>
                    </div>

                    <div style={{ borderTop: '1px solid var(--glass-border)', margin: '0.5rem 0' }}></div>

                    <div className="dropdown-item link" onClick={() => navigate('/settings')} style={{ cursor: 'pointer' }}>
                        <i className="ri-settings-4-line"></i> Settings
                    </div>

                    <div className="dropdown-item link" onClick={handleLogout} style={{ color: 'var(--danger)', cursor: 'pointer' }}>
                        <i className="ri-logout-box-r-line"></i> Logout
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Header;

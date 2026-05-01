import { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { useVisibilityPolling } from '../../hooks/useVisibilityPolling';
import { systemService } from '../../services/api';
import Breadcrumbs from './Breadcrumbs';
import GlobalSearch from './GlobalSearch';
import StatusBadge from '../V2/StatusBadge';

const routeMeta = [
  { match: (path) => path === '/dashboard' || path === '/', title: 'Operational Overview', subtitle: 'Real-time posture and triage' },
  { match: (path) => path === '/devices', title: 'Device Inventory', subtitle: 'Managed and observed assets' },
  { match: (path) => path.startsWith('/apps'), title: 'Application Coverage', subtitle: 'Traffic grouped by product usage' },
  { match: (path) => path === '/threats', title: 'Threat Investigation', subtitle: 'Active high-risk detections' },
  { match: (path) => path === '/activity', title: 'Traffic Activity', subtitle: 'Live session visibility' },
  { match: (path) => path === '/logs', title: 'Flow Logs', subtitle: 'Search and export flow records' },
  { match: (path) => path === '/agents' || path.startsWith('/agents/'), title: 'Fleet Operations', subtitle: 'Agent health and device coverage' },
  { match: (path) => path === '/vpn', title: 'VPN Risk Feed', subtitle: 'Tunnel and proxy detections' },
  { match: (path) => path === '/settings', title: 'System Controls', subtitle: 'Runtime and maintenance controls' },
  { match: (path) => path === '/dpi', title: 'Web Inspection', subtitle: 'Global browser visibility' },
  { match: (path) => path === '/user', title: 'My Security Workspace', subtitle: 'Account posture and linked telemetry' },
  { match: (path) => path.startsWith('/user/'), title: 'Device Workspace', subtitle: 'Evidence-first device investigation' },
];

const Header = ({ onToggleAlerts, onToggleNav }) => {
  const { user, isAdmin, logout } = useAuth();
  const [systemHealth, setSystemHealth] = useState({
    status: 'Operational',
  });
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
  const menuRef = useRef(null);
  const navigate = useNavigate();
  const location = useLocation();

  const activeRoute = useMemo(
    () => routeMeta.find((entry) => entry.match(location.pathname)) || { title: 'NetVisor', subtitle: 'Security workspace' },
    [location.pathname],
  );

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await systemService.getHealth();
      setSystemHealth({
        status: res.data?.status === 'healthy' ? 'Operational' : 'Degraded',
      });
    } catch {
      setSystemHealth({
        status: 'Degraded',
      });
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  useVisibilityPolling(fetchHealth, 30000);

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    localStorage.setItem('theme', nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const displayUser = user || { username: 'Guest', role: 'viewer' };

  return (
    <header className="nv-topbar">
      <div className="nv-topbar__cluster">
        <button type="button" className="nv-button nv-button--secondary" onClick={onToggleNav}>
          <i className="ri-menu-line"></i>
        </button>
        <div className="nv-topbar__title">
          <Breadcrumbs />
          <strong>{activeRoute.title}</strong>
          <span>{activeRoute.subtitle}</span>
        </div>
      </div>

      <GlobalSearch />

      <div className="nv-topbar__cluster">
        <StatusBadge tone={systemHealth.status === 'Operational' ? 'success' : 'warning'} icon="ri-pulse-line">
          {systemHealth.status}
        </StatusBadge>
        <button type="button" className="nv-button nv-button--secondary" onClick={onToggleAlerts} title="Threat feed">
          <i className="ri-notification-3-line"></i>
        </button>
        <button type="button" className="nv-button nv-button--secondary" onClick={toggleTheme} title="Toggle theme">
          <i className={theme === 'light' ? 'ri-moon-line' : 'ri-sun-line'}></i>
        </button>

        <div style={{ position: 'relative' }} ref={menuRef}>
          <button type="button" className="nv-user-pill" onClick={() => setMenuOpen((current) => !current)}>
            <div className="nv-user-pill__avatar">{displayUser.username?.[0]?.toUpperCase() || 'U'}</div>
            <div className="nv-topbar__title" style={{ gap: '0.1rem', textAlign: 'left' }}>
              <strong>{displayUser.username}</strong>
              <span>{displayUser.role}</span>
            </div>
            <i className={`ri-arrow-down-s-line ${menuOpen ? 'rotate-180' : ''}`}></i>
          </button>

          {menuOpen ? (
            <div className="nv-menu">
              <div className="nv-menu__section">
                <div className="nv-menu__label">Session</div>
              </div>
              <button type="button" className="nv-menu__item" onClick={() => navigate('/user')}>
                <i className="ri-shield-user-line"></i>
                <span>Open personal workspace</span>
              </button>
              {isAdmin ? (
                <button type="button" className="nv-menu__item" onClick={() => navigate('/settings')}>
                  <i className="ri-settings-4-line"></i>
                  <span>Open system settings</span>
                </button>
              ) : null}
              <div className="nv-menu__section">
                <div className="nv-menu__label">Connection</div>
                <p>{window.location.hostname}</p>
              </div>
              <button type="button" className="nv-menu__item" onClick={handleLogout}>
                <i className="ri-logout-box-r-line"></i>
                <span>Logout</span>
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
};

export default Header;

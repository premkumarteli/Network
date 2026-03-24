import { NavLink } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

const Sidebar = ({ isCollapsed, toggleSidebar }) => {
  const { isAdmin } = useAuth();
  const links = isAdmin
    ? [
        { to: '/dashboard', icon: 'ri-dashboard-3-line', label: 'Dashboard' },
        { to: '/devices', icon: 'ri-macbook-line', label: 'Devices' },
        { to: '/dpi', icon: 'ri-eye-line', label: 'DPI Dashboard' },
        { to: '/apps', icon: 'ri-apps-2-line', label: 'Applications' },
        { to: '/threats', icon: 'ri-shield-flash-line', label: 'Threats' },
        { to: '/logs', icon: 'ri-radar-line', label: 'Agent Monitoring' },
        { to: '/vpn', icon: 'ri-shield-keyhole-line', label: 'VPN' },
      ]
    : [
        { to: '/user', icon: 'ri-shield-user-line', label: 'My Security' },
      ];

  return (
    <nav className={`sidebar ${isCollapsed ? 'collapsed' : ''}`} id="sidebar">
      <div className="sidebar-header">
        <div className="logo" style={{ color: 'var(--primary)' }}>
          <i className="ri-radar-line flicker-slow"></i>
          <span className="brand-name terminal-cursor">NetVisor</span>
        </div>
      </div>

      <div className="nav-links">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
          >
            <i className={link.icon}></i> <span>{link.label}</span>
          </NavLink>
        ))}
      </div>

      <button 
        className="sidebar-toggle-btn" 
        onClick={toggleSidebar}
        style={{
          marginTop: 'auto',
          background: 'transparent',
          border: '1px solid var(--glass-border)',
          color: 'var(--text-muted)',
          padding: '1rem',
          cursor: 'pointer',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          transition: 'all 0.3s ease'
        }}
      >
        <i className={isCollapsed ? "ri-arrow-right-s-line" : "ri-arrow-left-s-line"}></i>
        {!isCollapsed && <span style={{ marginLeft: '0.5rem' }}>Collapse</span>}
      </button>
    </nav>
  );
};

export default Sidebar;

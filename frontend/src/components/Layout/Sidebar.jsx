import { NavLink } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import StatusBadge from '../V2/StatusBadge';

const adminGroups = [
  {
    title: 'Overview',
    links: [
      { to: '/dashboard', icon: 'ri-dashboard-3-line', label: 'Dashboard', hint: 'Signal and posture' },
    ],
  },
  {
    title: 'Inventory',
    links: [
      { to: '/devices', icon: 'ri-macbook-line', label: 'Devices', hint: 'Managed and observed assets' },
      { to: '/apps', icon: 'ri-apps-2-line', label: 'Applications', hint: 'Session coverage by app' },
      { to: '/agents', icon: 'ri-radar-line', label: 'Fleet', hint: 'Agent heartbeat and health' },
    ],
  },
  {
    title: 'Investigation',
    links: [
      { to: '/dpi', icon: 'ri-navigation-line', label: 'Web Inspection', hint: 'Browser activity and evidence' },
      { to: '/threats', icon: 'ri-shield-flash-line', label: 'Threats', hint: 'High-risk detections' },
      { to: '/activity', icon: 'ri-pulse-line', label: 'Traffic', hint: 'Live session activity' },
    ],
  },
  {
    title: 'Operations',
    links: [
      { to: '/logs', icon: 'ri-file-list-3-line', label: 'Logs', hint: 'Flow records and exports' },
      { to: '/vpn', icon: 'ri-shield-keyhole-line', label: 'VPN', hint: 'Tunnel risk detections' },
      { to: '/settings', icon: 'ri-settings-4-line', label: 'Settings', hint: 'System controls' },
    ],
  },
];

const userGroups = [
  {
    title: 'Workspace',
    links: [
      { to: '/user', icon: 'ri-shield-user-line', label: 'My Security', hint: 'Account safety and linked device data' },
    ],
  },
];

const Sidebar = ({ isCollapsed, isMobileOpen, onCloseMobile }) => {
  const { isAdmin } = useAuth();
  const groups = isAdmin ? adminGroups : userGroups;

  return (
    <nav className={`nv-rail ${isMobileOpen ? 'is-open' : ''}`.trim()} id="sidebar">
      <div className="nv-rail__header">
        <div className="nv-rail__brand">
          <div className="nv-rail__brand-mark">
            <i className="ri-radar-line"></i>
          </div>
          {!isCollapsed ? (
            <div className="nv-rail__brand-copy">
              <span>NetVisor</span>
              <span>Cyber Security Workspace</span>
            </div>
          ) : null}
        </div>
        {!isCollapsed ? <StatusBadge tone="accent" icon="ri-pulse-fill">Analyst Console</StatusBadge> : null}
      </div>

      <div className="nv-rail__nav">
        {groups.map((group) => (
          <div key={group.title} className="nv-rail__group">
            {!isCollapsed ? <div className="nv-rail__group-title">{group.title}</div> : null}
            {group.links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                className={({ isActive }) => `nv-rail__link ${isActive ? 'is-active' : ''}`.trim()}
                onClick={() => {
                  if (window.innerWidth <= 980) {
                    onCloseMobile?.();
                  }
                }}
              >
                <span className="nv-rail__link-icon">
                  <i className={link.icon}></i>
                </span>
                {!isCollapsed ? (
                  <span className="nv-rail__link-copy">
                    <strong>{link.label}</strong>
                    <span>{link.hint}</span>
                  </span>
                ) : null}
              </NavLink>
            ))}
          </div>
        ))}
      </div>
    </nav>
  );
};

export default Sidebar;

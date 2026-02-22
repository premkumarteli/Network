import React from 'react';
import { NavLink } from 'react-router-dom';

const Sidebar = () => {
  return (
    <nav className="sidebar" id="sidebar">
      <div className="sidebar-header">
        <div className="logo" style={{ color: 'var(--primary)' }}>
          <i className="ri-radar-line flicker-slow"></i>
          <span className="brand-name terminal-cursor">NetVisor</span>
        </div>
      </div>

      <div className="nav-links">
        <NavLink 
          to="/" 
          className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
          end
        >
          <i className="ri-dashboard-3-line"></i> <span>Dashboard</span>
        </NavLink>
        <NavLink 
          to="/devices" 
          className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
        >
          <i className="ri-macbook-line"></i> <span>Devices</span>
        </NavLink>
        <NavLink 
          to="/activity" 
          className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
        >
          <i className="ri-pulse-line"></i> <span>Live Traffic</span>
        </NavLink>
        <NavLink 
          to="/threats" 
          className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
        >
          <i className="ri-shield-flash-line"></i> <span>Threats</span>
        </NavLink>
        <NavLink 
          to="/logs" 
          className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
        >
          <i className="ri-history-line"></i> <span>System Logs</span>
        </NavLink>
        <NavLink 
          to="/vpn" 
          className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
        >
          <i className="ri-shield-keyhole-line"></i> <span>VPN</span>
        </NavLink>
        <NavLink 
          to="/settings" 
          className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
        >
          <i className="ri-settings-4-line"></i> <span>Settings</span>
        </NavLink>
        <NavLink 
          to="/user" 
          className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
        >
          <i className="ri-user-settings-line"></i> <span>User Profile</span>
        </NavLink>
      </div>
    </nav>
  );
};

export default Sidebar;

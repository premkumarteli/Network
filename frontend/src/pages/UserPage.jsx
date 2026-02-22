import React, { useState, useEffect } from "react";
import axios from "axios";

const UserPage = () => {
  const [user, setUser] = useState({
    username: "...",
    role: "...",
    email: "...",
  });
  const [stats, setStats] = useState({
    lastLogin: "Recent",
    sessionTime: "0h 0m",
  });

  useEffect(() => {
    axios.get("/api/me").then((res) => {
      if (res.data.authenticated) {
        setUser({
          username: res.data.username,
          role: res.data.role,
          email: res.data.email || `${res.data.username}@netvisor.local`,
        });
      }
    });
  }, []);

  return (
    <div className="animate-fade" style={{ padding: "var(--app-padding)" }}>
      <div className="header-section" style={{ marginBottom: "2rem" }}>
        <h1 style={{ margin: 0 }}>User Profile</h1>
        <p style={{ color: "var(--text-muted)" }}>
          Manage your account and security settings.
        </p>
      </div>

      <div className="stats-grid">
        <div className="stat-card animate-slide-up">
          <div style={{ display: "flex", alignItems: "center", gap: "1.5rem" }}>
            <div
              style={{
                width: "80px",
                height: "80px",
                background: "var(--primary)",
                borderRadius: "50%",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "black",
                fontSize: "2rem",
                fontWeight: 800,
              }}
            >
              {user.username[0].toUpperCase()}
            </div>
            <div>
              <h2 style={{ margin: 0 }}>{user.username}</h2>
              <p
                style={{ color: "var(--primary)", margin: 0, fontWeight: 600 }}
              >
                {user.role}
              </p>
            </div>
          </div>
        </div>

        <div
          className="stat-card animate-slide-up"
          style={{ animationDelay: "0.1s" }}
        >
          <h3>
            <i className="ri-mail-line"></i> Email Address
          </h3>
          <div className="stat-value" style={{ fontSize: "1.2rem" }}>
            {user.email}
          </div>
        </div>

        <div
          className="stat-card animate-slide-up"
          style={{ animationDelay: "0.2s" }}
        >
          <h3>
            <i className="ri-shield-check-line"></i> Security Status
          </h3>
          <div
            className="stat-value"
            style={{ fontSize: "1.2rem", color: "var(--success)" }}
          >
            Protected
          </div>
        </div>
      </div>

      <div className="bento-grid" style={{ marginTop: "1.5rem" }}>
        <div
          className="chart-card animate-slide-up"
          style={{ gridColumn: "span 2", animationDelay: "0.3s" }}
        >
          <h3>Account Activity</h3>
          <div style={{ marginTop: "1rem" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                padding: "1rem 0",
                borderBottom: "1px solid var(--glass-border)",
              }}
            >
              <span style={{ color: "var(--text-muted)" }}>Last Login</span>
              <span className="mono">{stats.lastLogin}</span>
            </div>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                padding: "1rem 0",
                borderBottom: "1px solid var(--glass-border)",
              }}
            >
              <span style={{ color: "var(--text-muted)" }}>
                Session Duration
              </span>
              <span className="mono">{stats.sessionTime}</span>
            </div>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                padding: "1rem 0",
              }}
            >
              <span style={{ color: "var(--text-muted)" }}>
                Two-Factor Auth
              </span>
              <span style={{ color: "var(--warning)" }}>Disabled</span>
            </div>
          </div>
        </div>
      </div>

      <div
        style={{ marginTop: "2rem", display: "flex", gap: "1rem" }}
        className="animate-fade"
      >
        <button
          className="action-btn"
          style={{ background: "var(--primary)", color: "black" }}
        >
          Update Profile
        </button>
        <button className="action-btn">Change Password</button>
      </div>
    </div>
  );
};

export default UserPage;

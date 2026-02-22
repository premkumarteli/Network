import React, { useState } from "react";
import axios from "axios";
import { useNavigate, Link } from "react-router-dom";

const RegisterPage = () => {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    confirm_password: "",
  });
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");

    if (formData.password !== formData.confirm_password) {
      setError("Passwords do not match");
      return;
    }

    try {
      const res = await axios.post("/register", formData);
      if (res.data.status === "success") {
        navigate("/login");
      } else {
        setError(res.data.message || "Registration failed");
      }
    } catch (err) {
      setError(err.response?.data?.message || "Connection error");
    }
  };

  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "var(--bg-app)",
        color: "var(--text-main)",
      }}
    >
      <div className="glass-panel" style={{ width: "400px", padding: "2rem" }}>
        <h2
          style={{
            textAlign: "center",
            marginBottom: "1.5rem",
            color: "var(--primary)",
          }}
        >
          <i className="ri-user-add-line"></i> Create Account
        </h2>
        {error && (
          <div
            className="badge danger"
            style={{
              display: "block",
              textAlign: "center",
              marginBottom: "1rem",
            }}
          >
            {error}
          </div>
        )}
        <form onSubmit={handleRegister}>
          <div style={{ marginBottom: "1rem" }}>
            <label>Username</label>
            <input
              type="text"
              name="username"
              className="search-bar"
              style={{ width: "100%", marginTop: "0.5rem" }}
              value={formData.username}
              onChange={handleChange}
              required
            />
          </div>
          <div style={{ marginBottom: "1rem" }}>
            <label>Email</label>
            <input
              type="email"
              name="email"
              className="search-bar"
              style={{ width: "100%", marginTop: "0.5rem" }}
              value={formData.email}
              onChange={handleChange}
              required
            />
          </div>
          <div style={{ marginBottom: "1rem" }}>
            <label>Password</label>
            <input
              type="password"
              name="password"
              className="search-bar"
              style={{ width: "100%", marginTop: "0.5rem" }}
              value={formData.password}
              onChange={handleChange}
              required
            />
          </div>
          <div style={{ marginBottom: "1.5rem" }}>
            <label>Confirm Password</label>
            <input
              type="password"
              name="confirm_password"
              className="search-bar"
              style={{ width: "100%", marginTop: "0.5rem" }}
              value={formData.confirm_password}
              onChange={handleChange}
              required
            />
          </div>
          <button
            type="submit"
            className="action-btn"
            style={{ width: "100%", padding: "0.75rem" }}
          >
            Register
          </button>
          <div
            style={{
              textAlign: "center",
              marginTop: "1rem",
              fontSize: "0.9rem",
            }}
          >
            <Link
              to="/login"
              style={{ color: "var(--primary)", textDecoration: "none" }}
            >
              Back to Login
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
};

export default RegisterPage;

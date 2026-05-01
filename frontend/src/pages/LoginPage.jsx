import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { authService } from '../services/api';
import AuthSurface from '../components/V2/AuthSurface';

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { refreshUser } = useAuth();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await authService.login({ username, password });
      await refreshUser();
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.detail || 'Connection error');
    }
  };

  const aside = (
    <div className="nv-auth__points">
      <div className="nv-auth__point">
        <i className="ri-shield-keyhole-line"></i>
        <div>
          <strong>Cookie-based sessions</strong>
          <p>Browser auth stays in httpOnly cookies with CSRF protection on unsafe requests.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-radar-line"></i>
        <div>
          <strong>Signed endpoint traffic</strong>
          <p>Agents and gateways use signed transport so the control plane can trust the source.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-navigation-line"></i>
        <div>
          <strong>DPI stays managed</strong>
          <p>Inspection remains explicit opt-in on managed devices only.</p>
        </div>
      </div>
    </div>
  );

  return (
    <AuthSurface
      eyebrow="Secure access"
      title="NetVisor Login"
      description="Sign in to the operational workspace. The UI now uses one visual system for forms, cards, and tables, so the login screen matches the rest of the product."
      badge="Protected session"
      asideTitle="Why this workspace is different"
      asideCaption="Control plane"
      aside={aside}
      footer={(
        <>
          <span>Request access from an administrator if you do not have an account.</span>
          <Link className="nv-auth__link" to="/register">Create account</Link>
        </>
      )}
    >
      {error ? (
        <div className="nv-auth__error" role="alert">
          <i className="ri-error-warning-line"></i>
          <span>{error}</span>
        </div>
      ) : null}

      <form onSubmit={handleLogin} className="nv-auth__form">
        <label className="nv-auth__field">
          <span className="nv-auth__label">Username</span>
          <input
            type="text"
            className="nv-auth__input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
          />
        </label>

        <label className="nv-auth__field">
          <span className="nv-auth__label">Password</span>
          <input
            type="password"
            className="nv-auth__input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>

        <div className="nv-auth__footer">
          <button type="submit" className="nv-button nv-button--primary">
            <i className="ri-login-box-line"></i>
            Sign In
          </button>
          <span>Managed access only</span>
        </div>
      </form>
    </AuthSurface>
    );
};

export default LoginPage;

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authService } from "../services/api";
import AuthSurface from '../components/V2/AuthSurface';

const RegisterPage = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirm_password: '',
  });
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirm_password) {
      setError('Passwords do not match');
      return;
    }

    try {
      await authService.register(formData);
      navigate('/login');
    } catch (err) {
      setError(err.response?.data?.detail || err.response?.data?.message || err.message || 'Registration failed');
    }
  };

  const aside = (
    <div className="nv-auth__points">
      <div className="nv-auth__point">
        <i className="ri-user-3-line"></i>
        <div>
          <strong>One account, one role</strong>
          <p>Registration should match the workspace policy and the access level assigned by an administrator.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-lock-password-line"></i>
        <div>
          <strong>Use a strong password</strong>
          <p>Account access is protected by server-side session cookies and CSRF checks after login.</p>
        </div>
      </div>
      <div className="nv-auth__point">
        <i className="ri-shield-star-line"></i>
        <div>
          <strong>Operational review</strong>
          <p>Admin review is still expected for system-level, DPI, and fleet access.</p>
        </div>
      </div>
    </div>
  );

  return (
    <AuthSurface
      eyebrow="Account onboarding"
      title="Create account"
      description="Create a workspace account using the same card-based layout used across the rest of the product, so the onboarding screen no longer feels disconnected from the console."
      badge="Onboarding"
      asideTitle="Before you register"
      asideCaption="Access model"
      aside={aside}
      footer={(
        <>
          <span>Already have access?</span>
          <Link className="nv-auth__link" to="/login">Back to login</Link>
        </>
      )}
    >
      {error ? (
        <div className="nv-auth__error" role="alert">
          <i className="ri-error-warning-line"></i>
          <span>{error}</span>
        </div>
      ) : null}

      <form onSubmit={handleRegister} className="nv-auth__form">
        <label className="nv-auth__field">
          <span className="nv-auth__label">Username</span>
          <input
            type="text"
            name="username"
            className="nv-auth__input"
            value={formData.username}
            onChange={handleChange}
            autoComplete="username"
            required
          />
        </label>

        <label className="nv-auth__field">
          <span className="nv-auth__label">Email</span>
          <input
            type="email"
            name="email"
            className="nv-auth__input"
            value={formData.email}
            onChange={handleChange}
            autoComplete="email"
            required
          />
        </label>

        <label className="nv-auth__field">
          <span className="nv-auth__label">Password</span>
          <input
            type="password"
            name="password"
            className="nv-auth__input"
            value={formData.password}
            onChange={handleChange}
            autoComplete="new-password"
            required
          />
        </label>

        <label className="nv-auth__field">
          <span className="nv-auth__label">Confirm password</span>
          <input
            type="password"
            name="confirm_password"
            className="nv-auth__input"
            value={formData.confirm_password}
            onChange={handleChange}
            autoComplete="new-password"
            required
          />
        </label>

        <div className="nv-auth__footer">
          <button type="submit" className="nv-button nv-button--primary">
            <i className="ri-user-add-line"></i>
            Register
          </button>
          <Link className="nv-auth__link" to="/login">Back to login</Link>
        </div>
      </form>
    </AuthSurface>
  );
};

export default RegisterPage;

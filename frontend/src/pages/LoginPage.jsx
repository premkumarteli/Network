import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const LoginPage = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        try {
            const res = await axios.post('/login', { username, password });
            if (res.data.status === 'success') {
                navigate('/');
            } else {
                setError(res.data.message || 'Login failed');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Connection error');
        }
    };

    return (
        <div style={{ 
            height: '100vh', 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center', 
            background: 'var(--bg-app)',
            color: 'var(--text-main)'
        }}>
            <div className="glass-panel" style={{ width: '400px', padding: '2rem' }}>
                <h2 style={{ textAlign: 'center', marginBottom: '1.5rem', color: 'var(--primary)' }}>
                    <i className="ri-shield-keyhole-line"></i> NetVisor Login
                </h2>
                {error && <div className="badge danger" style={{ display: 'block', textAlign: 'center', marginBottom: '1rem' }}>{error}</div>}
                <form onSubmit={handleLogin}>
                    <div style={{ marginBottom: '1rem' }}>
                        <label>Username</label>
                        <input 
                            type="text" 
                            className="search-bar" 
                            style={{ width: '100%', marginTop: '0.5rem' }} 
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                        />
                    </div>
                    <div style={{ marginBottom: '1.5rem' }}>
                        <label>Password</label>
                        <input 
                            type="password" 
                            className="search-bar" 
                            style={{ width: '100%', marginTop: '0.5rem' }} 
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                        />
                    </div>
                    <button type="submit" className="action-btn" style={{ width: '100%', padding: '0.75rem' }}>
                        Sign In
                    </button>
                    <div style={{ textAlign: 'center', marginTop: '1rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        Request access from administrator
                    </div>
                </form>
            </div>
        </div>
    );
};

export default LoginPage;

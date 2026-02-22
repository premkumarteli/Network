import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import axios from 'axios';
import MainLayout from './components/Layout/MainLayout';
import Sidebar from './components/Layout/Sidebar';
import Background from './components/Layout/Background';
import DashboardPage from './pages/DashboardPage';
import DevicesPage from './pages/DevicesPage';
import ThreatsPage from './pages/ThreatsPage';
import ActivityPage from './pages/ActivityPage';
import SystemLogsPage from './pages/SystemLogsPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import VPNPage from './pages/VPNPage';
import SettingsPage from './pages/SettingsPage';
import UserPage from './pages/UserPage';
import './index.css';

import { authService } from './services/api';

const ProtectedRoute = () => {
    const [auth, setAuth] = useState(null);

    useEffect(() => {
        authService.getCurrentUser()
            .then(res => setAuth(res.data.authenticated))
            .catch(() => setAuth(false));
    }, []);

    if (auth === null) return <div className="loading-state">Authenticating...</div>;
    return auth ? <Outlet /> : <Navigate to="/login" />;
};

function App() {
  return (
    <BrowserRouter>
         <Background />
         <Routes>
                <Route path="/login" element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />
                
                <Route element={<ProtectedRoute />}>
                    <Route element={<MainLayout />}>
                        <Route path="/" element={<DashboardPage />} />
                        <Route path="/devices" element={<DevicesPage />} />
                        <Route path="/threats" element={<ThreatsPage />} />
                        <Route path="/activity" element={<ActivityPage />} />
                        <Route path="/logs" element={<SystemLogsPage />} />
                        <Route path="/vpn" element={<VPNPage />} />
                        <Route path="/settings" element={<SettingsPage />} />
                        <Route path="/user" element={<UserPage />} />
                    </Route>
                </Route>
            </Routes>
    </BrowserRouter>
  );
}

export default App;

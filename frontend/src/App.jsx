import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import MainLayout from './components/Layout/MainLayout';
import Background from './components/Layout/Background';
import PageTransition from './components/UI/PageTransition';
import { AuthProvider } from './context/AuthContext';
import { useAuth } from './hooks/useAuth';
import './index.css';

import { ADMIN_ROLES, isAdminRole } from './utils/roles';

const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const DevicesPage = lazy(() => import('./pages/DevicesPage'));
const ThreatsPage = lazy(() => import('./pages/ThreatsPage'));
const ActivityPage = lazy(() => import('./pages/ActivityPage'));
const ApplicationsPage = lazy(() => import('./pages/ApplicationsPage'));
const ApplicationDevicesPage = lazy(() => import('./pages/ApplicationDevicesPage'));
const AgentDetailsPage = lazy(() => import('./pages/AgentDetailsPage'));
const SystemLogsPage = lazy(() => import('./pages/SystemLogsPage'));
const LoginPage = lazy(() => import('./pages/LoginPage'));
const RegisterPage = lazy(() => import('./pages/RegisterPage'));
const VPNPage = lazy(() => import('./pages/VPNPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const UserPage = lazy(() => import('./pages/UserPage'));

const ProtectedRoute = ({ allowedRoles = null }) => {
    const { user, loading } = useAuth();

    if (loading) return <div className="loading-state">Authenticating...</div>;
    if (!user) return <Navigate to="/login" replace />;
    if (allowedRoles && !allowedRoles.includes(user.role)) {
        return <Navigate to={isAdminRole(user.role) ? "/dashboard" : "/user"} replace />;
    }
    return <Outlet />;
};

const HomeRedirect = () => {
    const { user } = useAuth();
    return <Navigate to={isAdminRole(user?.role) ? "/dashboard" : "/user"} replace />;
};

const RouteLoader = () => (
  <div className="loading-state route-loading-state">
    Loading workspace...
  </div>
);

const pageElement = (Component) => (
  <PageTransition>
    <Suspense fallback={<RouteLoader />}>
      <Component />
    </Suspense>
  </PageTransition>
);

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Background />
        <Routes>
          <Route path="/login" element={pageElement(LoginPage)} />
          <Route path="/register" element={pageElement(RegisterPage)} />

          <Route element={<ProtectedRoute />}>
            <Route element={<MainLayout />}>
              <Route path="/" element={<HomeRedirect />} />
              <Route path="/user" element={pageElement(UserPage)} />

              <Route element={<ProtectedRoute allowedRoles={ADMIN_ROLES} />}>
                <Route path="/dashboard" element={pageElement(DashboardPage)} />
                <Route path="/devices" element={pageElement(DevicesPage)} />
                <Route path="/user/:deviceIp" element={pageElement(UserPage)} />
                <Route path="/dpi" element={pageElement(lazy(() => import('./pages/DpiDashboard.jsx')))} />
                <Route path="/apps" element={pageElement(ApplicationsPage)} />
                <Route path="/apps/:appName" element={pageElement(ApplicationDevicesPage)} />
                <Route path="/threats" element={pageElement(ThreatsPage)} />
                <Route path="/activity" element={pageElement(ActivityPage)} />
                <Route path="/logs" element={pageElement(SystemLogsPage)} />
                <Route path="/agents/:agentId" element={pageElement(AgentDetailsPage)} />
                <Route path="/vpn" element={pageElement(VPNPage)} />
                <Route path="/settings" element={pageElement(SettingsPage)} />
              </Route>
            </Route>
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;

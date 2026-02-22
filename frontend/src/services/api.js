import axios from 'axios';

// Use environment variables or fallback to development defaults
const API_BASE_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

export const authService = {
    login: (credentials) => api.post('/login', credentials),
    register: (data) => api.post('/register', data),
    logout: () => api.get('/logout'),
    getCurrentUser: () => api.get('/api/me'),
};

export const systemService = {
    getStats: () => api.get('/api/stats'),
    getActivity: (severity) => api.get('/api/activity', { params: { severity } }),
    getDevices: () => api.get('/api/devices'),
    getLogs: () => api.get('/api/logs'),
    getHealth: () => api.get('/api/system-health'),
};

export const adminService = {
    getAdminStats: () => api.get('/api/admin/stats'),
    toggleHotspot: (action) => api.post('/api/admin/hotspot', { action }),
    toggleMonitoring: (active) => api.post('/api/settings/system', { active }),
    toggleMaintenance: (active) => api.post('/api/settings/maintenance', { active }),
    resetDatabase: () => api.post('/api/admin/reset_db'),
};

export default api;

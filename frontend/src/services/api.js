import axios from "axios";

// Fast API backend runs on port 8000 by default and base path is /api/v1
const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Add a request interceptor to attach the JWT token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authService = {
  login: (credentials) => {
    // FastAPI OAuth2PasswordRequestForm requires x-www-form-urlencoded
    const formData = new URLSearchParams();
    formData.append("username", credentials.username || credentials.email);
    formData.append("password", credentials.password);
    return api.post("/auth/login", formData, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  },
  register: (data) => api.post("/auth/register", data),
  logout: () => {
    localStorage.removeItem("access_token");
    return Promise.resolve();
  },
  // We don't have a /me endpoint yet in the new backend, but decoding the JWT token on the frontend works for now.
  // We will add it later if needed. For now just verify if token exists.
  getCurrentUser: () => {
    const token = localStorage.getItem("access_token");
    if (!token) return Promise.reject("No token");
    // Decode logic can be added later, for now just assuming authenticated if token exists
    return Promise.resolve({
      data: { authenticated: true, username: "Admin" },
    });
  },
};

export const systemService = {
  // These need to be mapped to the intelligence/devices routers
  getHealth: () => api.get("/health/status"),
  getDevices: () => api.get("/devices/"),
  getAlerts: () => api.get("/alerts/"),
  getRiskRanking: () => api.get("/alerts/ranking"),
  // Stats and Activity are placeholders for now until we build the specific aggregation endpoints
  getStats: () =>
    Promise.resolve({
      data: { active_devices: 0, high_risk: 0, flows_24h: 0, bandwidth: "0" },
    }),
  getActivity: () => Promise.resolve({ data: [] }),
};

export default api;

import axios from "axios";
import { getApiBaseUrl } from "../config/runtime";

const API_BASE_URL = getApiBaseUrl();

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  xsrfCookieName: "XSRF-TOKEN",
  xsrfHeaderName: "X-XSRF-TOKEN",
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && (error.response.status === 401 || error.response.status === 403)) {
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

function parseTimestamp(value) {
  if (!value) {
    return null;
  }

  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed;
  }
  return null;
}

function parseByteValue(value) {
  if (typeof value === "number") {
    return value;
  }
  if (typeof value !== "string") {
    return 0;
  }

  const trimmed = value.trim();
  const match = trimmed.match(/^([\d.]+)\s*(B|KB|MB|GB)?$/i);
  if (!match) {
    const fallback = Number.parseFloat(trimmed);
    return Number.isFinite(fallback) ? fallback : 0;
  }

  const amount = Number.parseFloat(match[1]);
  const unit = (match[2] || "B").toUpperCase();
  const scale = {
    B: 1,
    KB: 1024,
    MB: 1024 * 1024,
    GB: 1024 * 1024 * 1024,
  };
  return Math.round(amount * (scale[unit] || 1));
}

function formatByteValue(value) {
  const bytes = Math.max(Number(value) || 0, 0);
  if (bytes >= 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${Math.round(bytes)} B`;
}

function formatRuntime(seconds) {
  const normalized = Math.max(Math.round(Number(seconds) || 0), 0);
  const hours = Math.floor(normalized / 3600);
  const minutes = Math.floor((normalized % 3600) / 60);
  const remainingSeconds = normalized % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  return `${remainingSeconds}s`;
}

export const authService = {
  login: (credentials) => {
    const formData = new URLSearchParams();
    formData.append("username", credentials.username || credentials.email);
    formData.append("password", credentials.password);
    return api.post("/auth/login", formData, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  },
  register: (data) => api.post("/auth/register", data),
  logout: () => api.post("/auth/logout").catch(() => null),
  getCurrentUser: () => api.get("/auth/me"),
};

export const systemService = {
  getHealth: () => api.get("/health/status"),
  getDevices: () => api.get("/devices/"),
  getAlerts: (params = {}) => api.get("/alerts/", { params }),
  getRiskRanking: () => api.get("/alerts/ranking"),
  getStats: () => api.get("/dashboard/overview"),
  getActivity: (limit = 50) =>
    api.get("/dashboard/activity", { params: { limit } }),
  getTrafficHistory: (hours = 24) =>
    api.get("/dashboard/traffic-history", { params: { hours } }),
  getDeviceStats: (limit = 5) =>
    api.get("/dashboard/device-stats", { params: { limit } }),
  getGlobalWebActivity: (limit = 15) =>
    api.get("/web/activity", { params: { limit } }),
  getGlobalWebEvidenceGroups: (limit = 15) =>
    api.get("/web/activity/groups", { params: { limit } }),
  getAppsSummary: () => api.get("/apps/summary"),
  getDpiGlobalStatus: () => api.get("/dpi/status"),
  getAppDevices: (appName) => api.get(`/apps/${encodeURIComponent(appName)}/devices`),
  getAppDpiEvents: (appName) => api.get(`/dpi/apps/${encodeURIComponent(appName)}`),
  getAnalyticsOverview: (hours = 24, limit = 8) =>
    api.get("/analytics/overview", { params: { hours, limit } }),
  exportAnalyticsReport: (kind, params = {}, format = "csv") =>
    api.get("/analytics/export", {
      params: { kind, format, ...params },
      responseType: "blob",
    }),
  getFlowLogs: (params = {}) => api.get("/logs/flows", { params }),
  getFlowStats: () => api.get("/logs/stats"),
  getDeviceWebActivity: (deviceIp) => api.get(`/web/devices/${encodeURIComponent(deviceIp)}/activity`),
  getDeviceWebEvidenceGroups: (deviceIp) =>
    api.get(`/web/devices/${encodeURIComponent(deviceIp)}/activity/groups`),
  getDeviceInspectionStatus: (deviceIp) => api.get(`/web/devices/${encodeURIComponent(deviceIp)}/status`),
  updateInspectionPolicy: (agentId, payload) =>
    api.post(`/web/policies/${encodeURIComponent(agentId)}`, payload),
  getDeviceProfile: async (deviceIp) => {
    const [devicesRes, activityRes, webActivityRes, webEvidenceGroupsRes, inspectionStatusRes] = await Promise.allSettled([
      api.get("/devices/"),
      api.get("/dashboard/activity", { params: { limit: 250 } }),
      api.get(`/web/devices/${encodeURIComponent(deviceIp)}/activity`),
      api.get(`/web/devices/${encodeURIComponent(deviceIp)}/activity/groups`),
      api.get(`/web/devices/${encodeURIComponent(deviceIp)}/status`),
    ]);

    const devicesData = devicesRes.status === 'fulfilled' ? devicesRes.value.data || [] : [];
    const activityData = activityRes.status === 'fulfilled' ? activityRes.value.data || [] : [];
    const webActivityData = webActivityRes.status === 'fulfilled' ? webActivityRes.value.data?.activity || [] : [];
    const webEvidenceGroupsData = webEvidenceGroupsRes.status === 'fulfilled' ? webEvidenceGroupsRes.value.data?.activity || [] : [];
    const inspectionStatusData = inspectionStatusRes.status === 'fulfilled' ? inspectionStatusRes.value.data || null : null;

    const device = devicesData.find((entry) => entry.ip === deviceIp) || null;
    const scopedEvents = activityData.filter(
      (entry) => entry.src_ip === deviceIp || entry.dst_ip === deviceIp,
    );

    const sortedEvents = scopedEvents
      .map((entry) => ({
        ...entry,
        parsedTimestamp: parseTimestamp(entry.timestamp || entry.last_seen || entry.time_str || entry.time),
        parsedBytes: parseByteValue(entry.size ?? entry.byte_count ?? 0),
      }))
      .sort((a, b) => {
        const left = a.parsedTimestamp?.getTime() || 0;
        const right = b.parsedTimestamp?.getTime() || 0;
        return right - left;
      });

    const applicationMap = new Map();
    let earliest = null;
    let latest = null;
    let totalBytes = 0;

    sortedEvents.forEach((entry) => {
      const key = entry.application || "Other";
      const current = applicationMap.get(key) || {
        application: key,
        bandwidth_bytes: 0,
        event_count: 0,
        last_seen: entry.timestamp || entry.last_seen || entry.time_str || entry.time || "",
      };
      current.bandwidth_bytes += entry.parsedBytes;
      current.event_count += 1;
      if (entry.parsedTimestamp) {
        if (!earliest || entry.parsedTimestamp < earliest) {
          earliest = entry.parsedTimestamp;
        }
        if (!latest || entry.parsedTimestamp > latest) {
          latest = entry.parsedTimestamp;
          current.last_seen = entry.timestamp || entry.last_seen || entry.time_str || entry.time || "";
        }
      }
      applicationMap.set(key, current);
      totalBytes += entry.parsedBytes;
    });

    const runtimeSeconds =
      earliest && latest ? Math.max(Math.round((latest.getTime() - earliest.getTime()) / 1000), 0) : 0;

    const applications = Array.from(applicationMap.values())
      .map((entry) => ({
        ...entry,
        bandwidth: formatByteValue(entry.bandwidth_bytes),
      }))
      .sort((a, b) => b.bandwidth_bytes - a.bandwidth_bytes);

    const webActivity = webActivityData.map((entry) => ({
      ...entry,
      request_bytes_formatted: formatByteValue(entry.request_bytes),
      response_bytes_formatted: formatByteValue(entry.response_bytes),
      event_count: Number(entry.event_count) || 1,
      confidence_score: Number(entry.confidence_score) || 0,
      risk_level: entry.risk_level || 'safe',
    }));

    const webEvidenceGroups = webEvidenceGroupsData.map((entry) => ({
      ...entry,
      request_bytes_formatted: formatByteValue(entry.request_bytes),
      response_bytes_formatted: formatByteValue(entry.response_bytes),
      event_count: Number(entry.event_count) || 1,
      confidence_score: Number(entry.confidence_score) || 0,
      risk_level: entry.risk_level || 'safe',
      page_urls: Array.isArray(entry.page_urls) ? entry.page_urls : [],
      page_titles: Array.isArray(entry.page_titles) ? entry.page_titles : [],
      content_ids: Array.isArray(entry.content_ids) ? entry.content_ids : [],
      search_queries: Array.isArray(entry.search_queries) ? entry.search_queries : [],
    }));

    return {
      data: {
        device_ip: deviceIp,
        hostname: device?.hostname || "Unknown Device",
        status: device?.status || "Offline",
        management_mode: device?.management_mode || "byod",
        risk_level: device?.risk_level || "LOW",
        risk_score: device?.risk_score || 0,
        last_seen: device?.last_seen || sortedEvents[0]?.timestamp || sortedEvents[0]?.last_seen || "Unknown",
        bandwidth_bytes: totalBytes,
        bandwidth: formatByteValue(totalBytes),
        runtime_seconds: runtimeSeconds,
        runtime: formatRuntime(runtimeSeconds),
        applications,
        recent_events: sortedEvents.slice(0, 8),
        web_activity: webActivity,
        web_evidence_groups: webEvidenceGroups,
        inspection_status: inspectionStatusData,
        device,
      },
    };
  },
  getAdminStats: () => api.get("/system/admin-stats"),
  getSystemStatus: () => api.get("/system/status"),
  getSystemLogs: () => api.get("/system/logs"),
  setMaintenanceMode: (active) =>
    api.post("/system/settings/maintenance", { active }),
  setMonitoring: (active) =>
    api.post("/system/settings/monitoring", { active }),
  triggerScan: () => api.post("/system/actions/scan"),
  resetDatabase: () => api.post("/system/reset-data"),
  getVPNAlerts: (params = {}) =>
    api.get("/alerts/", { params }).then((res) => {
      const vpn = (res.data || []).filter((a) => {
        const breakdown = a.breakdown || {};
        const reasons = breakdown.reasons || [];
        return (
          (breakdown.vpn_score || 0) > 0.3 ||
          reasons.includes("Possible VPN/Proxy Usage")
        );
      });
      return { data: vpn };
    }),
  getUserSummary: (role) => {
    if (!["org_admin", "super_admin"].includes(role)) {
      return Promise.resolve({
        data: {
          safety_score: null,
          recent_activity: [],
          transparency_log: [],
          scoped: false,
        },
      });
    }

    return api.get("/dashboard/activity", { params: { limit: 20 } }).then((res) => {
      const recent = res.data || [];
      const severityWeights = { LOW: 5, MEDIUM: 15, HIGH: 30, CRITICAL: 50 };
      const totalRisk = recent.reduce(
        (sum, item) => sum + (severityWeights[item.severity] || 0),
        0
      );
      return {
        data: {
          safety_score: Math.max(0, 100 - totalRisk),
          recent_activity: recent.slice(0, 5),
          scoped: true,
          transparency_log: recent.map((item) => ({
            src_ip: item.src_ip,
            dst_ip: item.dst_ip,
            domain: item.domain,
            timestamp: item.timestamp,
          })),
        },
      };
    });
  },
};

export const agentService = {
  getAgents: () => api.get("/agents/"),
  getAgentDetails: (agentId) => api.get(`/agents/${encodeURIComponent(agentId)}`),
  getEnrollmentRequests: () => api.get("/agents/enrollment-requests"),
  approveEnrollmentRequest: (requestId, reviewReason) =>
    api.post(`/agents/enrollment-requests/${encodeURIComponent(requestId)}/approve`, {
      review_reason: reviewReason,
    }),
  rejectEnrollmentRequest: (requestId, reviewReason) =>
    api.post(`/agents/enrollment-requests/${encodeURIComponent(requestId)}/reject`, {
      review_reason: reviewReason,
    }),
  revokeAgent: (agentId, reviewReason) =>
    api.post(`/agents/${encodeURIComponent(agentId)}/revoke`, {
      review_reason: reviewReason,
    }),
};

export default api;

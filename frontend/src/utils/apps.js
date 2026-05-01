const GENERIC_TRANSPORT_APPLICATIONS = new Set([
  'ARP',
  'DHCP',
  'DNS',
  'HTTP',
  'HTTPS',
  'ICMP',
  'ICMPV6',
  'LLMNR',
  'MDNS',
  'NBDS',
  'NBNS',
  'NTP',
  'QUIC',
  'SSDP',
  'TCP',
  'TLS',
  'UDP',
]);

const NETWORK_SERVICE_APPLICATIONS = new Set([
  ...GENERIC_TRANSPORT_APPLICATIONS,
  'OTHER',
  'UNKNOWN',
]);

const NETWORK_SERVICE_VISUAL = {
  icon: 'ri-radar-line',
  accent: '#38bdf8',
  background: 'rgba(56, 189, 248, 0.14)',
  label: 'SV',
};

const APP_VISUALS = {
  Grammarly: {
    icon: 'ri-edit-line',
    accent: '#22c55e',
    background: 'rgba(34, 197, 94, 0.14)',
    label: 'GR',
  },
  'Azure CloudApp': {
    icon: 'ri-cloud-line',
    accent: '#38bdf8',
    background: 'rgba(56, 189, 248, 0.14)',
    label: 'AZ',
  },
  YouTube: {
    icon: "ri-youtube-fill",
    accent: "#ff3b30",
    background: "rgba(255, 59, 48, 0.14)",
    label: "YT",
  },
  Instagram: {
    icon: "ri-instagram-fill",
    accent: "#ff7a59",
    background: "rgba(255, 122, 89, 0.14)",
    label: "IG",
  },
  Facebook: {
    icon: "ri-facebook-circle-fill",
    accent: "#1877f2",
    background: "rgba(24, 119, 242, 0.14)",
    label: "FB",
  },
  WhatsApp: {
    icon: "ri-whatsapp-fill",
    accent: "#25d366",
    background: "rgba(37, 211, 102, 0.14)",
    label: "WA",
  },
  ChatGPT: {
    icon: "ri-robot-2-fill",
    accent: "#10a37f",
    background: "rgba(16, 163, 127, 0.16)",
    label: "AI",
  },
  Google: {
    icon: "ri-google-fill",
    accent: "#4285f4",
    background: "rgba(66, 133, 244, 0.14)",
    label: "G",
  },
  'Google Services': {
    icon: "ri-google-fill",
    accent: "#34d399",
    background: "rgba(52, 211, 153, 0.14)",
    label: "GS",
  },
  Microsoft: {
    icon: "ri-windows-fill",
    accent: "#5e5ce6",
    background: "rgba(94, 92, 230, 0.14)",
    label: "MS",
  },
  'Amazon CloudFront': {
    icon: 'ri-cloud-line',
    accent: '#f59e0b',
    background: 'rgba(245, 158, 11, 0.14)',
    label: 'CF',
  },
  'App Insights': {
    icon: 'ri-line-chart-line',
    accent: '#f97316',
    background: 'rgba(249, 115, 22, 0.14)',
    label: 'AI',
  },
  'Visual Studio Code': {
    icon: 'ri-code-s-line',
    accent: '#3b82f6',
    background: 'rgba(59, 130, 246, 0.14)',
    label: 'VS',
  },
  Windows: {
    icon: 'ri-windows-fill',
    accent: '#60a5fa',
    background: 'rgba(96, 165, 250, 0.14)',
    label: 'WN',
  },
  'Windows Activity': {
    icon: 'ri-windows-fill',
    accent: '#60a5fa',
    background: 'rgba(96, 165, 250, 0.14)',
    label: 'WA',
  },
  MSN: {
    icon: 'ri-newspaper-line',
    accent: '#0ea5e9',
    background: 'rgba(14, 165, 233, 0.14)',
    label: 'MS',
  },
  GitHub: {
    icon: "ri-github-fill",
    accent: "#94a3b8",
    background: "rgba(148, 163, 184, 0.14)",
    label: "GH",
  },
  Perplexity: {
    icon: "ri-bubble-chart-fill",
    accent: "#22c55e",
    background: "rgba(34, 197, 94, 0.14)",
    label: "PX",
  },
  Other: {
    icon: "ri-global-line",
    accent: "#00f5ff",
    background: "rgba(0, 245, 255, 0.12)",
    label: "OT",
  },
};

function normalizeApplicationName(appName) {
  return String(appName || '').trim().toUpperCase();
}

export function isGenericTransportApplication(appName) {
  return GENERIC_TRANSPORT_APPLICATIONS.has(normalizeApplicationName(appName));
}

export function isNetworkServiceApplication(appName) {
  return NETWORK_SERVICE_APPLICATIONS.has(normalizeApplicationName(appName));
}

export function getApplicationKind(appName) {
  return isNetworkServiceApplication(appName) ? 'network-service' : 'product';
}

export function getApplicationVisual(appName) {
  if (isNetworkServiceApplication(appName)) {
    return NETWORK_SERVICE_VISUAL;
  }
  return APP_VISUALS[appName] || APP_VISUALS.Other;
}

export function formatRuntime(totalSeconds) {
  const seconds = Math.max(Math.trunc(Number(totalSeconds) || 0), 0);
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  return `${remainingSeconds}s`;
}

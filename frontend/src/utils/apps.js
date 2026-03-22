const APP_VISUALS = {
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
  Microsoft: {
    icon: "ri-windows-fill",
    accent: "#5e5ce6",
    background: "rgba(94, 92, 230, 0.14)",
    label: "MS",
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

export function getApplicationVisual(appName) {
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

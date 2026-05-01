function trimTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

export function getApiBaseUrl() {
  const configured = trimTrailingSlash(import.meta.env.VITE_API_URL);
  if (configured) {
    return configured;
  }
  return "/api/v1";
}

export function getSocketBaseUrl() {
  const configured = trimTrailingSlash(import.meta.env.VITE_WS_URL);
  if (configured) {
    return configured;
  }
  return "/";
}

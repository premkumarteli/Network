export const formatByteCount = (value) => {
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
};

export const formatPercent = (value) => `${Math.round(Number(value) || 0)}%`;

export const getRiskTone = (riskLevel) => {
  const normalized = String(riskLevel || 'low').toLowerCase();
  if (normalized === 'critical' || normalized === 'high' || normalized === 'red') {
    return 'danger';
  }
  if (normalized === 'medium' || normalized === 'warning' || normalized === 'yellow') {
    return 'warning';
  }
  return 'success';
};

export const getStatusTone = (status) => {
  const normalized = String(status || 'unknown').toLowerCase();
  if (
    normalized === 'online' ||
    normalized === 'running' ||
    normalized === 'enabled' ||
    normalized === 'installed' ||
    normalized === 'healthy' ||
    normalized === 'operational' ||
    normalized === 'approved'
  ) {
    return 'success';
  }
  if (
    normalized === 'idle' ||
    normalized === 'degraded' ||
    normalized === 'warning' ||
    normalized === 'pending' ||
    normalized === 'pending_review' ||
    normalized === 'queued'
  ) {
    return 'warning';
  }
  if (normalized === 'rejected' || normalized === 'revoked' || normalized === 'expired' || normalized === 'disabled' || normalized === 'offline' || normalized === 'failed') {
    return 'danger';
  }
  return 'danger';
};

export const formatBrowserLabel = (browserName, processName) => {
  const browser = String(browserName || '').trim();
  if (browser) {
    if (browser.toLowerCase().includes('edge')) return 'Edge';
    if (browser.toLowerCase().includes('chrome')) return 'Chrome';
    if (browser.toLowerCase().includes('firefox')) return 'Firefox';
    if (browser.toLowerCase().includes('safari') && !browser.toLowerCase().includes('chrome')) return 'Safari';
    return browser;
  }
  const process = String(processName || '').toLowerCase();
  if (process.includes('msedge')) return 'Edge';
  if (process.includes('chrome')) return 'Chrome';
  if (process.includes('firefox')) return 'Firefox';
  if (process.includes('safari')) return 'Safari';
  if (process.includes('python')) return 'Python';
  return 'Browser';
};

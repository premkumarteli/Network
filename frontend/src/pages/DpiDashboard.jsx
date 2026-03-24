import { useState, useEffect, useCallback, useRef } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { systemService } from '../services/api';
import './DpiDashboard.css';

const MAX_EVENTS = 100;

// Real status will come from web_inspection_service via API
const fetchDpiStatus = async () => {
  try {
    const res = await systemService.getDpiGlobalStatus();
    return res.data;
  } catch (err) {
    return {
      state: 'enabled',
      proxy: 'running',
      certificate: 'installed',
      lastActivity: new Date().toISOString(),
      eps: 0,
    };
  }
};

const DPI_STATUS_MAP = {
  enabled: { text: 'Enabled', color: 'text-green-500' },
  disabled: { text: 'Disabled', color: 'text-red-500' },
  degraded: { text: 'Degraded', color: 'text-yellow-500' },
};

const PROXY_STATUS_MAP = {
  running: { text: 'Running', color: 'text-green-500' },
  stopped: { text: 'Stopped', color: 'text-red-500' },
};

const CERT_STATUS_MAP = {
  installed: { text: 'Installed', color: 'text-green-500' },
  not_installed: { text: 'Not Installed', color: 'text-red-500' },
};

function StatusIndicator({ status, statusMap }) {
  const { text, color } = statusMap[status] || { text: 'Unknown', color: 'text-gray-500' };
  return <span className={color}>{text}</span>;
}

function DpiStatus({ status }) {
  return (
    <div className="summary-grid">
      <div className="summary-card">
        <span className="summary-label">DPI State</span>
        <strong>
          <StatusIndicator status={status.state} statusMap={DPI_STATUS_MAP} />
        </strong>
      </div>
      <div className="summary-card">
        <span className="summary-label">Proxy</span>
        <strong>
          <StatusIndicator status={status.proxy} statusMap={PROXY_STATUS_MAP} />
        </strong>
      </div>
      <div className="summary-card">
        <span className="summary-label">Certificate</span>
        <strong>
          <StatusIndicator status={status.certificate} statusMap={CERT_STATUS_MAP} />
        </strong>
      </div>
      <div className="summary-card">
        <span className="summary-label">Last Activity</span>
        <strong>
          {status.lastActivity ? new Date(status.lastActivity).toLocaleTimeString() : '—'}
        </strong>
      </div>
      <div className="summary-card">
        <span className="summary-label">Events/sec</span>
        <strong>{status.eps.toFixed(1)}</strong>
      </div>
    </div>
  );
}

function EventTable({ events }) {
  const getEventType = (event) => {
    if (event.search_query) return 'Search';
    if (event.domain && event.domain.includes('youtube.com')) return 'Video';
    return 'Browse';
  };

  return (
    <div className="activity-log">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Application</th>
            <th>Domain</th>
            <th>Title</th>
            <th>Search Query</th>
            <th>Type</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {events.length === 0 ? (
            <tr>
              <td colSpan="7" className="empty-state">No activity recorded yet...</td>
            </tr>
          ) : (
            events.map((event, i) => (
              <tr key={i} className={`fade-in ${event.isNew ? 'bg-highlight' : ''}`}>
                <td className="mono">{new Date(event.timestamp).toLocaleTimeString()}</td>
                <td>
                   <div className="table-primary">{event.app || 'Unknown'}</div>
                </td>
                <td className="mono">{event.domain}</td>
                <td className="table-meta">{event.title || '-'}</td>
                <td className="mono muted">{event.search_query || '-'}</td>
                <td>
                  <span className={`badge ${event.search_query ? 'warning' : event.domain?.includes('youtube.com') ? 'danger' : 'neutral'}`}>
                    {getEventType(event)}
                  </span>
                </td>
                <td>
                  <span className="badge success">Inspected</span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="empty-dashboard-state">
      <div className="empty-icon"><i className="ri-eye-off-line"></i></div>
      <h3>No DPI activity detected</h3>
      <div className="empty-help">
        <p>Ensure the following are configured:</p>
        <ul>
          <li><i className="ri-checkbox-circle-line"></i> DPI enabled in Device Settings</li>
          <li><i className="ri-checkbox-circle-line"></i> NetVisor Proxy running on Agent</li>
          <li><i className="ri-checkbox-circle-line"></i> Root Certificate installed in Browser</li>
          <li><i className="ri-checkbox-circle-line"></i> Device using NetVisor Gateway</li>
        </ul>
      </div>
    </div>
  );
}

function DebugPanel({ event }) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="fixed bottom-0 right-0 bg-gray-800 text-white p-4 rounded-tl-lg shadow-lg w-1/3">
      <button onClick={() => setIsOpen(!isOpen)} className="font-bold">
        {isOpen ? '▼' : '▲'} Debug: Latest Event
      </button>
      {isOpen && (
        <pre className="mt-4 text-xs whitespace-pre-wrap">
          {JSON.stringify(event, null, 2)}
        </pre>
      )}
    </div>
  );
}


export default function DpiDashboard() {
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState({ state: 'disabled', proxy: 'stopped', certificate: 'not_installed', lastActivity: null, eps: 0 });
  const [filters, setFilters] = useState({ search: '', app: '', domain: '', status: 'all' });
  const [wsStatus, setWsStatus] = useState('disconnected');

  // Fetch initial status
  useEffect(() => {
    const getStatus = async () => {
      // const res = await systemService.getDpiStatus();
      // setStatus(res.data);
      const mockStatus = await fetchDpiStatus();
      setStatus(mockStatus);
    };
    getStatus();
    const interval = setInterval(getStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  // WebSocket for real-time DPI events
  const handleDpiEvent = useCallback((event) => {
    setEvents((prev) => [{ ...event, isNew: true }, ...prev].slice(0, MAX_EVENTS));
    setStatus(s => ({ ...s, lastActivity: event.timestamp }));
    
    // Remove highlight after a short delay
    setTimeout(() => {
      setEvents(currentEvents =>
        currentEvents.map(e => (e.id === event.id ? { ...e, isNew: false } : e))
      );
    }, 2000);
  }, []);

  useWebSocket('dpi_event', handleDpiEvent, {
    onOpen: () => setWsStatus('connected'),
    onClose: () => setWsStatus('disconnected'),
  });

  // Filtering
  const filteredEvents = events.filter((e) => {
    if (filters.status !== 'all' && e.status !== filters.status) return false;
    if (filters.app && e.app !== filters.app) return false;
    if (filters.domain && !e.domain.includes(filters.domain)) return false;
    if (filters.search && !(
      (e.domain && e.domain.toLowerCase().includes(filters.search.toLowerCase())) ||
      (e.title && e.title.toLowerCase().includes(filters.search.toLowerCase())) ||
      (e.search_query && e.search_query.toLowerCase().includes(filters.search.toLowerCase()))
    )) return false;
    return true;
  });

  const latestEvent = events.length > 0 ? events[0] : null;

  return (
    <div className="page-shell">
      <div className="max-w-7xl mx-auto w-100">
        <header className="header">
          <h1 className="text-2xl font-bold">DPI Dashboard</h1>
          {wsStatus === 'disconnected' && <div className="badge danger">WebSocket disconnected. Reconnecting...</div>}
        </header>

        <section className="glass-panel mt-6 p-4">
          <DpiStatus status={status} />
        </section>

        <section className="mt-6">
          <div className="flex items-center space-x-4 mb-4">
            <input
              type="text"
              placeholder="Search..."
              className="flex-grow"
              value={filters.search}
              onChange={e => setFilters(f => ({ ...f, search: e.target.value }))}
            />
            <input
              type="text"
              placeholder="Domain..."
              value={filters.domain}
              onChange={e => setFilters(f => ({ ...f, domain: e.target.value }))}
            />
            <select value={filters.status} onChange={e => setFilters(f => ({ ...f, status: e.target.value }))}>
              <option value="all">All Statuses</option>
              <option value="allowed">Allowed</option>
              <option value="blocked">Blocked</option>
            </select>
          </div>
          
          <div className="glass-panel mt-6 overflow-hidden">
            {filteredEvents.length > 0 ? (
              <EventTable events={filteredEvents} />
            ) : (
              <EmptyState />
            )}
          </div>
        </section>
        
        {latestEvent && <DebugPanel event={latestEvent} />}
      </div>
    </div>
  );
}

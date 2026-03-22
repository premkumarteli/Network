import { useState, useEffect, useCallback } from 'react';
import { systemService } from '../../services/api';
import { useVisibilityPolling } from '../../hooks/useVisibilityPolling';

const WebActivityLog = () => {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchWebActivity = useCallback(async () => {
    try {
      const response = await systemService.getGlobalWebActivity(15);
      if (response.data && response.data.activity) {
        setEvents(response.data.activity);
      }
      setError(null);
    } catch (err) {
      console.error('Failed to fetch web activity:', err);
    } finally {
      if (loading) setLoading(false);
    }
  }, [loading]);

  useEffect(() => {
    fetchWebActivity();
  }, [fetchWebActivity]);

  useVisibilityPolling(fetchWebActivity, 5000);

  const getCategoryBadge = (category) => {
    const cat = (category || 'web').toLowerCase();
    if (cat.includes('video')) return <span className="badge danger"><i className="ri-youtube-fill"></i> {category}</span>;
    if (cat.includes('repo') || cat.includes('code')) return <span className="badge neutral"><i className="ri-github-fill"></i> {category}</span>;
    if (cat.includes('chat') || cat.includes('ai')) return <span className="badge success"><i className="ri-message-3-fill"></i> {category}</span>;
    if (cat.includes('search')) return <span className="badge primary"><i className="ri-search-line"></i> {category}</span>;
    return <span className="badge neutral"><i className="ri-global-line"></i> {category}</span>;
  };

  const parseTime = (ts) => {
    if (!ts) return '';
    const d = new Date(ts);
    return Number.isNaN(d.getTime()) ? ts : d.toLocaleTimeString();
  };

  return (
    <div className="activity-log">
      <div className="section-title-row">
        <h3><i className="ri-spy-line primary" style={{marginRight: '0.4rem'}}></i> Deep Packet Inspection <span className="muted table-meta">(Live)</span></h3>
        {loading && <div className="pulse" style={{width: 8, height: 8, borderRadius: '50%', background: 'var(--primary)'}}></div>}
      </div>

      {error ? (
        <div className="empty-panel">
          <p className="danger">{error}</p>
        </div>
      ) : events.length === 0 && !loading ? (
        <div className="empty-panel" style={{ padding: '3rem 1rem' }}>
          <h4>No Web Activity Detected</h4>
          <p className="muted" style={{ fontSize: '0.9rem', marginTop: '0.5rem' }}>
            Enable DPI proxy on a device to analyze HTTPS traffic.
          </p>
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Domain / Time</th>
              <th>Category</th>
              <th>Page Title</th>
              <th>Device / Browser</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event, idx) => (
              <tr key={idx} className="clickable-row fade-in" style={{animationDelay: `${idx * 0.05}s`}}>
                <td className="mono" title={event.page_url}>
                  <div className="table-primary">{event.base_domain}</div>
                  <div className="table-meta">{parseTime(event.last_seen || event.first_seen)}</div>
                </td>
                <td>{getCategoryBadge(event.content_category)}</td>
                <td style={{maxWidth: '220px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'}} title={event.page_title}>
                  {event.page_title}
                </td>
                <td>
                  <div className="table-primary mono">{event.device_ip}</div>
                  <div className="table-meta">
                    <i className={event.browser_name === 'Edge' ? 'ri-edge-line' : event.browser_name === 'Chrome' ? 'ri-chrome-line' : 'ri-compass-line'}></i> {event.browser_name}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default WebActivityLog;

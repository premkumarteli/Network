import { useState, useEffect } from 'react';
import { subscribeRealtimeEvent } from '../../socket';
import SidePanel from '../V2/SidePanel';
import StatusBadge from '../V2/StatusBadge';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { getRiskTone } from '../../utils/presentation';

const AlertPanel = ({ isOpen, onClose }) => {
    const [alerts, setAlerts] = useState([]);

    useEffect(() => {
        const handleNewAlert = (alert) => {
            setAlerts(prev => [alert, ...prev].slice(0, 20));
        };

        return subscribeRealtimeEvent('alert_event', handleNewAlert);
    }, []);

    return (
        <SidePanel
            open={isOpen}
            title="Real-time Threats"
            description="Live threat feed from the detection engine."
            onClose={onClose}
            footer={
                <button
                    type="button"
                    className="nv-button nv-button--secondary"
                    style={{ width: '100%' }}
                    onClick={() => setAlerts([])}
                >
                    <i className="ri-delete-bin-line"></i>
                    Clear History
                </button>
            }
        >
            {alerts.length > 0 ? (
                <div className="nv-timeline">
                    {alerts.map((alert, index) => (
                        <div
                            key={alert.id || index}
                            className="nv-timeline-row"
                        >
                            <div className="nv-timeline-row__icon" style={
                                alert.severity === 'CRITICAL'
                                    ? { background: 'rgba(251, 113, 133, 0.18)', color: 'var(--nv-danger)' }
                                    : undefined
                            }>
                                <i className={alert.severity === 'CRITICAL' ? 'ri-alarm-warning-line' : 'ri-shield-flash-line'}></i>
                            </div>
                            <div>
                                <div className="nv-timeline-row__title">{alert.message}</div>
                                <div className="nv-timeline-row__meta">
                                    <span className="mono">{alert.src_ip}</span>
                                    {alert.application ? ` · ${alert.application}` : ''}
                                </div>
                            </div>
                            <div className="nv-timeline-row__aside">
                                <StatusBadge tone={getRiskTone(alert.severity)}>
                                    {alert.severity}
                                </StatusBadge>
                                <div className="mono" style={{ marginTop: '0.35rem', fontSize: '0.76rem' }}>
                                    {formatUtcTimestampToLocal(alert.time || alert.timestamp)}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            ) : (
                <div className="nv-empty" style={{ background: 'transparent', boxShadow: 'none', border: '0', textAlign: 'center', alignItems: 'center' }}>
                    <div className="nv-empty__icon">
                        <i className="ri-shield-flash-line"></i>
                    </div>
                    <div className="nv-stack" style={{ gap: '0.5rem' }}>
                        <h3 className="nv-empty__title">Scanning Grid...</h3>
                        <p className="nv-empty__description">No threats detected in the current session. The engine is monitoring live traffic.</p>
                    </div>
                </div>
            )}
        </SidePanel>
    );
};


export default AlertPanel;

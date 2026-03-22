import KpiCard from '../UI/KpiCard';

const StatsPanel = ({ stats = {}, cards = null }) => {
  const resolvedCards = cards || [
    {
      icon: 'ri-macbook-line',
      label: 'Active Devices',
      value: stats.active_devices || 0,
      meta: 'managed and byod currently visible',
    },
    {
      icon: 'ri-apps-2-line',
      label: 'Applications',
      value: stats.applications || 0,
      meta: 'classified sessions in the rolling window',
    },
    {
      icon: 'ri-alarm-warning-line',
      label: 'High Risk Alerts',
      value: stats.high_risk || 0,
      meta: 'high and critical alerts in the last 24h',
      tone: stats.high_risk > 0 ? 'danger' : 'default',
    },
    {
      icon: 'ri-exchange-box-line',
      label: 'Total Flows (24h)',
      value: stats.flows_24h || 0,
      meta: 'aggregated network sessions processed',
    },
  ];

  return (
    <div className="kpi-grid">
      {resolvedCards.map((card) => (
        <KpiCard key={card.label} {...card} />
      ))}
    </div>
  );
};

export default StatsPanel;

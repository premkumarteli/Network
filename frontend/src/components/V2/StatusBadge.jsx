const StatusBadge = ({ tone = 'neutral', icon, children, className = '' }) => (
  <span className={`nv-badge nv-badge--${tone} ${className}`.trim()}>
    {icon ? <i className={icon}></i> : null}
    <span>{children}</span>
  </span>
);

export default StatusBadge;

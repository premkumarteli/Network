const MetricCard = ({
  icon,
  label,
  value,
  meta,
  accent,
  className = '',
}) => (
  <article
    className={`nv-metric ${className}`.trim()}
    style={accent ? { '--nv-accent': accent } : undefined}
  >
    <div className="nv-metric__header">
      {icon ? (
        <span className="nv-metric__icon">
          <i className={icon}></i>
        </span>
      ) : null}
      <span className="nv-metric__label">{label}</span>
    </div>
    <div className="nv-metric__value">{value}</div>
    {meta ? <div className="nv-metric__meta">{meta}</div> : null}
  </article>
);

export default MetricCard;

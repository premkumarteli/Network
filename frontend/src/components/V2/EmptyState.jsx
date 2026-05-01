const EmptyState = ({ icon = 'ri-inbox-archive-line', title, description, action }) => (
  <div className="nv-empty">
    <div className="nv-empty__icon">
      <i className={icon}></i>
    </div>
    <div className="nv-stack" style={{ gap: '0.5rem' }}>
      <h3 className="nv-empty__title">{title}</h3>
      {description ? <p className="nv-empty__description">{description}</p> : null}
    </div>
    {action || null}
  </div>
);

export default EmptyState;

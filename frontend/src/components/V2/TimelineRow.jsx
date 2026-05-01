const TimelineRow = ({ icon, title, meta, aside, children }) => (
  <div className="nv-timeline-row">
    <div className="nv-timeline-row__icon">
      <i className={icon}></i>
    </div>
    <div>
      <div className="nv-timeline-row__title">{title}</div>
      {meta ? <div className="nv-timeline-row__meta">{meta}</div> : null}
      {children}
    </div>
    {aside ? <div className="nv-timeline-row__aside">{aside}</div> : null}
  </div>
);

export default TimelineRow;

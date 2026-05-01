const SectionCard = ({ title, caption, aside, children, className = '' }) => (
  <section className={`nv-section ${className}`.trim()}>
    {(title || caption || aside) ? (
      <div className="nv-section__header">
        <div className="nv-section__heading">
          {caption ? <div className="nv-section__caption">{caption}</div> : null}
          {title ? <h2 className="nv-section__title">{title}</h2> : null}
        </div>
        {aside ? <div>{aside}</div> : null}
      </div>
    ) : null}
    <div className="nv-section__body">{children}</div>
  </section>
);

export default SectionCard;

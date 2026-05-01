const PageHeader = ({ eyebrow, title, description, actions, children }) => (
  <header className="nv-page-header">
    <div className="nv-page-header__copy">
      {eyebrow ? <div className="nv-page-header__eyebrow">{eyebrow}</div> : null}
      <h1 className="nv-page-header__title">{title}</h1>
      {description ? <p className="nv-page-header__description">{description}</p> : null}
      {children}
    </div>
    {actions ? <div className="nv-page-header__actions">{actions}</div> : null}
  </header>
);

export default PageHeader;

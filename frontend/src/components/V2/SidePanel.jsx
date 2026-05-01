import { useEffect } from 'react';

const SidePanel = ({ open, title, description, onClose, children, footer }) => {
  useEffect(() => {
    if (!open) {
      return undefined;
    }

    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        onClose?.();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  if (!open) {
    return null;
  }

  return (
    <>
      <button type="button" className="nv-drawer-backdrop" aria-label="Close details" onClick={onClose} />
      <aside className="nv-drawer" aria-modal="true" role="dialog">
        <button type="button" className="nv-button nv-button--ghost nv-drawer__close" onClick={onClose}>
          <i className="ri-close-line"></i>
        </button>
        <div className="nv-drawer__header">
          <div className="nv-stack" style={{ gap: '0.35rem' }}>
            <h3>{title}</h3>
            {description ? <p>{description}</p> : null}
          </div>
        </div>
        <div className="nv-drawer__body">{children}</div>
        {footer ? <div className="nv-drawer__footer">{footer}</div> : null}
      </aside>
    </>
  );
};

export default SidePanel;

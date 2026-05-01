import SectionCard from './SectionCard';
import StatusBadge from './StatusBadge';

const AuthSurface = ({
  eyebrow = 'Secure access',
  title,
  description,
  badge = 'Protected session',
  asideTitle = 'Workspace posture',
  asideCaption = 'Operational notes',
  aside,
  footer,
  children,
}) => (
  <div className="nv-auth">
    <div className="nv-auth__shell">
      <SectionCard
        className="nv-auth__card"
        caption={eyebrow}
        title={title}
        aside={<StatusBadge tone="accent" icon="ri-shield-keyhole-line">{badge}</StatusBadge>}
      >
        {description ? <p className="nv-auth__description">{description}</p> : null}
        <div className="nv-auth__body">{children}</div>
        {footer ? <div className="nv-auth__footer">{footer}</div> : null}
      </SectionCard>

      {aside ? (
        <SectionCard className="nv-auth__aside" caption={asideCaption} title={asideTitle}>
          <div className="nv-auth__aside-body">{aside}</div>
        </SectionCard>
      ) : null}
    </div>
  </div>
);

export default AuthSurface;

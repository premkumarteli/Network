const AppShell = ({
  rail,
  topbar,
  children,
  collapsed = false,
  mobileNavOpen = false,
  onCloseMobileNav,
  aside,
}) => (
  <div className={`nv-shell ${collapsed ? 'nv-shell--collapsed' : ''}`.trim()}>
    {mobileNavOpen ? (
      <button
        type="button"
        className="nv-overlay"
        aria-label="Close navigation"
        onClick={onCloseMobileNav}
      />
    ) : null}
    {rail}
    <div className="nv-main">
      {topbar}
      <div className="nv-workspace">{children}</div>
    </div>
    {aside}
  </div>
);

export default AppShell;

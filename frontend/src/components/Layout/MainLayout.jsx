import { useEffect, useState } from 'react';
import { Outlet } from 'react-router-dom';
import Header from './Header';
import Sidebar from './Sidebar';
import AlertPanel from './AlertPanel';
import AppShell from '../V2/AppShell';

const MainLayout = () => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);
  const [isAlertPanelOpen, setIsAlertPanelOpen] = useState(false);

  const toggleSidebar = () => {
    setIsCollapsed(!isCollapsed);
  };

  const toggleNavigation = () => {
    if (window.innerWidth <= 980) {
      setIsMobileNavOpen((current) => !current);
      return;
    }
    toggleSidebar();
  };

  const toggleAlertPanel = () => {
    setIsAlertPanelOpen(!isAlertPanelOpen);
  };

  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth > 980) {
        setIsMobileNavOpen(false);
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return (
    <AppShell
      collapsed={isCollapsed}
      mobileNavOpen={isMobileNavOpen}
      onCloseMobileNav={() => setIsMobileNavOpen(false)}
      rail={(
        <Sidebar
          isCollapsed={isCollapsed}
          isMobileOpen={isMobileNavOpen}
          onCloseMobile={() => setIsMobileNavOpen(false)}
        />
      )}
      topbar={(
        <Header
          onToggleAlerts={toggleAlertPanel}
          onToggleNav={toggleNavigation}
        />
      )}
      aside={<AlertPanel isOpen={isAlertPanelOpen} onClose={() => setIsAlertPanelOpen(false)} />}
    >
      <Outlet />
    </AppShell>
  );
};

export default MainLayout;

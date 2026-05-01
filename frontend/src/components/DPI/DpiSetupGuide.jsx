import StatusBadge from '../V2/StatusBadge';

const DpiSetupGuide = ({ deviceIp, inspectionStatus }) => {
  const inspectionEnabled = Boolean(inspectionStatus?.inspection_enabled);
  const caInstalled = Boolean(inspectionStatus?.ca_installed);
  const ready = inspectionEnabled && caInstalled;

  return (
    <div className="nv-stack" style={{ gap: '1rem' }}>
      <div className="nv-inline-actions">
        <StatusBadge tone={ready ? 'success' : 'warning'} icon={ready ? 'ri-check-line' : 'ri-settings-3-line'}>
          {ready ? 'Ready' : 'Setup required'}
        </StatusBadge>
        <StatusBadge tone="neutral" icon="ri-shield-user-line">
          Managed devices only
        </StatusBadge>
      </div>

      <div className="nv-grid nv-grid--two">
        <div className="nv-stack" style={{ gap: '0.9rem' }}>
          <p className="nv-table__meta" style={{ fontSize: '0.86rem' }}>
            DPI visibility is available only when the managed browser launcher and trusted CA are in place for device <span className="mono">{deviceIp}</span>.
            General browsing outside the managed launcher remains outside inspection by design.
          </p>

          <div className="nv-insight-list">
            <div className="nv-insight-item">
              <div className="nv-insight-item__icon">
                <i
                  className="ri-checkbox-circle-fill"
                  style={{ opacity: inspectionEnabled ? 1 : 0.35 }}
                ></i>
              </div>
              <div className="nv-insight-item__body">
                <strong>Enable Inspection</strong>
                <p>Ensure the policy is active for this device.</p>
              </div>
            </div>
            <div className="nv-insight-item">
              <div className="nv-insight-item__icon">
                <i
                  className="ri-checkbox-circle-fill"
                  style={{ opacity: caInstalled ? 1 : 0.35 }}
                ></i>
              </div>
              <div className="nv-insight-item__body">
                <strong>Trust the CA</strong>
                <p>The NetVisor CA must be installed for browser interception to work.</p>
              </div>
            </div>
            <div className="nv-insight-item">
              <div className="nv-insight-item__icon">
                <i className="ri-terminal-box-line"></i>
              </div>
              <div className="nv-insight-item__body">
                <strong>Launch the managed browser</strong>
                <p>Open the managed launcher on the agent machine to keep browsing in scope.</p>
              </div>
            </div>
          </div>

          <div className="nv-code-block">launch_chrome_netvisor.cmd</div>
        </div>

        <div className="nv-stack" style={{ gap: '0.85rem' }}>
          <div className="nv-section__caption">Expected results</div>
          <div className="nv-pill-grid">
            <div className="nv-pill-card">
              <div className="nv-pill-card__icon">
                <i className="ri-google-fill"></i>
              </div>
              <div className="nv-pill-card__content">
                <strong>Google Search</strong>
                <span>&quot;Networking basics&quot;</span>
              </div>
            </div>
            <div className="nv-pill-card">
              <div className="nv-pill-card__icon">
                <i className="ri-youtube-fill"></i>
              </div>
              <div className="nv-pill-card__content">
                <strong>YouTube Video</strong>
                <span>&quot;How NetVisor Works&quot;</span>
              </div>
            </div>
          </div>
          <p className="nv-table__meta" style={{ fontSize: '0.8rem' }}>
            Managed DPI stays narrow by policy. The aim is evidence, not full payload retention.
          </p>
        </div>
      </div>
    </div>
  );
};

export default DpiSetupGuide;

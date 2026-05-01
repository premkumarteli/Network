import SidePanel from './SidePanel';
import StatusBadge from './StatusBadge';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { formatByteCount, getRiskTone } from '../../utils/presentation';

const buildEvidenceTitle = (event) => {
  if (!event) {
    return 'Session Evidence';
  }
  return event.application || event.domain || event.host || event.dst_ip || 'Session Evidence';
};

const EvidenceRow = ({ label, value }) => (
  <div className="nv-summary-tile">
    <span>{label}</span>
    <strong>{value}</strong>
  </div>
);

const EvidenceDrawer = ({ open, event, onClose, footer }) => {
  if (!open) {
    return null;
  }

  const title = buildEvidenceTitle(event);
  const timestamp = formatUtcTimestampToLocal(event?.timestamp || event?.last_seen || event?.time);
  const bytes = formatByteCount(event?.byte_count || event?.size || 0);
  const severity = event?.severity || 'LOW';
  const destination = event?.domain || event?.host || event?.dst_ip || '-';

  return (
    <SidePanel
      open={open}
      title={title}
      description="Flow evidence captured from the live session feed."
      onClose={onClose}
      footer={footer}
    >
      <div className="nv-evidence-grid">
        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <EvidenceRow label="Severity" value={<StatusBadge tone={getRiskTone(severity)}>{severity}</StatusBadge>} />
          <EvidenceRow label="Last Seen" value={<span className="mono">{timestamp}</span>} />
          <EvidenceRow label="Source" value={<span className="mono">{event?.src_ip || '-'}</span>} />
          <EvidenceRow label="Destination" value={<span className="mono">{destination}</span>} />
        </div>

        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <EvidenceRow label="Protocol" value={<span className="mono">{event?.protocol || 'Unknown'}</span>} />
          <EvidenceRow label="Bytes" value={<span className="mono">{bytes}</span>} />
          <EvidenceRow label="Session Time" value={<span className="mono">{event?.duration ? `${event.duration}s` : '—'}</span>} />
          <EvidenceRow label="App" value={event?.application || 'Other'} />
        </div>

        <div>
          <div className="nv-section__caption">Raw Context</div>
          <pre className="nv-code-block">{JSON.stringify(event || {}, null, 2)}</pre>
        </div>
      </div>
    </SidePanel>
  );
};

export default EvidenceDrawer;

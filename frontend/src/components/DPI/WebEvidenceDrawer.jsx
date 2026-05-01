import SidePanel from '../V2/SidePanel';
import StatusBadge from '../V2/StatusBadge';
import SectionCard from '../V2/SectionCard';
import { formatUtcTimestampToLocal } from '../../utils/time';
import { formatBrowserLabel, formatByteCount, getRiskTone } from '../../utils/presentation';
import {
  getWebEvidencePrimaryLabel,
  getWebEvidenceSearchQueries,
  getWebEvidenceTitles,
  getWebEvidenceUrls,
  normalizeWebRiskLevel,
} from '../../utils/webEvidence';

const formatConfidence = (value) => {
  const score = Number(value) || 0;
  if (score >= 0.8) {
    return `High (${score.toFixed(2)})`;
  }
  if (score >= 0.55) {
    return `Medium (${score.toFixed(2)})`;
  }
  return `Low (${score.toFixed(2)})`;
};

const WebEvidenceDrawer = ({ open, item, onClose, footer }) => {
  if (!open) {
    return null;
  }

  const urls = getWebEvidenceUrls(item);
  const titles = getWebEvidenceTitles(item);
  const queries = getWebEvidenceSearchQueries(item);
  const requestBytes = Number(item?.request_bytes) || 0;
  const responseBytes = Number(item?.response_bytes) || 0;
  const eventCount = Number(item?.event_count) || 1;
  const riskLevel = normalizeWebRiskLevel(item?.risk_level);
  const title = item?.group_label || getWebEvidencePrimaryLabel(item);

  return (
    <SidePanel
      open={open}
      title={title}
      description="Redacted evidence only. The backend stores metadata and sanitized snippets, not full payload bodies."
      onClose={onClose}
      footer={footer ?? (
        <StatusBadge tone={getRiskTone(riskLevel)}>
          {riskLevel} · {formatConfidence(item?.confidence_score)}
        </StatusBadge>
      )}
    >
      <div className="nv-evidence-grid">
        <div className="nv-summary-strip" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <div className="nv-summary-tile">
            <span>Device</span>
            <strong className="mono">{item?.device_ip || '-'}</strong>
            <p>{formatBrowserLabel(item?.browser_name, item?.process_name)}</p>
          </div>
          <div className="nv-summary-tile">
            <span>Seen</span>
            <strong>{formatUtcTimestampToLocal(item?.last_seen)}</strong>
            <p>{item?.first_seen ? `First seen ${formatUtcTimestampToLocal(item.first_seen)}` : 'No first-seen timestamp'}</p>
          </div>
          <div className="nv-summary-tile">
            <span>Scope</span>
            <strong>{eventCount} event{eventCount === 1 ? '' : 's'}</strong>
            <p>{urls.length} URL{urls.length === 1 ? '' : 's'} · {titles.length} title{titles.length === 1 ? '' : 's'}</p>
          </div>
          <div className="nv-summary-tile">
            <span>Traffic</span>
            <strong>{formatByteCount(requestBytes + responseBytes)}</strong>
            <p>{formatByteCount(requestBytes)} request · {formatByteCount(responseBytes)} response</p>
          </div>
        </div>

        <SectionCard title="Observed URLs" caption="Correlated Tabs">
          {urls.length > 0 ? (
            <div className="nv-stack" style={{ gap: '0.6rem' }}>
              {urls.map((url) => (
                <code key={url} className="nv-code-block" style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>{url}</code>
              ))}
            </div>
          ) : (
            <code className="nv-code-block">No URL captured for this evidence cluster.</code>
          )}
        </SectionCard>

        {queries.length > 0 ? (
          <SectionCard title="Search Queries" caption="Intent">
            <div className="nv-stack" style={{ gap: '0.6rem' }}>
              {queries.map((query) => (
                <code key={query} className="nv-code-block" style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>{query}</code>
              ))}
            </div>
          </SectionCard>
        ) : null}

        <SectionCard title="Redacted Snippet" caption="Evidence">
          <pre className="nv-code-block">{item?.snippet_redacted || 'No textual snippet captured for this event.'}</pre>
        </SectionCard>

        {item?.threat_msg ? (
          <SectionCard title="Threat Note" caption="Detection Context">
            <p>{item.threat_msg}</p>
          </SectionCard>
        ) : null}
      </div>
    </SidePanel>
  );
};

export default WebEvidenceDrawer;

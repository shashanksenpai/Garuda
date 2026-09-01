import SeverityChip from './SeverityChip.jsx'
import RiskGauge from './RiskGauge.jsx'
import { api } from '../api.js'

function fmtTime(ts) {
  try {
    return new Date(ts).toLocaleTimeString([], { hour12: false })
  } catch {
    return ts
  }
}

export default function IncidentDetail({ incident, onPresent }) {
  if (!incident) {
    return (
      <div className="panel">
        <div className="panel-header"><span className="panel-title">INCIDENT DETAIL</span></div>
        <div className="panel-body"><div className="empty-hint">Select an incident to view the AI investigation.</div></div>
      </div>
    )
  }

  const entities = incident.entities || {}
  const actions = incident.recommended_actions || {}

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">INCIDENT DETAIL</span>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button className="live-btn" onClick={() => onPresent?.(incident)}>Present</button>
          <span className="status-tag">{incident.investigation_status}</span>
        </div>
      </div>
      <div className="panel-body">
        <div className="detail-section">
          <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 8, lineHeight: 1.4 }}>{incident.title}</div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
            <SeverityChip severity={incident.severity} />
          </div>
          <RiskGauge score={incident.risk_score} severity={incident.severity} />
        </div>

        <div className="detail-section">
          <div className="detail-label">ENTITIES</div>
          <dl className="kv-grid">
            <dt>Source IP</dt><dd>{(entities.source_ips || []).join(', ') || '—'}</dd>
            <dt>Target IP</dt><dd>{(entities.dest_ips || []).join(', ') || '—'}</dd>
            <dt>Host</dt><dd>{(entities.hosts || []).join(', ') || '—'}</dd>
            <dt>User</dt><dd>{(entities.users || []).join(', ') || '—'}</dd>
          </dl>
        </div>

        <div className="detail-section">
          <div className="detail-label">MITRE ATT&amp;CK TECHNIQUES</div>
          <div className="chip-row">
            {(incident.attack_techniques || []).map((t) => (
              <span className="tech-chip" key={t.id}><b>{t.id}</b> {t.name}</span>
            ))}
            {(incident.attack_techniques || []).length === 0 && <span className="empty-hint" style={{ padding: 0 }}>None mapped</span>}
          </div>
        </div>

        <div className="detail-section">
          <div className="detail-label">ATTACK TIMELINE</div>
          <div className="timeline">
            {(incident.timeline || []).map((t, i) => (
              <div className="timeline-item" key={i}>
                <div className={`timeline-rail sev-${t.severity}`}><div className="timeline-node" /></div>
                <div>
                  <div className="timeline-time">{fmtTime(t.timestamp)}</div>
                  <div className="timeline-desc">{t.description}</div>
                </div>
              </div>
            ))}
            {(incident.timeline || []).length === 0 && <div className="empty-hint">No timeline yet.</div>}
          </div>
        </div>

        <div className="detail-section">
          <div className="detail-label">AI INVESTIGATION</div>
          <p className="detail-summary">{incident.investigation_summary || 'Investigation in progress…'}</p>
        </div>

        <div className="detail-section">
          <div className="detail-label">RECOMMENDED RESPONSE</div>
          {['immediate', 'investigation', 'recovery'].map((k) => (
            (actions[k] || []).length > 0 && (
              <div className="action-group" key={k}>
                <div className="action-group-title" style={{ color: k === 'immediate' ? 'var(--sev-high)' : 'var(--text-dim)' }}>
                  {k === 'immediate' ? 'Immediate containment' : k === 'investigation' ? 'Investigation steps' : 'Recovery'}
                </div>
                <ul className="action-list">
                  {actions[k].map((a, i) => <li key={i}>{a}</li>)}
                </ul>
              </div>
            )
          ))}
        </div>

        <button className="report-btn" onClick={() => window.open(api.reportUrl(incident.incident_id), '_blank')}>
          Download incident report (PDF)
        </button>
      </div>
    </div>
  )
}

import SeverityChip from './SeverityChip.jsx'

export default function IncidentList({ incidents, selectedId, onSelect }) {
  const sorted = [...incidents].sort((a, b) => b.risk_score - a.risk_score)

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">INCIDENTS</span>
        <span className="status-tag">{incidents.length} total</span>
      </div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {sorted.length === 0 && <div className="empty-hint">No incidents correlated yet.</div>}
        {sorted.map((inc) => (
          <button
            key={inc.incident_id}
            className={`incident-card sev-${inc.severity} ${inc.incident_id === selectedId ? 'selected' : ''}`}
            style={{ borderLeftColor: `var(--sev-${inc.severity})` }}
            onClick={() => onSelect(inc.incident_id)}
          >
            <div className="incident-card-top">
              <span className="incident-card-title">{inc.title}</span>
              <span className="incident-card-risk" style={{ color: `var(--sev-${inc.severity})` }}>
                {inc.risk_score}
              </span>
            </div>
            <div className="incident-card-meta">
              <SeverityChip severity={inc.severity} />
              <span>{inc.investigation_status}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

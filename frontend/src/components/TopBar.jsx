import BrandMark from './BrandMark.jsx'

export default function TopBar({ status, scenarios, running, scenario, onScenarioChange, onStart, onStop, view, onViewChange }) {
  return (
    <div className="topbar">
      <div className="brand">
        <BrandMark />
        GARUDA
        <span className="brand-sub">Agentic Threat Investigation Console</span>
      </div>

      <div className="view-switch">
        <button className={`view-switch-btn ${view === 'console' ? 'active' : ''}`} onClick={() => onViewChange('console')}>Console</button>
        <button className={`view-switch-btn ${view === 'topology' ? 'active' : ''}`} onClick={() => onViewChange('topology')}>Topology &amp; Response</button>
      </div>

      <div className="topbar-stats">
        <div className="topbar-stat">
          <span className="topbar-stat-label">EVENTS</span>
          <span className="topbar-stat-value">{status?.total_events ?? '—'}</span>
        </div>
        <div className="topbar-stat">
          <span className="topbar-stat-label">ACTIVE INCIDENTS</span>
          <span className="topbar-stat-value">{status?.active_incidents ?? '—'}</span>
        </div>
        <div className="topbar-stat">
          <span className="topbar-stat-label">PEAK RISK</span>
          <span className="topbar-stat-value">{status?.highest_risk_score ?? 0}</span>
        </div>
      </div>

      <div className="live-toggle">
        <div className={`pulse-dot ${running ? 'on' : ''}`} style={{ marginRight: -2 }} />
        <select className="live-select" value={scenario} onChange={(e) => onScenarioChange(e.target.value)} disabled={running}>
          {scenarios.map((s) => (
            <option key={s} value={s}>{s.replaceAll('_', ' ')}</option>
          ))}
        </select>
        {running ? (
          <button className="live-btn stop" onClick={onStop}>Stop</button>
        ) : (
          <button className="live-btn" onClick={onStart}>Run scenario</button>
        )}
      </div>
    </div>
  )
}

const COLOR_VAR = {
  info: 'var(--sev-info)',
  low: 'var(--sev-low)',
  medium: 'var(--sev-medium)',
  high: 'var(--sev-high)',
  critical: 'var(--sev-critical)',
}

function classify(score) {
  if (score >= 85) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 35) return 'MEDIUM'
  if (score > 0) return 'LOW'
  return 'NONE'
}

export default function RiskGauge({ score = 0, severity = 'info' }) {
  const color = COLOR_VAR[severity] || COLOR_VAR.info
  return (
    <div className="risk-gauge">
      <span className="risk-gauge-value" style={{ color }}>{score}</span>
      <span className="risk-gauge-label">{classify(score)} RISK</span>
      <div className="risk-gauge-track">
        <div className="risk-gauge-fill" style={{ width: `${Math.min(score, 100)}%`, background: color }} />
      </div>
    </div>
  )
}

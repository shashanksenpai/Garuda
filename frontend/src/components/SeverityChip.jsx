export function sevClass(sev) {
  return `sev-${sev || 'info'}`
}

export default function SeverityChip({ severity, label }) {
  const cls = sevClass(severity)
  return (
    <span className={`sev-chip ${cls}`}>
      <span className="sev-dot" />
      {label || (severity || 'info').toUpperCase()}
    </span>
  )
}

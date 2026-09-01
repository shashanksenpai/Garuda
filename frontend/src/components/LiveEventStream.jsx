import { useEffect, useRef } from 'react'
import { sevClass } from './SeverityChip.jsx'

function fmtTime(ts) {
  try {
    return new Date(ts).toLocaleTimeString([], { hour12: false })
  } catch {
    return ''
  }
}

export default function LiveEventStream({ items }) {
  const scrollerRef = useRef(null)

  useEffect(() => {
    const el = scrollerRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [items.length])

  return (
    <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <div className="panel-header">
        <span className="panel-title">LIVE EVENT STREAM</span>
        <span className="status-tag">{items.length} shown</span>
      </div>
      <div className="panel-body" style={{ flex: 1, minHeight: 0, display: 'flex' }}>
        <div className="event-stream" ref={scrollerRef}>
          {items.length === 0 && (
            <div className="empty-hint">No telemetry yet.<br />Run a scenario to start the feed.</div>
          )}
          {items.map((it) => (
            <div key={it.id} className={`event-row ${sevClass(it.severity)}`}>
              <span className="event-time">{fmtTime(it.timestamp)}</span>
              <span className="event-bullet">●</span>
              <span className="event-msg">
                {it.kind === 'detection' && <b>{it.title} — </b>}
                {it.message}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

import { useEffect, useRef } from 'react'

function fmtTime(ts) {
  try {
    return new Date(ts).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch {
    return ''
  }
}

const KIND_LABEL = { scenario: 'SCENARIO', agent: 'REAL', live: 'LIVE', background: 'NORMAL' }

/**
 * Compact live-scrolling packet table. `packets` is expected to already be a
 * throttled/batched buffer (see App.jsx) so this never re-renders per raw SSE frame.
 * `hotSourceIps`, if given, flags rows from a recently-detected attacker source.
 */
export default function PacketFlow({ packets = [], hotSourceIps = null }) {
  const scrollerRef = useRef(null)

  useEffect(() => {
    const el = scrollerRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [packets.length])

  return (
    <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <div className="panel-header">
        <span className="panel-title">PACKET FLOW</span>
        <span className="status-tag">{packets.length} shown</span>
      </div>
      <div className="panel-body" style={{ flex: 1, minHeight: 0, display: 'flex', padding: 0 }}>
        <div className="packet-flow" ref={scrollerRef}>
          <div className="packet-row packet-row-head">
            <span>TIME</span><span>SRC</span><span>DST</span><span>PROTO</span><span>SIZE</span><span>KIND</span>
          </div>
          {packets.length === 0 && <div className="empty-hint">No traffic yet.</div>}
          {packets.map((p) => {
            const malicious = Boolean(hotSourceIps?.has(p.src_ip)) || (p.severity && p.severity !== 'info' && p.kind !== 'background')
            return (
              <div key={p.id} className={`packet-row packet-kind-${p.kind}${malicious ? ' packet-row-malicious' : ''}`}>
                <span className="packet-time">{fmtTime(p.timestamp)}</span>
                <span className="packet-addr">{p.src_ip}{p.src_port ? `:${p.src_port}` : ''}</span>
                <span className="packet-addr">{p.dst_ip}{p.dst_port ? `:${p.dst_port}` : ''}</span>
                <span>{p.protocol}</span>
                <span>{p.size}B</span>
                <span className={`packet-tag packet-tag-${p.kind}`}>{KIND_LABEL[p.kind] || p.kind}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

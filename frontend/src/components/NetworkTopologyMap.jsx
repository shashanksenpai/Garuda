import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import ReactFlow, {
  Background, Controls, MiniMap, Handle, Position, MarkerType, useViewport,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { api } from '../api.js'

const DESTINATIONS_CACHE_TTL_MS = 4000
const _destinationsCache = new Map() // assetId -> { data, ts }
const HOVER_CARD_WIDTH = 270
const HOVER_CARD_EST_HEIGHT = 340

// Node color = asset status, reusing the exact severity tokens already defined in index.css.
const STATUS_COLOR = {
  healthy: 'var(--sev-info)',
  at_risk: 'var(--sev-medium)',
  compromised: 'var(--sev-critical)',
  isolated: 'var(--sev-high)',
  blocked: 'var(--sev-low)',
}

const TYPE_LABEL = {
  workstation: 'WS', server: 'SRV', database: 'DB',
  firewall: 'FW', router: 'RTR', cloud_service: 'CLOUD', external: 'NET',
}

const EXTERNAL_ID = 'external'
const PACKET_TTL_MS = 850
const NODE_W = 148
const NODE_H = 64
const ACTIVITY_WINDOW_MS = 3000
const HOT_WINDOW_MS = 9000
const MAX_ACTIVE_DOTS = 90

function pairKey(a, b) {
  return a < b ? `${a}|${b}` : `${b}|${a}`
}

function fmtRelative(iso) {
  if (!iso) return 'never'
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 5) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  return `${Math.round(m / 60)}h ago`
}

function severityDotColor(sev) {
  if (sev === 'critical') return 'var(--sev-critical)'
  if (sev === 'high') return 'var(--sev-high)'
  if (sev === 'medium') return 'var(--sev-medium)'
  if (sev === 'low') return 'var(--sev-low)'
  return 'var(--sev-info)'
}

function HoverCard({ data, destinations, position, pinned, onClose }) {
  const online = data.is_dynamic ? (Date.now() - new Date(data.last_seen || 0).getTime()) < 12000 : null
  const reasons = data.attack_reasons || []
  return (
    <div
      className={`topo-hover-card${pinned ? ' topo-hover-card-pinned' : ''}`}
      style={{ left: position.left, top: position.top }}
    >
      <div className="topo-hover-title">
        {data.name}
        {pinned && <button className="topo-hover-close" onClick={onClose} aria-label="Close">×</button>}
      </div>
      <dl className="kv-grid topo-hover-grid">
        <dt>Type</dt><dd>{data.asset_type}{data.is_dynamic ? ' (live device)' : ''}</dd>
        <dt>IP</dt><dd>{data.ip_address || 'unknown'}</dd>
        <dt>Status</dt><dd>{data.status}</dd>
        <dt>Criticality</dt><dd>{data.criticality}</dd>
        <dt>Zone</dt><dd>{data.zone}</dd>
        {data.is_dynamic && (
          <>
            <dt>Role</dt><dd>{data.role}{online !== null && (online ? ' · online' : ' · offline')}</dd>
            <dt>User</dt><dd>{data.current_user || 'unknown'}</dd>
            <dt>OS</dt><dd>{data.os_info || 'unknown'}</dd>
            <dt>Last seen</dt><dd>{fmtRelative(data.last_seen)}</dd>
          </>
        )}
        <dt>Activity</dt><dd>{data.activity ? `~${data.activity} pkt/3s` : 'quiet'}</dd>
      </dl>

      {data.role === 'attacker' && reasons.length > 0 && (
        <>
          <div className="topo-hover-subtitle topo-hover-subtitle-attacker">WHY FLAGGED ATTACKER</div>
          <ul className="topo-hover-reason-list">
            {[...reasons].reverse().slice(0, 3).map((r, i) => (
              <li key={r.detection_id || i}>
                <b>{r.threat_type}</b>{r.mitre_technique_id ? ` (${r.mitre_technique_id})` : ''} — {fmtRelative(r.timestamp)}
                <div className="topo-hover-proc-meta">{r.evidence}</div>
              </li>
            ))}
          </ul>
        </>
      )}

      {data.is_dynamic && (data.processes || []).length > 0 && (
        <>
          <div className="topo-hover-subtitle">LOCAL PROCESSES</div>
          <ul className="topo-hover-proc-list">
            {data.processes.slice(0, 6).map((p, i) => (
              <li key={i}>{p.name} <span className="topo-hover-proc-meta">({p.pid}{p.username ? ` · ${p.username}` : ''})</span></li>
            ))}
          </ul>
        </>
      )}

      {data.ip_address && (
        <>
          <div className="topo-hover-subtitle">SITES ACCESSED</div>
          {destinations === null && <div className="topo-hover-proc-meta">loading…</div>}
          {destinations && destinations.length === 0 && <div className="topo-hover-proc-meta">none observed yet</div>}
          {destinations && destinations.length > 0 && (
            <ul className="topo-hover-proc-list">
              {destinations.slice(0, 8).map((d, i) => (
                <li key={i}>
                  {d.hostname ? <b>{d.hostname}</b> : d.destination_ip}
                  <span className="topo-hover-proc-meta">
                    {d.hostname ? ` (${d.destination_ip})` : ''}{d.destination_port ? `:${d.destination_port}` : ''} · {d.count}x · {fmtRelative(d.last_seen)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  )
}

function AssetNode({ id, data }) {
  const [hovered, setHovered] = useState(false)
  const [destinations, setDestinations] = useState(null)
  const [cardPos, setCardPos] = useState(null)
  const nodeRef = useRef(null)
  const { x: vpX, y: vpY, zoom } = useViewport()
  const color = STATUS_COLOR[data.status] || STATUS_COLOR.healthy
  const activityLevel = Math.min((data.activity || 0) / 12, 1)
  const online = data.is_dynamic ? (Date.now() - new Date(data.last_seen || 0).getTime()) < 12000 : null
  const pinned = data.pinned
  const showCard = hovered || pinned

  // Hover card is portaled to document.body (see render below) so it can't be
  // clipped by reactflow's overflow:hidden container or buried under a sibling
  // node's stacking context — both of which happened when it rendered inline.
  // Re-measured (not just computed once) whenever shown or the viewport pans/zooms,
  // so a pinned card stays glued to its node instead of drifting.
  const updateCardPosition = useCallback(() => {
    const rect = nodeRef.current?.getBoundingClientRect()
    if (!rect) return
    let left = rect.left + rect.width / 2 - HOVER_CARD_WIDTH / 2
    left = Math.min(Math.max(left, 8), window.innerWidth - HOVER_CARD_WIDTH - 8)
    const opensBelow = rect.bottom + HOVER_CARD_EST_HEIGHT + 8 <= window.innerHeight
    const top = opensBelow ? rect.bottom + 8 : Math.max(8, rect.top - HOVER_CARD_EST_HEIGHT - 8)
    setCardPos({ left, top })
  }, [])

  useEffect(() => {
    if (showCard) updateCardPosition()
  }, [showCard, vpX, vpY, zoom, updateCardPosition])

  // Lazy-fetch "sites accessed" only once actually shown (debounced so a quick
  // mouse pass-through doesn't fire a request), cached briefly per asset so
  // re-showing the same node right after doesn't refetch.
  useEffect(() => {
    if (!showCard || !data.asset_id) return undefined
    const cached = _destinationsCache.get(data.asset_id)
    if (cached && Date.now() - cached.ts < DESTINATIONS_CACHE_TTL_MS) {
      setDestinations(cached.data)
      return undefined
    }
    setDestinations(null)
    let cancelled = false
    const t = setTimeout(() => {
      api.getAssetDestinations(data.asset_id).then((d) => {
        if (cancelled) return
        _destinationsCache.set(data.asset_id, { data: d, ts: Date.now() })
        setDestinations(d)
      }).catch(() => { if (!cancelled) setDestinations([]) })
    }, 200)
    return () => { cancelled = true; clearTimeout(t) }
  }, [showCard, data.asset_id])

  function handleClick(e) {
    e.stopPropagation()
    data.onTogglePin?.(id)
  }

  return (
    <div
      ref={nodeRef}
      className={[
        'topo-node',
        data.isExternal && 'topo-node-external',
        data.highlighted && 'topo-node-highlighted',
        data.status === 'compromised' && 'topo-node-pulse',
        data.role === 'attacker' && 'topo-node-attacker',
        data.is_dynamic && 'topo-node-dynamic',
        online === false && 'topo-node-offline',
        pinned && 'topo-node-pinned',
      ].filter(Boolean).join(' ')}
      style={{ borderColor: color, '--activity': activityLevel, cursor: 'pointer' }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={handleClick}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      {activityLevel > 0.05 && <div className="topo-node-activity-ring" />}
      <div className="topo-node-top">
        <span className="topo-node-type">{TYPE_LABEL[data.asset_type] || '—'}</span>
        <span className="topo-node-dot" style={{ background: color }} />
      </div>
      <div className="topo-node-name">{data.name}</div>
      <div className="topo-node-ip">{data.ip_address || (data.isExternal ? 'unknown source' : '—')}</div>
      {data.is_dynamic && (
        <div className="topo-node-badges">
          <span className="topo-role-badge topo-role-live">LIVE</span>
          {data.role !== 'unknown' && (
            <span className={`topo-role-badge topo-role-${data.role}`}>{data.role}</span>
          )}
        </div>
      )}
      {showCard && cardPos && createPortal(
        <HoverCard
          data={data}
          destinations={destinations}
          position={cardPos}
          pinned={pinned}
          onClose={(e) => { e.stopPropagation(); data.onTogglePin?.(id) }}
        />,
        document.body,
      )}
    </div>
  )
}

function PacketOverlay({ dots, onDone }) {
  const { x, y, zoom } = useViewport()
  return (
    <div className="topo-packet-layer">
      <div className="topo-packet-viewport" style={{ transform: `translate(${x}px, ${y}px) scale(${zoom})` }}>
        {dots.map((d) => (
          <div
            key={d.id}
            className={`packet-dot${d.malicious ? ' packet-dot-malicious' : ''}`}
            style={{
              '--x0': `${d.x0}px`, '--y0': `${d.y0}px`,
              '--x1': `${d.x1}px`, '--y1': `${d.y1}px`,
              '--dot-color': d.color, '--dot-size': `${d.size}px`,
              animationDuration: `${d.duration}ms`,
            }}
            onAnimationEnd={() => onDone(d.id)}
          />
        ))}
      </div>
    </div>
  )
}

const NODE_TYPES = { assetNode: AssetNode }

/**
 * Renders the (mix of seeded-demo + real agent-reported) topology as a node-link
 * graph. Node color = asset status (STATUS_COLOR reuses the severity tokens).
 * `selectedIncident`, if given, highlights its affected_assets and draws a pulsing
 * directed attack path. `packets`, if given, is a live buffer of recent
 * {src_ip,dst_ip,...} events (SSE "packet" channel) animated as traveling dots —
 * driven by a CSS keyframe (see index.css .packet-dot), not per-edge SVG, so it
 * works between ANY two resolvable nodes regardless of whether a topology edge
 * connects them (this matters once two friends' laptops start talking directly).
 * `hotSourceIps`, if given, is a Set of IPs recently implicated in a Detection —
 * packets from them render as visibly "compromising" traffic.
 */
export default function NetworkTopologyMap({ assets = [], edges = [], selectedIncident = null, packets = [], hotSourceIps = null, height = 420 }) {
  const [activeDots, setActiveDots] = useState([])
  const [nodeActivity, setNodeActivity] = useState({})
  const [pinnedAssetId, setPinnedAssetId] = useState(null)
  const lastConsumedId = useRef(0)
  const activityLog = useRef({}) // assetId -> [timestamps]
  const dotSeq = useRef(0)

  const handleTogglePin = useCallback((nodeId) => {
    setPinnedAssetId((prev) => (prev === nodeId ? null : nodeId))
  }, [])

  const { nodes, ipToAssetId } = useMemo(() => {
    const ipToAssetId = {}
    for (const a of assets) if (a.ip_address) ipToAssetId[a.ip_address] = a.asset_id

    const affected = new Set(selectedIncident?.affected_assets || [])
    const nodes = assets.map((a) => ({
      id: a.asset_id,
      type: 'assetNode',
      position: { x: a.position_x, y: a.position_y },
      data: { ...a, highlighted: affected.has(a.asset_id) },
      draggable: false,
    }))

    // Frontend-only visual affordance (not a real Asset row) for anything outside the
    // enterprise — always present so attacker/C2/internet traffic (which never matches
    // a real asset IP) has somewhere to animate to/from.
    nodes.push({
      id: EXTERNAL_ID,
      type: 'assetNode',
      position: { x: -240, y: 200 },
      data: { name: 'INTERNET / EXTERNAL', asset_type: 'external', status: 'healthy', isExternal: true, highlighted: false },
      draggable: false,
    })

    return { nodes, ipToAssetId }
  }, [assets, selectedIncident])

  const baseEdges = useMemo(() => {
    const firewall = assets.find((a) => a.asset_type === 'firewall')
    const dmzAssets = assets.filter((a) => a.zone === 'dmz')
    const syntheticExternal = [firewall, ...dmzAssets].filter(Boolean).map((a, i) => ({
      id: `ext-${i}`, source: EXTERNAL_ID, target: a.asset_id, type: 'default',
      style: { stroke: 'var(--border)', strokeWidth: 1, strokeDasharray: '3 3' },
    }))
    const real = edges.map((e, i) => ({
      id: `edge-${i}`, source: e.source_asset_id, target: e.target_asset_id, type: 'default',
      style: { stroke: 'var(--border)', strokeWidth: 1.2 },
    }))

    const pathEdges = []
    if (selectedIncident) {
      const firstSourceIp = (selectedIncident.entities?.source_ips || [])[0]
      const path = [
        ...(firstSourceIp && !ipToAssetId[firstSourceIp] ? [EXTERNAL_ID] : []),
        ...(selectedIncident.affected_assets || []),
      ]
      for (let i = 0; i < path.length - 1; i++) {
        pathEdges.push({
          id: `path-${i}`, source: path[i], target: path[i + 1], type: 'straight', animated: true,
          style: { stroke: 'var(--sev-critical)', strokeWidth: 2.5 },
          markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--sev-critical)' },
        })
      }
    }

    return [...real, ...syntheticExternal, ...pathEdges]
  }, [assets, edges, selectedIncident, ipToAssetId])

  const nodeCenter = useMemo(() => {
    const map = {}
    for (const n of nodes) map[n.id] = { x: n.position.x + NODE_W / 2, y: n.position.y + NODE_H / 2 }
    return map
  }, [nodes])

  // Consume newly-arrived packets (already throttled/batched by the parent) into
  // traveling dots + per-node activity counters. Tracked by monotonic id, not array
  // length, since the parent buffer is capped and truncates old entries from the front.
  useEffect(() => {
    const fresh = packets.filter((p) => p.id > lastConsumedId.current)
    if (fresh.length === 0) return
    lastConsumedId.current = Math.max(...fresh.map((p) => p.id), lastConsumedId.current)

    const now = Date.now()
    const newDots = []
    for (const p of fresh) {
      const srcId = ipToAssetId[p.src_ip] || EXTERNAL_ID
      const dstId = ipToAssetId[p.dst_ip] || EXTERNAL_ID
      if (srcId === EXTERNAL_ID && dstId === EXTERNAL_ID) continue
      const from = nodeCenter[srcId]
      const to = nodeCenter[dstId]
      if (!from || !to) continue

      for (const id of [srcId, dstId]) {
        const log = activityLog.current[id] || (activityLog.current[id] = [])
        log.push(now)
      }

      const malicious = Boolean(hotSourceIps?.has(p.src_ip)) || (p.severity && p.severity !== 'info' && p.kind !== 'background')
      newDots.push({
        id: `dot-${dotSeq.current++}`,
        x0: from.x, y0: from.y, x1: to.x, y1: to.y,
        color: malicious ? 'var(--sev-critical)' : severityDotColor(p.severity),
        size: malicious ? 6 : (p.kind === 'background' ? 3 : 4.5),
        duration: 650 + Math.random() * 250,
        malicious,
        createdAt: now,
      })
    }
    if (newDots.length > 0) {
      setActiveDots((prev) => {
        const next = [...prev, ...newDots]
        return next.length > MAX_ACTIVE_DOTS ? next.slice(next.length - MAX_ACTIVE_DOTS) : next
      })
    }
  }, [packets, ipToAssetId, nodeCenter, hotSourceIps])

  // Recompute per-node activity counts (for the pulse ring + hover card) on a fixed tick.
  useEffect(() => {
    const t = setInterval(() => {
      const now = Date.now()
      const counts = {}
      let changed = false
      for (const [id, log] of Object.entries(activityLog.current)) {
        const kept = log.filter((ts) => now - ts < ACTIVITY_WINDOW_MS)
        activityLog.current[id] = kept
        if (kept.length > 0) counts[id] = kept.length
      }
      setNodeActivity((prev) => {
        const prevKeys = Object.keys(prev)
        if (prevKeys.length !== Object.keys(counts).length) changed = true
        else for (const k of prevKeys) if (prev[k] !== counts[k]) { changed = true; break }
        return changed ? counts : prev
      })
    }, 400)
    return () => clearInterval(t)
  }, [])

  const removeDot = (id) => setActiveDots((prev) => prev.filter((d) => d.id !== id))

  // Safety-net pruning: onAnimationEnd normally removes a dot, but that event never
  // fires under `prefers-reduced-motion` (no animation plays) or a backgrounded tab —
  // without this, dots would accumulate forever in those cases.
  useEffect(() => {
    const t = setInterval(() => {
      const cutoff = Date.now() - PACKET_TTL_MS
      setActiveDots((prev) => {
        const kept = prev.filter((d) => d.createdAt > cutoff)
        return kept.length === prev.length ? prev : kept
      })
    }, 300)
    return () => clearInterval(t)
  }, [])

  const renderedNodes = useMemo(
    () => nodes.map((n) => ({
      ...n,
      data: { ...n.data, activity: nodeActivity[n.id] || 0, pinned: n.id === pinnedAssetId, onTogglePin: handleTogglePin },
    })),
    [nodes, nodeActivity, pinnedAssetId, handleTogglePin],
  )

  return (
    <div className="topo-map" style={{ height }}>
      <ReactFlow
        nodes={renderedNodes}
        edges={baseEdges}
        nodeTypes={NODE_TYPES}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        proOptions={{ hideAttribution: true }}
        nodesConnectable={false}
        elementsSelectable={false}
        onPaneClick={() => setPinnedAssetId(null)}
      >
        <Background color="var(--border-soft)" gap={24} />
        <Controls showInteractive={false} />
        <MiniMap
          pannable zoomable
          nodeColor={(n) => STATUS_COLOR[n.data?.status] || STATUS_COLOR.healthy}
          maskColor="rgba(12,14,19,0.7)"
          style={{ background: 'var(--bg-inset)' }}
        />
        <PacketOverlay dots={activeDots} onDone={removeDot} />
      </ReactFlow>
    </div>
  )
}

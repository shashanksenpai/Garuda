import { useEffect, useState } from 'react'
import { api } from '../api.js'

const ROLES = ['unknown', 'enterprise', 'attacker']

function fmtRelative(iso) {
  if (!iso) return 'never'
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 5) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  return m < 60 ? `${m}m ago` : `${Math.round(m / 60)}h ago`
}

function DestinationsList({ assetId }) {
  const [destinations, setDestinations] = useState(null)

  useEffect(() => {
    let cancelled = false
    api.getAssetDestinations(assetId).then((d) => { if (!cancelled) setDestinations(d) }).catch(() => { if (!cancelled) setDestinations([]) })
    return () => { cancelled = true }
  }, [assetId])

  if (destinations === null) return <div className="empty-hint" style={{ padding: '4px 0', textAlign: 'left' }}>loading…</div>
  if (destinations.length === 0) return <div className="empty-hint" style={{ padding: '4px 0', textAlign: 'left' }}>No outbound connections observed yet.</div>
  return (
    <ul className="fleet-destinations-list">
      {destinations.slice(0, 10).map((d, i) => (
        <li key={i}>
          {d.hostname ? <b>{d.hostname}</b> : d.destination_ip}
          <span className="topo-hover-proc-meta">
            {d.hostname ? ` (${d.destination_ip})` : ''}{d.destination_port ? `:${d.destination_port}` : ''} · {d.protocol} · {d.count}x · {fmtRelative(d.last_seen)}
          </span>
        </li>
      ))}
    </ul>
  )
}

function AgentCard({ agent: a, onSetRole }) {
  const [expanded, setExpanded] = useState(false)
  const online = a.last_seen && (Date.now() - new Date(a.last_seen).getTime()) < 12000
  const reasons = a.attack_reasons || []
  const latestReason = reasons[reasons.length - 1]

  return (
    <div className="action-card">
      <div className="action-card-top">
        <span className="action-card-title">
          <span className={`fleet-online-dot ${online ? 'on' : ''}`} />
          {a.name}
        </span>
        <span className="status-tag">{a.status}</span>
      </div>
      <div className="action-card-meta">
        {a.ip_address} · {a.current_user || 'unknown user'} · {a.os_info || 'unknown OS'} · {fmtRelative(a.last_seen)}
      </div>
      {a.role === 'attacker' && latestReason && (
        <div className="action-card-reason">
          Flagged: <b>{latestReason.threat_type}</b>{latestReason.mitre_technique_id ? ` (${latestReason.mitre_technique_id})` : ''} — {latestReason.evidence}
        </div>
      )}
      <div className="action-card-buttons">
        {ROLES.map((r) => (
          <button
            key={r}
            className={`live-btn fleet-role-btn ${a.role === r ? `fleet-role-active-${r}` : ''}`}
            onClick={() => onSetRole(a.asset_id, r)}
          >
            {r}
          </button>
        ))}
      </div>
      <button className="live-btn" style={{ width: '100%', marginTop: 8 }} onClick={() => setExpanded((e) => !e)}>
        {expanded ? 'Hide sites accessed' : 'Show sites accessed'}
      </button>
      {expanded && <DestinationsList assetId={a.asset_id} />}
    </div>
  )
}

/**
 * "Connect a device" helper (LAN address + ready-to-paste agent command) plus the
 * live roster of laptops actually running agent/garuda_agent.py — with a manual
 * role override for self-declaring who's posing as the enterprise vs the attacker,
 * alongside GARUDA's own auto-detected role.
 */
export default function FleetPanel({ agents = [], onSetRole }) {
  const [connectInfo, setConnectInfo] = useState(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    api.getConnectInfo().then(setConnectInfo).catch(() => {})
  }, [])

  const command = connectInfo?.lan_ip
    ? `python garuda_agent.py join --server http://${connectInfo.lan_ip}:${connectInfo.port} --name "Your-Laptop"`
    : null

  function copyCommand() {
    if (!command) return
    navigator.clipboard.writeText(command).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }).catch(() => {})
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">CONNECTED DEVICES</span>
        <span className="status-tag">{agents.length} joined</span>
      </div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div className="fleet-connect-card">
          <div className="detail-label" style={{ marginBottom: 4 }}>CONNECT A LAPTOP</div>
          <div className="empty-hint" style={{ padding: 0, textAlign: 'left', marginBottom: 6 }}>
            Run this on a friend's laptop (needs <code>agent/requirements.txt</code> installed):
          </div>
          <code className="fleet-command">{command || 'resolving LAN address…'}</code>
          <button className="live-btn" style={{ marginTop: 6, width: '100%' }} onClick={copyCommand} disabled={!command}>
            {copied ? 'Copied' : 'Copy command'}
          </button>
        </div>

        {agents.length === 0 && <div className="empty-hint">No live devices yet — waiting for someone to join.</div>}
        {agents.map((a) => <AgentCard key={a.asset_id} agent={a} onSetRole={onSetRole} />)}
      </div>
    </div>
  )
}

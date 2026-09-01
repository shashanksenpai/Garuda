import { useEffect, useMemo, useRef, useState } from 'react'
import NetworkTopologyMap from './NetworkTopologyMap.jsx'
import RiskGauge from './RiskGauge.jsx'
import SeverityChip from './SeverityChip.jsx'
import { api } from '../api.js'

const IP_RE = /\d{1,3}(?:\.\d{1,3}){3}/g
const SPEEDS = [0.5, 1, 2, 4]
const BASE_INTERVAL_MS = 2400

function extractIps(text) {
  return [...new Set((text || '').match(IP_RE) || [])]
}

function fmtTime(ts) {
  try { return new Date(ts).toLocaleTimeString([], { hour12: false }) } catch { return ts }
}

/**
 * Full-screen stakeholder presentation / replay mode for one incident. Scrubs
 * through incident.timeline (real stored entries — nothing invented), animating
 * each stage onto the topology map, and ends on a summary card built from the
 * same risk score / MITRE techniques / investigation_summary already on the
 * incident.
 */
export default function PresentMode({ incident, assets, edges, onClose }) {
  const timeline = incident.timeline || []
  const totalSteps = timeline.length + 1 // last index = summary card
  const [step, setStep] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const [copied, setCopied] = useState(false)
  const timerRef = useRef(null)

  useEffect(() => {
    if (!playing) return undefined
    timerRef.current = setInterval(() => {
      setStep((s) => {
        if (s >= totalSteps - 1) {
          setPlaying(false)
          return s
        }
        return s + 1
      })
    }, BASE_INTERVAL_MS / speed)
    return () => clearInterval(timerRef.current)
  }, [playing, speed, totalSteps])

  useEffect(() => {
    function onKey(e) {
      if (e.key === 'Escape') onClose()
      if (e.key === ' ') { e.preventDefault(); setPlaying((p) => !p) }
      if (e.key === 'ArrowRight') setStep((s) => Math.min(s + 1, totalSteps - 1))
      if (e.key === 'ArrowLeft') setStep((s) => Math.max(s - 1, 0))
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, totalSteps])

  const isSummary = step >= timeline.length
  const currentEntry = !isSummary ? timeline[step] : null

  const pseudoIncident = useMemo(() => {
    const ipToAssetId = {}
    for (const a of assets) if (a.ip_address) ipToAssetId[a.ip_address] = a.asset_id
    const path = []
    const upTo = isSummary ? timeline.length - 1 : step
    for (let i = 0; i <= upTo && i < timeline.length; i++) {
      for (const ip of extractIps(timeline[i].description)) {
        const assetId = ipToAssetId[ip]
        if (assetId && !path.includes(assetId)) path.push(assetId)
      }
    }
    return { entities: incident.entities, affected_assets: path }
  }, [assets, timeline, step, isSummary, incident.entities])

  async function copySummary() {
    try {
      const { markdown } = await api.getIncidentSummary(incident.incident_id)
      await navigator.clipboard.writeText(markdown)
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    } catch {
      // clipboard access can be denied by the browser — fail silently, button stays actionable
    }
  }

  const actions = incident.recommended_actions || {}

  return (
    <div className="present-overlay">
      <div className="present-header">
        <span className="brand-sub" style={{ borderLeft: 'none', paddingLeft: 0 }}>PRESENT MODE — {incident.title}</span>
        <button className="live-btn" onClick={onClose}>Close (Esc)</button>
      </div>

      <div className="present-map">
        <NetworkTopologyMap assets={assets} edges={edges} selectedIncident={pseudoIncident} height="100%" />
      </div>

      {!isSummary ? (
        <div className="present-caption">
          <SeverityChip severity={currentEntry.severity} />
          <span className="present-caption-time">{fmtTime(currentEntry.timestamp)}</span>
          <span className="present-caption-text">{currentEntry.description}</span>
        </div>
      ) : (
        <div className="present-summary">
          <RiskGauge score={incident.risk_score} severity={incident.severity} />
          <div className="chip-row" style={{ justifyContent: 'center', margin: '8px 0' }}>
            {(incident.attack_techniques || []).map((t) => (
              <span className="tech-chip" key={t.id}><b>{t.id}</b> {t.name}</span>
            ))}
          </div>
          <p className="detail-summary" style={{ textAlign: 'center', maxWidth: 720, margin: '0 auto' }}>
            {incident.investigation_summary}
          </p>
          <div className="chip-row" style={{ justifyContent: 'center', marginTop: 10 }}>
            {(actions.immediate || []).slice(0, 3).map((a, i) => (
              <span className="tech-chip" key={i}>{a}</span>
            ))}
          </div>
          <button className="report-btn" style={{ maxWidth: 280, margin: '16px auto 0' }} onClick={copySummary}>
            {copied ? 'Copied to clipboard' : 'Copy shareable summary'}
          </button>
        </div>
      )}

      <div className="present-scrubber">
        <button className="live-btn" onClick={() => { setPlaying(false); setStep((s) => Math.max(s - 1, 0)) }}>⏮</button>
        <button className="live-btn" onClick={() => setPlaying((p) => !p)}>{playing ? '⏸ Pause' : '▶ Play'}</button>
        <button className="live-btn" onClick={() => { setPlaying(false); setStep((s) => Math.min(s + 1, totalSteps - 1)) }}>⏭</button>
        <input
          type="range" min={0} max={totalSteps - 1} value={step}
          onChange={(e) => { setPlaying(false); setStep(Number(e.target.value)) }}
          className="present-scrub-range"
        />
        <select className="live-select" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
          {SPEEDS.map((s) => <option key={s} value={s}>{s}x</option>)}
        </select>
        <span className="status-tag">{isSummary ? 'Summary' : `Stage ${step + 1}/${timeline.length}`}</span>
      </div>
    </div>
  )
}

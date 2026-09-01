import { useCallback, useEffect, useRef, useState } from 'react'
import TopBar from './components/TopBar.jsx'
import LiveEventStream from './components/LiveEventStream.jsx'
import IncidentList from './components/IncidentList.jsx'
import IncidentDetail from './components/IncidentDetail.jsx'
import StatusCharts from './components/StatusCharts.jsx'
import NetworkTopologyMap from './components/NetworkTopologyMap.jsx'
import PacketFlow from './components/PacketFlow.jsx'
import ResponseConsole from './components/ResponseConsole.jsx'
import FleetPanel from './components/FleetPanel.jsx'
import PresentMode from './components/PresentMode.jsx'
import { api } from './api.js'
import { useLiveStream } from './useLiveStream.js'

const MAX_STREAM_ITEMS = 200
const MAX_PACKET_ITEMS = 250
const PACKET_FLUSH_MS = 200
const HOT_IP_TTL_MS = 9000

function upsertById(list, item, idKey) {
  const idx = list.findIndex((x) => x[idKey] === item[idKey])
  if (idx === -1) return [item, ...list]
  const next = [...list]
  next[idx] = item
  return next
}

export default function App() {
  const [status, setStatus] = useState(null)
  const [incidents, setIncidents] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [selectedDetail, setSelectedDetail] = useState(null)
  const [streamItems, setStreamItems] = useState([])
  const [scenarios, setScenarios] = useState([])
  const [scenario, setScenario] = useState('multi_stage_attack')
  const [running, setRunning] = useState(false)

  const [view, setView] = useState('console')
  const [topologyAssets, setTopologyAssets] = useState([])
  const [topologyEdges, setTopologyEdges] = useState([])
  const [pendingActions, setPendingActions] = useState([])
  const [auditLog, setAuditLog] = useState([])
  const [policy, setPolicy] = useState(null)
  const [packets, setPackets] = useState([])
  const [presentIncident, setPresentIncident] = useState(null)
  const [hotSourceIps, setHotSourceIps] = useState(new Set())

  const selectedIdRef = useRef(selectedId)
  selectedIdRef.current = selectedId
  const packetBufferRef = useRef([])
  const packetSeqRef = useRef(0)
  const hotIpExpiryRef = useRef(new Map())

  const refreshStatus = useCallback(() => {
    api.getStatus().then(setStatus).catch(() => {})
  }, [])

  const selectIncident = useCallback((id) => {
    setSelectedId(id)
    api.getIncident(id).then(setSelectedDetail).catch(() => {})
  }, [])

  // Initial load
  useEffect(() => {
    api.getScenarios().then((r) => setScenarios(r.scenarios)).catch(() => {})
    api.getStatus().then((s) => { setStatus(s); setRunning(s.live_mode_running) }).catch(() => {})
    api.getIncidents().then((list) => {
      setIncidents(list)
      if (list.length > 0) selectIncident(list[0].incident_id)
    }).catch(() => {})
    api.getEvents(150).then((evts) => {
      setStreamItems(evts.map((e) => ({
        id: e.event_id, timestamp: e.timestamp, severity: e.severity, message: e.message, kind: 'event',
      })))
    }).catch(() => {})
    api.getTopology().then((t) => { setTopologyAssets(t.assets); setTopologyEdges(t.edges) }).catch(() => {})
    api.getPendingActions().then(setPendingActions).catch(() => {})
    api.getAuditLog().then(setAuditLog).catch(() => {})
    api.getPolicy().then(setPolicy).catch(() => {})
  }, [selectIncident])

  // Throttles the packet SSE stream (which can arrive several times a second) down to
  // a fixed render cadence so the topology/packet-flow views never re-render per frame.
  useEffect(() => {
    const t = setInterval(() => {
      if (packetBufferRef.current.length === 0) return
      const batch = packetBufferRef.current
      packetBufferRef.current = []
      setPackets((prev) => {
        const next = [...prev, ...batch]
        return next.length > MAX_PACKET_ITEMS ? next.slice(next.length - MAX_PACKET_ITEMS) : next
      })
    }, PACKET_FLUSH_MS)
    return () => clearInterval(t)
  }, [])

  // Recomputes the "recently implicated as an attack source" IP set (drives the
  // malicious-packet flavoring on the topology map + packet table) from Detection
  // SSE messages, each held "hot" for HOT_IP_TTL_MS.
  useEffect(() => {
    const t = setInterval(() => {
      const now = Date.now()
      let changed = false
      for (const [ip, expiry] of hotIpExpiryRef.current) {
        if (expiry <= now) { hotIpExpiryRef.current.delete(ip); changed = true }
      }
      if (changed) setHotSourceIps(new Set(hotIpExpiryRef.current.keys()))
    }, 1000)
    return () => clearInterval(t)
  }, [])

  // Live pipeline messages
  useLiveStream((msg) => {
    if (msg.type === 'event') {
      const e = msg.data
      setStreamItems((prev) => [
        ...prev.slice(-MAX_STREAM_ITEMS + 1),
        { id: e.event_id, timestamp: e.timestamp, severity: e.severity, message: e.message, kind: 'event' },
      ])
      setStatus((s) => (s ? { ...s, total_events: s.total_events + 1 } : s))
    } else if (msg.type === 'detection') {
      const d = msg.data
      setStreamItems((prev) => [
        ...prev.slice(-MAX_STREAM_ITEMS + 1),
        { id: d.detection_id, timestamp: d.timestamp, severity: d.severity, message: d.evidence, title: `${d.threat_type} detected`, kind: 'detection' },
      ])
      if (d.source_ip) {
        hotIpExpiryRef.current.set(d.source_ip, Date.now() + HOT_IP_TTL_MS)
        setHotSourceIps(new Set(hotIpExpiryRef.current.keys()))
      }
    } else if (msg.type === 'incident_update') {
      const inc = msg.data
      setIncidents((prev) => {
        const idx = prev.findIndex((i) => i.incident_id === inc.incident_id)
        const summary = {
          incident_id: inc.incident_id, created_at: inc.created_at, updated_at: inc.updated_at,
          title: inc.title, severity: inc.severity, risk_score: inc.risk_score,
          investigation_status: inc.investigation_status,
        }
        if (idx === -1) return [summary, ...prev]
        const next = [...prev]
        next[idx] = summary
        return next
      })
      if (selectedIdRef.current === inc.incident_id) {
        setSelectedDetail(inc)
      } else if (selectedIdRef.current === null) {
        selectIncident(inc.incident_id)
      }
      refreshStatus()
    } else if (msg.type === 'scenario_started') {
      setRunning(true)
    } else if (msg.type === 'scenario_finished') {
      setRunning(false)
      refreshStatus()
    } else if (msg.type === 'asset_update') {
      setTopologyAssets((prev) => upsertById(prev, msg.data, 'asset_id'))
    } else if (msg.type === 'action_pending') {
      setPendingActions((prev) => upsertById(prev, msg.data, 'action_id'))
      setAuditLog((prev) => upsertById(prev, msg.data, 'action_id'))
    } else if (msg.type === 'action_executed' || msg.type === 'action_rejected' || msg.type === 'action_rolled_back') {
      setPendingActions((prev) => prev.filter((a) => a.action_id !== msg.data.action_id))
      setAuditLog((prev) => upsertById(prev, msg.data, 'action_id'))
    } else if (msg.type === 'packet') {
      packetSeqRef.current += 1
      packetBufferRef.current.push({ ...msg.data, id: packetSeqRef.current })
    }
  })

  function handleStart() {
    api.startLive(scenario, 6).then(() => setRunning(true)).catch(() => {})
  }
  function handleStop() {
    api.stopLive().then(() => setRunning(false)).catch(() => {})
  }

  function handleApprove(id) { api.approveAction(id).catch(() => {}) }
  function handleReject(id) { api.rejectAction(id).catch(() => {}) }
  function handleRollback(id) { api.rollbackAction(id).catch(() => {}) }
  function handlePolicyChange(patch) { api.updatePolicy(patch).then(setPolicy).catch(() => {}) }
  function handleSetRole(assetId, role) { api.setAssetRole(assetId, role).catch(() => {}) }

  const liveAgents = topologyAssets.filter((a) => a.is_dynamic)

  return (
    <div className="app-shell">
      <TopBar
        view={view}
        onViewChange={setView}
        status={status}
        scenarios={scenarios}
        running={running}
        scenario={scenario}
        onScenarioChange={setScenario}
        onStart={handleStart}
        onStop={handleStop}
      />
      {view === 'console' ? (
        <div className="main-grid">
          <div className="col">
            <LiveEventStream items={streamItems} />
          </div>
          <div className="col">
            <StatusCharts
              severityDist={status?.severity_distribution}
              threatDist={status?.threat_distribution}
            />
            <IncidentList incidents={incidents} selectedId={selectedId} onSelect={selectIncident} />
          </div>
          <div className="col">
            <IncidentDetail incident={selectedDetail} onPresent={setPresentIncident} />
          </div>
        </div>
      ) : (
        <div className="main-grid topology-grid">
          <div className="col topology-col">
            <div className="panel" style={{ flex: '2 1 0', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
              <div className="panel-header">
                <span className="panel-title">NETWORK TOPOLOGY</span>
                {selectedDetail && <span className="status-tag">highlighting: {selectedDetail.title}</span>}
              </div>
              <NetworkTopologyMap
                assets={topologyAssets}
                edges={topologyEdges}
                selectedIncident={selectedDetail}
                packets={packets}
                hotSourceIps={hotSourceIps}
                height="100%"
              />
            </div>
            <PacketFlow packets={packets} hotSourceIps={hotSourceIps} />
          </div>
          <div className="col">
            <FleetPanel agents={liveAgents} onSetRole={handleSetRole} />
            <ResponseConsole
              pendingActions={pendingActions}
              auditLog={auditLog}
              policy={policy}
              onApprove={handleApprove}
              onReject={handleReject}
              onRollback={handleRollback}
              onPolicyChange={handlePolicyChange}
            />
          </div>
        </div>
      )}

      {presentIncident && (
        <PresentMode
          incident={presentIncident}
          assets={topologyAssets}
          edges={topologyEdges}
          onClose={() => setPresentIncident(null)}
        />
      )}
    </div>
  )
}

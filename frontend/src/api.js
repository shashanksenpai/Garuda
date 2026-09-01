const BASE = '/api'

async function j(res) {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

function post(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  }).then(j)
}

export const api = {
  getStatus: () => fetch(`${BASE}/status`).then(j),
  getIncidents: () => fetch(`${BASE}/incidents`).then(j),
  getIncident: (id) => fetch(`${BASE}/incidents/${id}`).then(j),
  getIncidentSummary: (id) => fetch(`${BASE}/incidents/${id}/summary`).then(j),
  getEvents: (limit = 150) => fetch(`${BASE}/events?limit=${limit}`).then(j),
  getScenarios: () => fetch(`${BASE}/scenarios`).then(j),
  startLive: (scenario, speed = 6) =>
    fetch(`${BASE}/logs/start-live`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario, speed }),
    }).then(j),
  stopLive: () => fetch(`${BASE}/logs/stop-live`, { method: 'POST' }).then(j),
  reportUrl: (id) => `${BASE}/incidents/${id}/report`,

  getTopology: () => fetch(`${BASE}/topology`).then(j),

  getPendingActions: () => fetch(`${BASE}/actions/pending`).then(j),
  getAuditLog: () => fetch(`${BASE}/actions/audit-log`).then(j),
  approveAction: (id) => post(`${BASE}/actions/${id}/approve`),
  rejectAction: (id) => post(`${BASE}/actions/${id}/reject`),
  rollbackAction: (id) => post(`${BASE}/actions/${id}/rollback`),

  getPolicy: () => fetch(`${BASE}/policy`).then(j),
  updatePolicy: (patch) =>
    fetch(`${BASE}/policy`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }).then(j),

  getConnectInfo: () => fetch(`${BASE}/agents/connect-info`).then(j),
  setAssetRole: (assetId, role) =>
    fetch(`${BASE}/topology/assets/${assetId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role }),
    }).then(j),
  getAssetDestinations: (assetId) => fetch(`${BASE}/topology/assets/${assetId}/destinations`).then(j),
}

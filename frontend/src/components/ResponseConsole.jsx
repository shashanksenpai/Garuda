import SeverityChip from './SeverityChip.jsx'

const MODES = ['manual', 'hybrid', 'auto']
const CRITICALITIES = ['low', 'medium', 'high', 'critical']
const ACTION_LABEL = {
  block_ip: 'Block IP', isolate_host: 'Isolate Host', disable_account: 'Disable Account',
  kill_session: 'Kill Session', alert_soc: 'Alert SOC', rate_limit: 'Rate Limit',
}

function describeParams(action) {
  const p = action.params || {}
  if (p.ip_addresses) return `IP(s): ${p.ip_addresses.join(', ')}`
  if (p.hostnames) return `Host(s): ${p.hostnames.join(', ')}`
  if (p.usernames) return `User(s): ${p.usernames.join(', ')}`
  return '—'
}

function fmtTime(ts) {
  try { return new Date(ts).toLocaleTimeString([], { hour12: false }) } catch { return ts }
}

const STATUS_CLASS = { pending: 'medium', executed: 'low', rejected: 'info', rolled_back: 'info' }

function ActionStatusTag({ status }) {
  return <span className={`sev-chip sev-${STATUS_CLASS[status] || 'info'}`}><span className="sev-dot" />{status.replace('_', ' ').toUpperCase()}</span>
}

/**
 * Response Console: pending-approval queue, policy settings (manual/hybrid/auto,
 * globally and per target-asset-criticality), and a running audit log of every
 * action the response engine has executed, queued, rejected, or rolled back.
 *
 * Everything here operates only on GARUDA's own simulated asset inventory
 * (see backend/app/response_engine.py) — it never reaches real infrastructure.
 */
export default function ResponseConsole({ pendingActions = [], auditLog = [], policy, onApprove, onReject, onRollback, onPolicyChange }) {
  return (
    <>
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">PENDING APPROVALS</span>
          <span className="status-tag">{pendingActions.length} pending</span>
        </div>
        <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {pendingActions.length === 0 && <div className="empty-hint">Nothing awaiting analyst approval.</div>}
          {pendingActions.map((a) => (
            <div className="action-card" key={a.action_id}>
              <div className="action-card-top">
                <span className="action-card-title">{ACTION_LABEL[a.action] || a.action}</span>
                <span className="status-tag">{a.mode}</span>
              </div>
              <div className="action-card-meta">{describeParams(a)}</div>
              {a.reason && <div className="action-card-reason">{a.reason}</div>}
              <div className="action-card-buttons">
                <button className="live-btn" onClick={() => onApprove(a.action_id)}>Approve</button>
                <button className="live-btn stop" onClick={() => onReject(a.action_id)}>Reject</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="panel-header"><span className="panel-title">RESPONSE POLICY</span></div>
        <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div>
            <div className="detail-label" style={{ marginBottom: 6 }}>DEFAULT MODE</div>
            <select
              className="live-select" style={{ width: '100%' }}
              value={policy?.default_mode || 'manual'}
              onChange={(e) => onPolicyChange({ default_mode: e.target.value })}
            >
              {MODES.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>

          <div>
            <div className="detail-label" style={{ marginBottom: 6 }}>AUTO-MODE SEVERITY CEILING</div>
            <select
              className="live-select" style={{ width: '100%' }}
              value={policy?.auto_severity_ceiling || 'high'}
              onChange={(e) => onPolicyChange({ auto_severity_ceiling: e.target.value })}
            >
              {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            <div className="empty-hint" style={{ padding: '4px 0 0', textAlign: 'left' }}>
              Even in auto mode, incidents above this severity always require approval.
            </div>
          </div>

          <div>
            <div className="detail-label" style={{ marginBottom: 6 }}>PER TARGET-ASSET-CRITICALITY OVERRIDE</div>
            <dl className="kv-grid" style={{ gridTemplateColumns: '80px 1fr' }}>
              {CRITICALITIES.map((crit) => (
                <div key={crit} style={{ display: 'contents' }}>
                  <dt style={{ textTransform: 'capitalize' }}>{crit}</dt>
                  <dd>
                    <select
                      className="live-select" style={{ width: '100%' }}
                      value={policy?.criticality_overrides?.[crit] || ''}
                      onChange={(e) => onPolicyChange({ criticality_overrides: { ...(policy?.criticality_overrides || {}), [crit]: e.target.value || null } })}
                    >
                      <option value="">(use default)</option>
                      {MODES.map((m) => <option key={m} value={m}>{m}</option>)}
                    </select>
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">AUDIT LOG</span>
          <span className="status-tag">{auditLog.length} total</span>
        </div>
        <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 320, overflowY: 'auto' }}>
          {auditLog.length === 0 && <div className="empty-hint">No response actions logged yet.</div>}
          {auditLog.map((a) => (
            <div className="action-card" key={a.action_id}>
              <div className="action-card-top">
                <span className="action-card-title">{ACTION_LABEL[a.action] || a.action}</span>
                <ActionStatusTag status={a.status} />
              </div>
              <div className="action-card-meta">{describeParams(a)} · {a.mode} mode · {fmtTime(a.executed_at || a.created_at)}</div>
              {a.status === 'executed' && a.rollback_available && (
                <div className="action-card-buttons">
                  <button className="live-btn" onClick={() => onRollback(a.action_id)}>Roll back</button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </>
  )
}

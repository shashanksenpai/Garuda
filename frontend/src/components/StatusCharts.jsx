import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip } from 'recharts'

const SEV_ORDER = ['low', 'medium', 'high', 'critical']
const SEV_COLOR = {
  info: '#64748b', low: '#22c3d6', medium: '#e0a730', high: '#f2793a', critical: '#ef4b57',
}

const tooltipStyle = {
  background: '#161a23', border: '1px solid #262c3a', borderRadius: 3,
  fontSize: 11, fontFamily: 'var(--font-mono)', color: '#e7eaf2',
}

export default function StatusCharts({ severityDist = {}, threatDist = {} }) {
  const sevData = SEV_ORDER.map((s) => ({ name: s, value: severityDist[s] || 0 }))
  const threatData = Object.entries(threatDist)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, value]) => ({ name, value }))

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">DISTRIBUTIONS</span>
      </div>
      <div className="chart-panel">
        <div style={{ fontSize: 11, color: 'var(--text-faint)', margin: '0 8px 4px' }}>Incidents by severity</div>
        <ResponsiveContainer width="100%" height={90}>
          <BarChart data={sevData} margin={{ top: 4, right: 12, left: 4, bottom: 0 }}>
            <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-faint)' }} axisLine={{ stroke: '#262c3a' }} tickLine={false} />
            <YAxis hide allowDecimals={false} />
            <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
            <Bar dataKey="value" radius={[2, 2, 0, 0]}>
              {sevData.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>

        <div style={{ fontSize: 11, color: 'var(--text-faint)', margin: '10px 8px 4px' }}>Top MITRE techniques</div>
        <ResponsiveContainer width="100%" height={Math.max(threatData.length * 26, 40)}>
          <BarChart data={threatData} layout="vertical" margin={{ top: 0, right: 20, left: 0, bottom: 0 }}>
            <XAxis type="number" hide allowDecimals={false} />
            <YAxis
              dataKey="name" type="category" width={130}
              tick={{ fontSize: 10, fill: 'var(--text-dim)' }} axisLine={false} tickLine={false}
            />
            <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
            <Bar dataKey="value" fill="var(--accent)" radius={[0, 2, 2, 0]} barSize={12} />
          </BarChart>
        </ResponsiveContainer>
        {threatData.length === 0 && (
          <div className="empty-hint" style={{ padding: '8px 4px' }}>No techniques mapped yet.</div>
        )}
      </div>
    </div>
  )
}

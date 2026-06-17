import { useQuery } from '@tanstack/react-query'
import { getDashboard } from '../api/dashboard.js'
import { getClientId } from '../store/authStore.js'
import { getBand, getBandName } from '../utils/scoring.js'
import { truncate, formatDate } from '../utils/formatters.js'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

function KpiCard({ label, value, delta, valueColor }) {
  return (
    <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '8px', padding: '14px 16px' }}>
      <div style={{ ...mono, fontSize: '10px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>{label}</div>
      <div style={{ ...mono, fontSize: '24px', fontWeight: 500, color: valueColor || '#e5e5e5', lineHeight: 1 }}>{value}</div>
      {delta && <div style={{ ...mono, fontSize: '11px', color: '#666', marginTop: '5px' }}>{delta}</div>}
    </div>
  )
}

function ScorePill({ score }) {
  const band = getBand(score)
  return (
    <span style={{ ...mono, fontSize: '12px', fontWeight: 500, padding: '3px 8px', borderRadius: '5px', background: band.bg, color: band.text }}>
      {parseFloat(score).toFixed(1)}
    </span>
  )
}

function Tag({ children, color, bg, text }) {
  return (
    <span style={{ ...mono, fontSize: '10px', fontWeight: 500, padding: '2px 6px', borderRadius: '3px', background: bg, color: text }}>
      {children}
    </span>
  )
}

export default function Dashboard() {
  const clientId = getClientId()
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', clientId],
    queryFn:  () => getDashboard(clientId),
    refetchInterval: 5 * 60 * 1000
  })

  if (isLoading) return <div style={{ ...mono, color: '#666', padding: '2rem' }}>Loading intelligence data...</div>
  if (error)     return <div style={{ ...mono, color: '#E24B4A', padding: '2rem' }}>Failed to load dashboard</div>

  const { summary, top_critical, trending, platforms } = data

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div>
          <div style={{ fontSize: '15px', fontWeight: 500, color: '#e5e5e5' }}>Threat Dashboard</div>
          <div style={{ ...mono, fontSize: '11px', color: '#666', marginTop: '2px' }}>Global CVE intelligence — {new Date().toISOString().split('T')[0]}</div>
        </div>
      </div>

      {/* KPI Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '1.25rem' }}>
        <KpiCard label="Critical" value={summary.critical} valueColor="#E24B4A" />
        <KpiCard label="High" value={summary.high} valueColor="#BA7517" />
        <KpiCard label="KEV Exposure" value={summary.kev_total} valueColor="#E24B4A" delta="Confirmed exploited" />
        <KpiCard label="Pre-KEV Flags" value={summary.pre_kev_total} valueColor="#534AB7" delta="Early warning signals" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: '12px', marginBottom: '12px' }}>

        {/* Act Now */}
        <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', overflow: 'hidden' }}>
          <div style={{ padding: '10px 16px', borderBottom: '0.5px solid #2a2a2a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ ...mono, fontSize: '11px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Act now</span>
            <span style={{ ...mono, fontSize: '10px', background: '#FCEBEB', color: '#A32D2D', padding: '2px 8px', borderRadius: '10px' }}>{summary.critical} critical</span>
          </div>
          {top_critical.slice(0, 6).map(cve => (
            <div key={cve.cve_id} style={{ padding: '10px 16px', borderBottom: '0.5px solid #1a1a1a', display: 'grid', gridTemplateColumns: '110px 1fr auto auto', gap: '12px', alignItems: 'center' }}>
              <span style={{ ...mono, fontSize: '11px', color: '#5b9bd5' }}>{cve.cve_id}</span>
              <div>
                <div style={{ fontSize: '12px', color: '#e5e5e5', fontWeight: 500 }}>{truncate(cve.description, 60)}</div>
                <div style={{ ...mono, fontSize: '10px', color: '#666', marginTop: '2px' }}>{cve.attack_vector} · {cve.patch_available ? 'patch available' : 'no patch'}</div>
              </div>
              <div style={{ display: 'flex', gap: '4px' }}>
                {cve.kev_member && <Tag bg="#FCEBEB" text="#A32D2D">KEV</Tag>}
                {cve.pre_kev_flag && <Tag bg="#EEEDFE" text="#534AB7">PRE-KEV</Tag>}
                {cve.exploit_available && <Tag bg="#FAEEDA" text="#854F0B">EXPLOIT</Tag>}
              </div>
              <ScorePill score={cve.adjusted_score} />
            </div>
          ))}
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

          {/* Score distribution */}
          <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', padding: '14px 16px' }}>
            <div style={{ ...mono, fontSize: '11px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '12px' }}>Distribution</div>
            {[
              { label: 'Critical', count: summary.critical, color: '#E24B4A', pct: summary.critical / (summary.critical + summary.high + summary.medium + summary.low) },
              { label: 'High',     count: summary.high,     color: '#BA7517', pct: summary.high / (summary.critical + summary.high + summary.medium + summary.low) },
              { label: 'Medium',   count: summary.medium,   color: '#888780', pct: summary.medium / (summary.critical + summary.high + summary.medium + summary.low) },
              { label: 'Low',      count: summary.low,      color: '#1D9E75', pct: summary.low / (summary.critical + summary.high + summary.medium + summary.low) },
            ].map(b => (
              <div key={b.label} style={{ marginBottom: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '3px' }}>
                  <span style={{ ...mono, fontSize: '11px', color: '#888' }}>{b.label}</span>
                  <span style={{ ...mono, fontSize: '11px', fontWeight: 500, color: '#e5e5e5' }}>{b.count.toLocaleString()}</span>
                </div>
                <div style={{ height: '4px', background: '#1a1a1a', borderRadius: '2px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min(b.pct * 100, 100)}%`, background: b.color, borderRadius: '2px' }} />
                </div>
              </div>
            ))}
          </div>

          {/* Platform exposure */}
          <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', padding: '14px 16px' }}>
            <div style={{ ...mono, fontSize: '11px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>Platform exposure</div>
            {platforms.map(p => (
              <div key={p.platform_tag} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ ...mono, fontSize: '12px', color: '#888' }}>{p.platform_tag}</span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <span style={{ ...mono, fontSize: '11px', color: '#E24B4A' }}>{p.critical} crit</span>
                  <span style={{ ...mono, fontSize: '11px', color: '#666' }}>{p.kev} kev</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

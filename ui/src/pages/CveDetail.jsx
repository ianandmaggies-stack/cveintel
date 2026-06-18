import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { getCve } from '../api/cves.js'
import { getClientId } from '../store/authStore.js'
import { getBand } from '../utils/scoring.js'
import { formatDate, formatEpss, truncate } from '../utils/formatters.js'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

function Tag({ children, bg, text }) {
  return <span style={{ ...mono, fontSize: '10px', fontWeight: 500, padding: '2px 6px', borderRadius: '3px', background: bg, color: text }}>{children}</span>
}

function Panel({ title, children, style }) {
  return (
    <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', overflow: 'hidden', marginBottom: '12px', ...style }}>
      <div style={{ padding: '10px 16px', borderBottom: '0.5px solid #2a2a2a' }}>
        <span style={{ ...mono, fontSize: '11px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{title}</span>
      </div>
      <div style={{ padding: '14px 16px' }}>{children}</div>
    </div>
  )
}

function ScoreBar({ label, points, max, color = '#E24B4A', suppressedBy, children }) {
  const pct = Math.min((points / max) * 100, 100)
  return (
    <div style={{ marginBottom: '10px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr 50px 36px', alignItems: 'center', gap: '10px' }}>
        <span style={{ ...mono, fontSize: '12px', color: '#888' }}>{label}</span>
        <div style={{ height: '7px', background: '#1a1a1a', borderRadius: '3px', overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${pct}%`, background: suppressedBy ? '#2a2a2a' : color, borderRadius: '3px', transition: 'width 0.4s' }} />
        </div>
        <span style={{ ...mono, fontSize: '12px', fontWeight: 500, color: suppressedBy ? '#444' : '#e5e5e5', textAlign: 'right' }}>{points.toFixed(1)}</span>
        <span style={{ ...mono, fontSize: '10px', color: '#444', textAlign: 'right' }}>/{max}</span>
      </div>
      {suppressedBy && <div style={{ ...mono, fontSize: '10px', color: '#555', marginTop: '3px', paddingLeft: '120px', fontStyle: 'italic' }}>superseded by {suppressedBy}</div>}
      {children && <div style={{ ...mono, fontSize: '10px', color: '#555', marginTop: '3px', paddingLeft: '120px' }}>{children}</div>}
    </div>
  )
}

function TimelineEvent({ dot, title, date, detail, last }) {
  return (
    <div style={{ display: 'flex', gap: '12px', marginBottom: last ? 0 : '14px' }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '20px', flexShrink: 0 }}>
        <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: dot, marginTop: '3px', flexShrink: 0 }} />
        {!last && <div style={{ width: '1px', flex: 1, background: '#2a2a2a', marginTop: '4px', minHeight: '20px' }} />}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: '13px', color: '#e5e5e5', fontWeight: 500 }}>{title}</div>
        <div style={{ ...mono, fontSize: '11px', color: '#555', marginTop: '2px' }}>{date}</div>
        {detail && <div style={{ fontSize: '11px', color: '#888', marginTop: '2px' }}>{detail}</div>}
      </div>
    </div>
  )
}

export default function CveDetail() {
  const { cveId }  = useParams()
  const navigate   = useNavigate()
  const clientId   = getClientId()

  const { data: cve, isLoading, error } = useQuery({
    queryKey: ['cve', clientId, cveId],
    queryFn:  () => getCve(clientId, cveId)
  })

  if (isLoading) return <div style={{ ...mono, color: '#666', padding: '2rem' }}>Loading CVE data...</div>
  if (error)     return <div style={{ ...mono, color: '#E24B4A', padding: '2rem' }}>Failed to load {cveId}</div>

  const band      = getBand(cve.adjusted_score)
  const sb        = cve.score_breakdown
  const epssChart = (cve.epss_history || []).slice().reverse().map(e => ({
    date:  formatDate(e.snapshot_date),
    epss:  parseFloat(e.epss_score)
  }))

  // Build timeline
  const timeline = [
    { dot: '#888780', title: 'CVE published', date: formatDate(cve.published_date), detail: `CVSS ${cve.cvss_base || '—'} assigned` }
  ]
  if (cve.exploit_available) {
    timeline.push({ dot: '#BA7517', title: 'Exploit available', date: '—', detail: 'Metasploit or ExploitDB module published' })
  }
  if (cve.kev_member) {
    timeline.push({ dot: '#E24B4A', title: 'Added to CISA KEV', date: formatDate(cve.kev_date_added), detail: 'Confirmed active exploitation in the wild' })
  }
  if (!cve.patch_available) {
    timeline.push({ dot: '#E24B4A', title: 'No patch available', date: 'Today', detail: `${Math.floor((Date.now() - new Date(cve.published_date)) / 86400000)} days since publication` })
  }

  return (
    <div>
      {/* Back */}
      <button onClick={() => navigate('/cves')} style={{ ...mono, fontSize: '12px', color: '#666', background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '4px' }}>
        ← CVE List
      </button>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
        <div>
          <div style={{ ...mono, fontSize: '18px', fontWeight: 500, color: '#e5e5e5', marginBottom: '4px' }}>{cveId}</div>
          <div style={{ fontSize: '14px', color: '#888', marginBottom: '8px' }}>{truncate(cve.description, 100)}</div>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {cve.kev_member       && <Tag bg="#FCEBEB" text="#A32D2D">KEV</Tag>}
            {cve.exploit_available && <Tag bg="#FAEEDA" text="#854F0B">EXPLOIT</Tag>}
            {cve.pre_kev_flag     && <Tag bg="#EEEDFE" text="#534AB7">PRE-KEV</Tag>}
            {!cve.patch_available  && <Tag bg="#FCEBEB" text="#A32D2D">NO PATCH</Tag>}
            {cve.user_interaction === 'required' && <Tag bg="#EEEDFE" text="#534AB7">USER INTERACTION</Tag>}
            {cve.scope === 'changed' && <Tag bg="#FAEEDA" text="#854F0B">SCOPE CHANGED</Tag>}
            <Tag bg="#1a1a1a" text="#888">{cve.attack_vector?.toUpperCase()}</Tag>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexShrink: 0 }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ ...mono, fontSize: '11px', color: '#666', marginBottom: '4px' }}>CVSS {cve.cvss_version}</div>
            <div style={{ ...mono, fontSize: '13px', color: '#888' }}>{cve.cvss_base}</div>
          </div>
          <div style={{ width: '72px', height: '72px', borderRadius: '50%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: band.bg, border: `2px solid ${band.color}` }}>
            <div style={{ ...mono, fontSize: '22px', fontWeight: 500, color: band.text, lineHeight: 1 }}>{parseFloat(cve.adjusted_score).toFixed(0)}</div>
            <div style={{ ...mono, fontSize: '9px', color: band.text, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{band.label}</div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: '12px' }}>
        <div>
          {/* Score breakdown */}
          <Panel title="Score breakdown">
            <ScoreBar label="CVSS base"   points={sb.components.cvss.points}     max={20} />
            <ScoreBar label="EPSS"        points={sb.components.epss.points}     max={25} color="#E24B4A">
              {formatEpss(sb.components.epss.value)} exploitation probability
            </ScoreBar>
            <ScoreBar label="Velocity 7d" points={sb.components.velocity.points} max={10} color="#BA7517">
              {sb.components.velocity.delta_7d > 0 ? `+${parseFloat(sb.components.velocity.delta_7d).toFixed(3)} in 7 days` : 'No velocity'}
            </ScoreBar>
            <ScoreBar label="KEV"         points={sb.components.kev.points}      max={25} color="#E24B4A">
              {sb.components.kev.member ? `Added ${formatDate(cve.kev_date_added)}` : 'Not on KEV list'}
            </ScoreBar>
            <ScoreBar label="Exploit"     points={sb.components.exploit.points}  max={10} color="#BA7517" suppressedBy={sb.components.exploit.suppressed_by}>
              {sb.components.exploit.available ? 'Module available' : 'No known exploit'}
            </ScoreBar>
            <ScoreBar label="No patch"    points={sb.components.no_patch.points} max={10} color="#A32D2D">
              {sb.components.no_patch.patch_available ? 'Patch available' : 'No patch released'}
            </ScoreBar>
            <div style={{ borderTop: '0.5px solid #2a2a2a', marginTop: '10px', paddingTop: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ ...mono, fontSize: '12px', fontWeight: 500, color: '#e5e5e5' }}>Combined score</span>
              <span style={{ ...mono, fontSize: '14px', fontWeight: 500, color: band.text }}>{parseFloat(cve.adjusted_score).toFixed(2)}</span>
            </div>
            <div style={{ ...mono, fontSize: '11px', color: '#555', marginTop: '6px' }}>
              Attack vector modifier: {cve.attack_vector} × {parseFloat(cve.attack_vector_modifier).toFixed(2)}
            </div>
          </Panel>

          {/* EPSS trend */}
          {epssChart.length > 0 && (
            <Panel title={`EPSS trend — ${epssChart.length} day${epssChart.length > 1 ? 's' : ''}`}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
                <div>
                  <div style={{ ...mono, fontSize: '20px', fontWeight: 500, color: '#E24B4A' }}>{formatEpss(epssChart[epssChart.length - 1]?.epss)}</div>
                  <div style={{ ...mono, fontSize: '11px', color: '#666' }}>current probability</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ ...mono, fontSize: '13px', color: '#888' }}>{cve.epss_history?.[0]?.percentile ? `${(parseFloat(cve.epss_history[0].percentile) * 100).toFixed(1)}th` : '—'}</div>
                  <div style={{ ...mono, fontSize: '11px', color: '#666' }}>percentile</div>
                </div>
              </div>
              <ResponsiveContainer width="100%" height={120}>
                <LineChart data={epssChart}>
                  <XAxis dataKey="date" tick={{ fontFamily: 'JetBrains Mono', fontSize: 10, fill: '#555' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                  <YAxis domain={[0, 1]} tick={{ fontFamily: 'JetBrains Mono', fontSize: 10, fill: '#555' }} tickLine={false} axisLine={false} tickFormatter={v => `${(v*100).toFixed(0)}%`} />
                  <Tooltip formatter={v => [`${(v*100).toFixed(2)}%`, 'EPSS']} contentStyle={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '6px', fontFamily: 'JetBrains Mono', fontSize: '11px' }} />
                  <Line type="monotone" dataKey="epss" stroke="#E24B4A" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </Panel>
          )}

          {/* Timeline */}
          <Panel title="Event timeline">
            {timeline.map((e, i) => (
              <TimelineEvent key={i} {...e} last={i === timeline.length - 1} />
            ))}
          </Panel>

          {/* Description */}
          <Panel title="Description">
            <p style={{ fontSize: '13px', color: '#888', lineHeight: 1.6, margin: 0 }}>{cve.description}</p>
            {cve.cwe_id && <div style={{ ...mono, fontSize: '11px', color: '#555', marginTop: '10px' }}>{cve.cwe_id}</div>}
          </Panel>
        </div>

        {/* Right column */}
        <div>
          {/* Status */}
          <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', overflow: 'hidden', marginBottom: '12px' }}>
            <div style={{ padding: '10px 16px', borderBottom: '0.5px solid #2a2a2a' }}>
              <span style={{ ...mono, fontSize: '11px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Status</span>
            </div>
            <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                { value: 'active',         label: 'Active — not resolved',  dot: '#E24B4A', active: true },
                { value: 'patched',        label: 'Mark as patched',        dot: '#1D9E75' },
                { value: 'accepted_risk',  label: 'Accept risk',            dot: '#BA7517' },
                { value: 'not_applicable', label: 'Not applicable',         dot: '#888780' },
              ].map(s => (
                <button key={s.value} style={{
                  display: 'flex', alignItems: 'center', gap: '8px',
                  padding: '8px 12px', borderRadius: '6px', border: '0.5px solid',
                  background:   s.active ? '#1a1a1a' : 'transparent',
                  borderColor:  s.active ? '#E24B4A44' : '#2a2a2a',
                  cursor: 'pointer', textAlign: 'left', width: '100%'
                }}>
                  <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: s.dot, flexShrink: 0 }} />
                  <span style={{ ...mono, fontSize: '12px', color: s.active ? '#e5e5e5' : '#888' }}>{s.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Affected CPEs */}
          {cve.cpes?.length > 0 && (
            <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', overflow: 'hidden', marginBottom: '12px' }}>
              <div style={{ padding: '10px 16px', borderBottom: '0.5px solid #2a2a2a' }}>
                <span style={{ ...mono, fontSize: '11px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Affected products</span>
              </div>
              <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {[...new Map(cve.cpes.map(c => [c.product, c])).values()].slice(0, 5).map((cpe, i) => (
                  <div key={i} style={{ padding: '8px 10px', background: '#1a1a1a', borderRadius: '6px' }}>
                    <div style={{ ...mono, fontSize: '12px', color: '#e5e5e5', fontWeight: 500 }}>{cpe.product}</div>
                    <div style={{ ...mono, fontSize: '10px', color: '#555', marginTop: '2px' }}>{cpe.vendor} · {cpe.platform_tag}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* CVSS detail */}
          <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', overflow: 'hidden', marginBottom: '12px' }}>
            <div style={{ padding: '10px 16px', borderBottom: '0.5px solid #2a2a2a' }}>
              <span style={{ ...mono, fontSize: '11px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px' }}>CVSS detail</span>
            </div>
            <div style={{ padding: '12px 16px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              {[
                ['Attack vector',   cve.attack_vector],
                ['Privileges',      cve.privileges_required],
                ['User interaction', cve.user_interaction],
                ['Scope',           cve.scope],
                ['Published',       formatDate(cve.published_date)],
                ['Modified',        formatDate(cve.modified_date)],
              ].map(([key, val]) => (
                <div key={key}>
                  <div style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase', marginBottom: '2px' }}>{key}</div>
                  <div style={{ ...mono, fontSize: '12px', fontWeight: 500, color: val === 'required' ? '#534AB7' : val === 'changed' ? '#E24B4A' : '#e5e5e5' }}>{val || '—'}</div>
                </div>
              ))}
            </div>
            {cve.cvss_vector && (
              <div style={{ padding: '10px 16px', borderTop: '0.5px solid #2a2a2a' }}>
                <div style={{ ...mono, fontSize: '10px', color: '#444', wordBreak: 'break-all' }}>{cve.cvss_vector}</div>
              </div>
            )}
          </div>

          {/* KEV detail */}
          {cve.kev_member && (
            <div style={{ background: '#FCEBEB', border: '0.5px solid #E24B4A44', borderRadius: '10px', padding: '14px 16px', marginBottom: '12px' }}>
              <div style={{ ...mono, fontSize: '11px', color: '#A32D2D', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>CISA KEV</div>
              <div style={{ fontSize: '12px', color: '#7a2020', lineHeight: 1.5 }}>{cve.kev_required_action}</div>
              <div style={{ ...mono, fontSize: '11px', color: '#A32D2D', marginTop: '8px' }}>Added {formatDate(cve.kev_date_added)}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getPosture, getDashboard } from '../api/posture.js'
import { getClientId } from '../store/authStore.js'
import { formatDate } from '../utils/formatters.js'
import { PieChart, Pie, Cell } from 'recharts'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: '1.5rem' }}>
      <div style={{ fontSize: '14px', fontWeight: 600, color: '#1a1a1a', borderBottom: '2px solid #E24B4A', display: 'inline-block', paddingBottom: '4px', marginBottom: '12px' }}>{title}</div>
      {children}
    </div>
  )
}

function ExecKpi({ num, label, desc, color }) {
  return (
    <div style={{ borderRadius: '10px', padding: '20px', textAlign: 'center', background: color.bg, border: `1px solid ${color.border}` }}>
      <div style={{ fontSize: '36px', fontWeight: 600, color: color.text, lineHeight: 1, marginBottom: '6px' }}>{num}</div>
      <div style={{ fontSize: '13px', fontWeight: 500, color: '#1a1a1a', marginBottom: '4px' }}>{label}</div>
      <div style={{ fontSize: '11px', color: '#666', lineHeight: 1.4 }}>{desc}</div>
    </div>
  )
}

function ActionRow({ dot, label, desc, bg }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '10px 12px', borderRadius: '8px', marginBottom: '6px', background: bg }}>
      <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: dot, flexShrink: 0, marginTop: '4px' }} />
      <div>
        <div style={{ fontSize: '12px', fontWeight: 500, color: '#1a1a1a' }}>{label}</div>
        <div style={{ fontSize: '12px', color: '#555', marginTop: '2px' }}>{desc}</div>
      </div>
    </div>
  )
}

export default function ExecutiveReport() {
  const clientId     = getClientId()
  const today        = new Date().toISOString().split('T')[0]
  const [mode, setMode] = useState('executive')

  const { data: posture, isLoading: pLoading } = useQuery({
    queryKey: ['posture', clientId],
    queryFn:  () => getPosture(clientId)
  })

  const { data: dash, isLoading: dLoading } = useQuery({
    queryKey: ['dashboard', clientId],
    queryFn:  () => getDashboard(clientId)
  })

  if (pLoading || dLoading) return <div style={{ ...mono, color: '#666', padding: '2rem' }}>Generating report...</div>

  const total = parseInt(posture.critical) + parseInt(posture.high) + parseInt(posture.medium) + parseInt(posture.low)
  const pieData = [
    { name: 'Critical', value: parseInt(posture.critical), color: '#E24B4A' },
    { name: 'High',     value: parseInt(posture.high),     color: '#BA7517' },
    { name: 'Medium',   value: parseInt(posture.medium),   color: '#888780' },
    { name: 'Low',      value: parseInt(posture.low),      color: '#1D9E75' },
  ]

  const overallRisk = parseInt(posture.kev_total) > 0 ? 'HIGH' : parseInt(posture.critical) > 10 ? 'ELEVATED' : 'MODERATE'
  const riskColor   = overallRisk === 'HIGH' ? '#E24B4A' : overallRisk === 'ELEVATED' ? '#BA7517' : '#1D9E75'

  return (
    <div>
      {/* Mode toggle + export */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', gap: 0, border: '0.5px solid #2a2a2a', borderRadius: '6px', overflow: 'hidden' }}>
          {[['executive', 'Executive'], ['technical', 'Technical']].map(([val, label]) => (
            <button key={val} onClick={() => setMode(val)} style={{
              ...mono, fontSize: '12px', padding: '6px 18px', border: 'none', cursor: 'pointer',
              background: mode === val ? '#e5e5e5' : 'transparent',
              color:      mode === val ? '#0a0a0a' : '#888'
            }}>{label}</button>
          ))}
        </div>
        <button onClick={() => window.print()} style={{ ...mono, fontSize: '12px', padding: '6px 16px', borderRadius: '6px', border: '0.5px solid #2a2a2a', background: 'transparent', color: '#888', cursor: 'pointer' }}>
          Print / Export PDF
        </button>
      </div>

      {/* EXECUTIVE MODE */}
      {mode === 'executive' && (
        <div style={{ background: '#fff', color: '#1a1a1a', borderRadius: '12px', padding: '2rem', border: '0.5px solid #e5e5e5' }}>
          <div style={{ textAlign: 'center', marginBottom: '2rem', paddingBottom: '1.5rem', borderBottom: '1px solid #e5e5e5' }}>
            <div style={{ fontSize: '11px', color: '#888', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '1px' }}>Cybersecurity Risk Summary</div>
            <div style={{ fontSize: '22px', fontWeight: 600, color: '#1a1a1a', marginBottom: '4px' }}>Security Intelligence Report</div>
            <div style={{ fontSize: '12px', color: '#888' }}>Generated {today} · Powered by CVE///INTEL</div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '1.5rem' }}>
            <ExecKpi
              num={overallRisk}
              label="Overall Risk Level"
              desc={parseInt(posture.kev_total) > 0 ? `${posture.kev_total} actively exploited vulnerabilities confirmed` : `${posture.critical} critical vulnerabilities require attention`}
              color={{ bg: `${riskColor}15`, border: `${riskColor}44`, text: riskColor }}
            />
            <ExecKpi
              num={posture.kev_total}
              label="Actively Exploited"
              desc="Confirmed by US Government (CISA KEV) as being exploited in the wild right now"
              color={{ bg: '#FCEBEB', border: '#E24B4A44', text: '#A32D2D' }}
            />
            <ExecKpi
              num={posture.critical}
              label="Critical Issues"
              desc="Vulnerabilities scoring 75+ requiring immediate action"
              color={{ bg: '#FFF8F0', border: '#BA751744', text: '#854F0B' }}
            />
          </div>

          <Section title="Top threats requiring attention">
            {dash.top_critical.slice(0, 3).map((cve, i) => (
              <div key={cve.cve_id} style={{ display: 'flex', gap: '12px', padding: '12px', background: '#fafafa', borderRadius: '8px', marginBottom: '8px' }}>
                <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: '#E24B4A', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '13px', fontWeight: 600, flexShrink: 0 }}>{i + 1}</div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: '#1a1a1a', marginBottom: '3px' }}>
                    {cve.kev_member ? 'Actively Exploited: ' : ''}{cve.cve_id}
                  </div>
                  <div style={{ fontSize: '12px', color: '#555', lineHeight: 1.5 }}>{cve.description}</div>
                  <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                    {cve.kev_member && <span style={{ fontSize: '10px', background: '#FCEBEB', color: '#A32D2D', padding: '2px 6px', borderRadius: '3px', fontWeight: 500 }}>Confirmed Exploited</span>}
                    {!cve.patch_available && <span style={{ fontSize: '10px', background: '#FFF0F0', color: '#A32D2D', padding: '2px 6px', borderRadius: '3px' }}>No patch available</span>}
                    <span style={{ ...mono, fontSize: '10px', background: '#f0f0f0', color: '#555', padding: '2px 6px', borderRadius: '3px' }}>Score: {parseFloat(cve.adjusted_score).toFixed(0)}/100</span>
                  </div>
                </div>
              </div>
            ))}
          </Section>

          <Section title="Recommended actions">
            {parseInt(posture.kev_total) > 0 && (
              <ActionRow dot="#E24B4A" bg="#FCEBEB"
                label="Act this week"
                desc={`Apply patches or mitigations for ${posture.kev_total} actively exploited vulnerabilities. These are confirmed by CISA as being used in real attacks.`}
              />
            )}
            {parseInt(posture.pre_kev_total) > 0 && (
              <ActionRow dot="#BA7517" bg="#FAEEDA"
                label="Plan this month"
                desc={`Review ${posture.pre_kev_total} vulnerabilities flagged as likely to be exploited soon — our early warning signal before official confirmation.`}
              />
            )}
            <ActionRow dot="#888780" bg="#f5f5f5"
              label="Ongoing monitoring"
              desc={`${posture.medium} medium-severity vulnerabilities are being monitored. Alerts will fire if any escalate to critical.`}
            />
          </Section>

          <Section title="Vulnerability distribution">
            <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
              <PieChart width={180} height={180}>
                <Pie data={pieData} cx={85} cy={85} innerRadius={50} outerRadius={80} dataKey="value" strokeWidth={0}>
                  {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
              </PieChart>
              <div style={{ flex: 1 }}>
                {pieData.map(b => (
                  <div key={b.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ width: '10px', height: '10px', borderRadius: '2px', background: b.color }} />
                      <span style={{ fontSize: '13px', color: '#555' }}>{b.name}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                      <span style={{ fontSize: '13px', fontWeight: 500, color: '#1a1a1a' }}>{b.value.toLocaleString()}</span>
                      <span style={{ ...mono, fontSize: '11px', color: '#888' }}>{total > 0 ? ((b.value / total) * 100).toFixed(1) : 0}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Section>

          <div style={{ textAlign: 'center', paddingTop: '1rem', borderTop: '1px solid #e5e5e5', fontSize: '11px', color: '#aaa' }}>
            CVE///INTEL · Data sourced from NVD, CISA KEV, EPSS · {today}
          </div>
        </div>
      )}

      {/* TECHNICAL MODE */}
      {mode === 'technical' && (
        <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '12px', padding: '1.5rem' }}>
          <div style={{ marginBottom: '1.5rem', paddingBottom: '1rem', borderBottom: '0.5px solid #2a2a2a' }}>
            <div style={{ ...mono, fontSize: '15px', fontWeight: 500, color: '#e5e5e5' }}>Technical Risk Report</div>
            <div style={{ ...mono, fontSize: '11px', color: '#666', marginTop: '2px' }}>Generated {today}</div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '1.25rem' }}>
            {[
              { label: 'Critical',  value: posture.critical,      color: '#E24B4A' },
              { label: 'High',      value: posture.high,          color: '#BA7517' },
              { label: 'KEV',       value: posture.kev_total,     color: '#E24B4A' },
              { label: 'Pre-KEV',   value: posture.pre_kev_total, color: '#534AB7' },
            ].map(k => (
              <div key={k.label} style={{ background: '#1a1a1a', borderRadius: '8px', padding: '12px 14px' }}>
                <div style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase', marginBottom: '4px' }}>{k.label}</div>
                <div style={{ ...mono, fontSize: '22px', fontWeight: 500, color: k.color }}>{parseInt(k.value).toLocaleString()}</div>
              </div>
            ))}
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <div style={{ ...mono, fontSize: '11px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>Top critical CVEs</div>
            {dash.top_critical.map((cve) => (
              <div key={cve.cve_id} style={{ padding: '10px 14px', background: '#1a1a1a', borderRadius: '8px', marginBottom: '6px', display: 'grid', gridTemplateColumns: '120px 1fr auto auto', gap: '12px', alignItems: 'center' }}>
                <span style={{ ...mono, fontSize: '11px', color: '#5b9bd5' }}>{cve.cve_id}</span>
                <span style={{ fontSize: '12px', color: '#888' }}>{cve.description?.slice(0, 70)}...</span>
                <div style={{ display: 'flex', gap: '4px' }}>
                  {cve.kev_member && <span style={{ ...mono, fontSize: '10px', background: '#FCEBEB', color: '#A32D2D', padding: '2px 5px', borderRadius: '3px' }}>KEV</span>}
                </div>
                <span style={{ ...mono, fontSize: '12px', fontWeight: 500, color: '#E24B4A' }}>{parseFloat(cve.adjusted_score).toFixed(1)}</span>
              </div>
            ))}
          </div>

          <div>
            <div style={{ ...mono, fontSize: '11px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>Platform exposure</div>
            {dash.platforms.map(p => (
              <div key={p.platform_tag} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 14px', background: '#1a1a1a', borderRadius: '6px', marginBottom: '6px' }}>
                <span style={{ ...mono, fontSize: '12px', color: '#888' }}>{p.platform_tag}</span>
                <div style={{ display: 'flex', gap: '16px' }}>
                  <span style={{ ...mono, fontSize: '12px', color: '#E24B4A' }}>{p.critical} critical</span>
                  <span style={{ ...mono, fontSize: '12px', color: '#666' }}>{p.kev} kev</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

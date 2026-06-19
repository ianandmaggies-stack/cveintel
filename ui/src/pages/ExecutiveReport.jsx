import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getPosture, getDashboard } from '../api/posture.js'
import { getClientId } from '../store/authStore.js'
import { PieChart, Pie, Cell } from 'recharts'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

// Dark theme tokens
const D = {
  bg:        '#111',
  bg2:       '#1a1a1a',
  bg3:       '#222',
  border:    '#2a2a2a',
  text:      '#e5e5e5',
  textMuted: '#888',
  textDim:   '#555',
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: '1.5rem' }}>
      <div style={{ fontSize: '14px', fontWeight: 600, color: D.text, borderBottom: '2px solid #E24B4A', display: 'inline-block', paddingBottom: '4px', marginBottom: '12px' }}>{title}</div>
      {children}
    </div>
  )
}

function ExecKpi({ num, label, desc, color }) {
  return (
    <div style={{ borderRadius: '10px', padding: '20px', textAlign: 'center', background: color.bg, border: `1px solid ${color.border}` }}>
      <div style={{ fontSize: '36px', fontWeight: 600, color: color.text, lineHeight: 1, marginBottom: '6px' }}>{num}</div>
      <div style={{ fontSize: '13px', fontWeight: 500, color: D.text, marginBottom: '4px' }}>{label}</div>
      <div style={{ fontSize: '11px', color: D.textMuted, lineHeight: 1.4 }}>{desc}</div>
    </div>
  )
}

function ActionRow({ dot, label, desc, bg }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '10px 12px', borderRadius: '8px', marginBottom: '6px', background: bg }}>
      <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: dot, flexShrink: 0, marginTop: '4px' }} />
      <div>
        <div style={{ fontSize: '12px', fontWeight: 500, color: D.text }}>{label}</div>
        <div style={{ fontSize: '12px', color: D.textMuted, marginTop: '2px' }}>{desc}</div>
      </div>
    </div>
  )
}

export default function ExecutiveReport() {
  const clientId        = getClientId()
  const today           = new Date().toISOString().split('T')[0]
  const [mode, setMode] = useState('executive')

  const { data: posture, isLoading: pLoading } = useQuery({
    queryKey: ['posture', clientId],
    queryFn:  () => getPosture(clientId)
  })

  const { data: dash, isLoading: dLoading } = useQuery({
    queryKey: ['dashboard', clientId],
    queryFn:  () => getDashboard(clientId)
  })

  if (pLoading || dLoading) return <div style={{ ...mono, color: D.textDim, padding: '2rem' }}>Generating report...</div>

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
        <div style={{ display: 'flex', gap: 0, border: `0.5px solid ${D.border}`, borderRadius: '6px', overflow: 'hidden' }}>
          {[['executive', 'Executive'], ['technical', 'Technical']].map(([val, label]) => (
            <button key={val} onClick={() => setMode(val)} style={{
              ...mono, fontSize: '12px', padding: '6px 18px', border: 'none', cursor: 'pointer',
              background: mode === val ? D.text : 'transparent',
              color:      mode === val ? '#0a0a0a' : D.textMuted
            }}>{label}</button>
          ))}
        </div>
        <button onClick={() => window.print()} style={{ ...mono, fontSize: '12px', padding: '6px 16px', borderRadius: '6px', border: `0.5px solid ${D.border}`, background: 'transparent', color: D.textMuted, cursor: 'pointer' }}>
          Print / Export PDF
        </button>
      </div>

      {/* EXECUTIVE MODE — dark */}
      {mode === 'executive' && (
        <div style={{ background: D.bg, borderRadius: '12px', padding: '2rem', border: `0.5px solid ${D.border}` }}>

          {/* Header */}
          <div style={{ textAlign: 'center', marginBottom: '2rem', paddingBottom: '1.5rem', borderBottom: `1px solid ${D.border}` }}>
            <div style={{ ...mono, fontSize: '11px', color: D.textDim, marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '1px' }}>Cybersecurity Risk Summary</div>
            <div style={{ fontSize: '22px', fontWeight: 600, color: D.text, marginBottom: '4px' }}>Security Intelligence Report</div>
            <div style={{ ...mono, fontSize: '12px', color: D.textMuted }}>Generated {today} · Powered by CVE<span style={{ color: '#E24B4A' }}>///</span>INTEL</div>
          </div>

          {/* KPIs */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '1.5rem' }}>
            <ExecKpi
              num={overallRisk}
              label="Overall Risk Level"
              desc={parseInt(posture.kev_total) > 0 ? `${posture.kev_total} actively exploited vulnerabilities confirmed` : `${posture.critical} critical vulnerabilities require attention`}
              color={{ bg: `${riskColor}22`, border: `${riskColor}55`, text: riskColor }}
            />
            <ExecKpi
              num={posture.kev_total}
              label="Actively Exploited"
              desc="Confirmed by US Government (CISA KEV) as exploited in the wild right now"
              color={{ bg: '#2a1010', border: '#E24B4A44', text: '#E24B4A' }}
            />
            <ExecKpi
              num={posture.critical}
              label="Critical Issues"
              desc="Vulnerabilities scoring 75+ requiring immediate action"
              color={{ bg: '#1f1500', border: '#BA751744', text: '#BA7517' }}
            />
          </div>

          {/* Top threats */}
          <Section title="Top threats requiring attention">
            {dash.top_critical.slice(0, 3).map((cve, i) => (
              <div key={cve.cve_id} style={{ display: 'flex', gap: '12px', padding: '12px', background: D.bg2, borderRadius: '8px', marginBottom: '8px', border: `0.5px solid ${D.border}` }}>
                <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: '#E24B4A', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '13px', fontWeight: 600, flexShrink: 0 }}>{i + 1}</div>
                <div>
                  <div style={{ ...mono, fontSize: '12px', fontWeight: 500, color: '#5b9bd5', marginBottom: '3px' }}>
                    {cve.kev_member ? 'Actively Exploited: ' : ''}{cve.cve_id}
                  </div>
                  <div style={{ fontSize: '12px', color: D.textMuted, lineHeight: 1.5 }}>{cve.description}</div>
                  <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                    {cve.kev_member && <span style={{ ...mono, fontSize: '10px', background: '#2a1010', color: '#E24B4A', padding: '2px 6px', borderRadius: '3px', fontWeight: 500 }}>Confirmed Exploited</span>}
                    {!cve.patch_available && <span style={{ ...mono, fontSize: '10px', background: '#1a1010', color: '#A32D2D', padding: '2px 6px', borderRadius: '3px' }}>No patch available</span>}
                    <span style={{ ...mono, fontSize: '10px', background: D.bg3, color: D.textMuted, padding: '2px 6px', borderRadius: '3px' }}>Score: {parseFloat(cve.adjusted_score).toFixed(0)}/100</span>
                  </div>
                </div>
              </div>
            ))}
          </Section>

          {/* Recommended actions */}
          <Section title="Recommended actions">
            {parseInt(posture.kev_total) > 0 && (
              <ActionRow dot="#E24B4A" bg="#1f0a0a"
                label="Act this week"
                desc={`Apply patches or mitigations for ${posture.kev_total} actively exploited vulnerabilities. Confirmed by CISA as being used in real attacks.`}
              />
            )}
            {parseInt(posture.pre_kev_total) > 0 && (
              <ActionRow dot="#BA7517" bg="#1a1000"
                label="Plan this month"
                desc={`Review ${posture.pre_kev_total} vulnerabilities flagged as likely to be exploited soon — early warning before official confirmation.`}
              />
            )}
            <ActionRow dot="#888780" bg={D.bg2}
              label="Ongoing monitoring"
              desc={`${posture.medium} medium-severity vulnerabilities are being monitored. Alerts will fire if any escalate.`}
            />
          </Section>

          {/* Distribution */}
          <Section title="Vulnerability distribution">
            <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
              <PieChart width={180} height={180}>
                <Pie data={pieData} cx={85} cy={85} innerRadius={50} outerRadius={80} dataKey="value" strokeWidth={0}>
                  {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
              </PieChart>
              <div style={{ flex: 1 }}>
                {pieData.map(b => (
                  <div key={b.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ width: '10px', height: '10px', borderRadius: '2px', background: b.color }} />
                      <span style={{ fontSize: '13px', color: D.textMuted }}>{b.name}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                      <span style={{ ...mono, fontSize: '13px', fontWeight: 500, color: D.text }}>{b.value.toLocaleString()}</span>
                      <span style={{ ...mono, fontSize: '11px', color: D.textDim }}>{total > 0 ? ((b.value / total) * 100).toFixed(1) : 0}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Section>

          {/* Footer */}
          <div style={{ textAlign: 'center', paddingTop: '1rem', borderTop: `1px solid ${D.border}`, ...mono, fontSize: '11px', color: D.textDim }}>
            CVE///INTEL · Data sourced from NVD, CISA KEV, EPSS · {today}
          </div>
        </div>
      )}

      {/* TECHNICAL MODE */}
      {mode === 'technical' && (
        <div style={{ background: D.bg, border: `0.5px solid ${D.border}`, borderRadius: '12px', padding: '1.5rem' }}>
          <div style={{ marginBottom: '1.5rem', paddingBottom: '1rem', borderBottom: `0.5px solid ${D.border}` }}>
            <div style={{ ...mono, fontSize: '15px', fontWeight: 500, color: D.text }}>Technical Risk Report</div>
            <div style={{ ...mono, fontSize: '11px', color: D.textDim, marginTop: '2px' }}>Generated {today}</div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '1.25rem' }}>
            {[
              { label: 'Critical',  value: posture.critical,      color: '#E24B4A' },
              { label: 'High',      value: posture.high,          color: '#BA7517' },
              { label: 'KEV',       value: posture.kev_total,     color: '#E24B4A' },
              { label: 'Pre-KEV',   value: posture.pre_kev_total, color: '#534AB7' },
            ].map(k => (
              <div key={k.label} style={{ background: D.bg2, borderRadius: '8px', padding: '12px 14px' }}>
                <div style={{ ...mono, fontSize: '10px', color: D.textDim, textTransform: 'uppercase', marginBottom: '4px' }}>{k.label}</div>
                <div style={{ ...mono, fontSize: '22px', fontWeight: 500, color: k.color }}>{parseInt(k.value).toLocaleString()}</div>
              </div>
            ))}
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <div style={{ ...mono, fontSize: '11px', color: D.textDim, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>Top critical CVEs</div>
            {dash.top_critical.map((cve) => (
              <div key={cve.cve_id} style={{ padding: '10px 14px', background: D.bg2, borderRadius: '8px', marginBottom: '6px', display: 'grid', gridTemplateColumns: '120px 1fr auto auto', gap: '12px', alignItems: 'center' }}>
                <span style={{ ...mono, fontSize: '11px', color: '#5b9bd5' }}>{cve.cve_id}</span>
                <span style={{ fontSize: '12px', color: D.textMuted }}>{cve.description?.slice(0, 70)}...</span>
                <div style={{ display: 'flex', gap: '4px' }}>
                  {cve.kev_member && <span style={{ ...mono, fontSize: '10px', background: '#2a1010', color: '#E24B4A', padding: '2px 5px', borderRadius: '3px' }}>KEV</span>}
                </div>
                <span style={{ ...mono, fontSize: '12px', fontWeight: 500, color: '#E24B4A' }}>{parseFloat(cve.adjusted_score).toFixed(1)}</span>
              </div>
            ))}
          </div>

          <div>
            <div style={{ ...mono, fontSize: '11px', color: D.textDim, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>Platform exposure</div>
            {dash.platforms.map(p => (
              <div key={p.platform_tag} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 14px', background: D.bg2, borderRadius: '6px', marginBottom: '6px' }}>
                <span style={{ ...mono, fontSize: '12px', color: D.textMuted }}>{p.platform_tag}</span>
                <div style={{ display: 'flex', gap: '16px' }}>
                  <span style={{ ...mono, fontSize: '12px', color: '#E24B4A' }}>{p.critical} critical</span>
                  <span style={{ ...mono, fontSize: '12px', color: D.textDim }}>{p.kev} kev</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

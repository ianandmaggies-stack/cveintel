import { useQuery } from '@tanstack/react-query'
import { getBrief } from '../api/brief.js'
import { getBand } from '../utils/scoring.js'
import { truncate } from '../utils/formatters.js'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

// ─── Template journalism engine ───────────────────────────────────────────────

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)]
}

function getGreeting() {
  const h = new Date().getHours()
  if (h < 12) return pick(['Good morning', 'Morning', 'Rise and shine'])
  if (h < 17) return pick(['Good afternoon', 'Afternoon', 'Hello'])
  return pick(['Good evening', 'Evening', 'You need to know'])
}

function severity(critical) {
  if (critical >= 100) return pick(['significantly elevated', 'at a critical level', 'demanding immediate attention'])
  if (critical >= 50)  return pick(['elevated', 'above the normal threshold', 'at a level worth watching'])
  if (critical >= 10)  return pick(['moderate', 'manageable but active', 'steady'])
  return pick(['low', 'relatively quiet', 'within normal range'])
}

function buildNarrative(data) {
  const { current, delta, has_history, new_kev, epss_movers, pre_kev, rising_exploits, active_actors } = data
  const lines = []

  if (!current) {
    return [{ type: 'lead', text: `${getGreeting()}. No snapshot data yet — run an ingest to populate the brief.` }]
  }

  // ── Lead paragraph ──────────────────────────────────────────────────────────
  const parts = []

  // New CVEs overnight
  if (current.new_cves_today > 0) {
    parts.push(pick([
      `${current.new_cves_today.toLocaleString()} new ${current.new_cves_today === 1 ? 'vulnerability was' : 'vulnerabilities were'} published in the last 24 hours`,
      `the vulnerability feed added ${current.new_cves_today.toLocaleString()} new ${current.new_cves_today === 1 ? 'entry' : 'entries'} overnight`,
    ]))
  }

  // Critical count — delta or absolute
  if (has_history && delta?.critical !== null) {
    const d = delta.critical
    if (d > 0)  parts.push(`the critical count climbed by ${d} to ${current.critical.toLocaleString()}`)
    else if (d < 0) parts.push(`the critical count fell by ${Math.abs(d)} to ${current.critical.toLocaleString()}`)
    else parts.push(`critical vulnerabilities held steady at ${current.critical.toLocaleString()}`)
  } else {
    parts.push(`${current.critical.toLocaleString()} critical ${current.critical === 1 ? 'vulnerability is' : 'vulnerabilities are'} currently active`)
  }

  // KEV additions
  if (current.new_cves_today > 0 && new_kev?.length > 0) {
    parts.push(`${new_kev.length} ${new_kev.length === 1 ? 'entry was' : 'entries were'} added to the CISA Known Exploited Vulnerabilities catalogue`)
  }

  const leadSentence = `${getGreeting()}. ${parts.map((p, i) => i === 0 ? p.charAt(0).toUpperCase() + p.slice(1) : p).join('; ')}. `

  // Threat actor context
  let actorSentence = ''
  if (active_actors?.length > 0) {
    const top = active_actors[0]
    actorSentence = pick([
      `The most active tracked threat actor is ${top.display_name}, with ${top.cve_count} mapped ${top.cve_count === 1 ? 'vulnerability' : 'vulnerabilities'} in the intelligence database.`,
      `${top.display_name} remains the most active tracked actor, linked to ${top.cve_count} known ${top.cve_count === 1 ? 'vulnerability' : 'vulnerabilities'}.`,
    ])
  }

  // Posture summary sentence
  const postureSentence = pick([
    `The overall threat posture is ${severity(current.critical)}, with ${current.kev_total.toLocaleString()} confirmed exploited ${current.kev_total === 1 ? 'vulnerability' : 'vulnerabilities'} remaining active and ${current.pre_kev_count.toLocaleString()} early-warning ${current.pre_kev_count === 1 ? 'signal' : 'signals'} in view.`,
    `Across the landscape, ${current.kev_total.toLocaleString()} ${current.kev_total === 1 ? 'vulnerability is' : 'vulnerabilities are'} confirmed as actively exploited in the wild. A further ${current.pre_kev_count.toLocaleString()} ${current.pre_kev_count === 1 ? 'vulnerability carries' : 'vulnerabilities carry'} early signals of imminent exploitation.`,
  ])

  lines.push({
    type: 'lead',
    text: leadSentence + (actorSentence ? actorSentence + ' ' : '') + postureSentence
  })

  // ── KEV additions ────────────────────────────────────────────────────────────
  if (new_kev?.length > 0) {
    const verb = pick(['confirmed', 'catalogued', 'added'])
    const intro = new_kev.length === 1
      ? `CISA ${verb} one new actively-exploited vulnerability to its Known Exploited Vulnerabilities catalogue. KEV listing means real-world attacks have been observed.`
      : `CISA ${verb} ${new_kev.length} new actively-exploited ${pick(['vulnerabilities', 'entries'])} to its Known Exploited Vulnerabilities catalogue this week. Each listing represents a confirmed real-world attack.`
    lines.push({ type: 'kev', heading: 'Known Exploited Vulnerabilities', text: intro, items: new_kev })
  }

  // ── EPSS movers ──────────────────────────────────────────────────────────────
  if (epss_movers?.length > 0) {
    const top = epss_movers[0]
    const pct = (parseFloat(top.epss_delta_7d) * 100).toFixed(1)
    const intro = pick([
      `Exploitation probability is climbing on ${epss_movers.length} ${epss_movers.length === 1 ? 'vulnerability' : 'vulnerabilities'} this week. EPSS measures the likelihood of exploitation in the wild — sharp rises here are an early warning to act before attacks materialise.`,
      `${epss_movers.length} ${epss_movers.length === 1 ? 'vulnerability has' : 'vulnerabilities have'} seen significant rises in exploitation likelihood over the past 7 days. The sharpest: ${top.cve_id} moved +${pct} percentage points. When EPSS climbs this fast, KEV listing often follows.`,
    ])
    lines.push({ type: 'epss', heading: 'Rising Exploitation Probability', text: intro, items: epss_movers })
  }

  // ── Pre-KEV signals ───────────────────────────────────────────────────────────
  if (pre_kev?.length > 0) {
    const intro = pick([
      `${pre_kev.length} ${pre_kev.length === 1 ? 'vulnerability is' : 'vulnerabilities are'} showing early signals consistent with KEV listing — projected based on exploit availability, EPSS trajectory, and historical patterns. These are not yet confirmed as exploited, but the indicators warrant attention ahead of any official advisory.`,
      `Our model has flagged ${pre_kev.length} projected KEV ${pre_kev.length === 1 ? 'candidate' : 'candidates'}. These are vulnerabilities where the combination of exploit availability, rising EPSS score, and threat actor behaviour suggests active exploitation is likely before official confirmation arrives. Treat them as early warnings.`,
    ])
    lines.push({ type: 'prekev', heading: 'Projected KEV Candidates', text: intro, items: pre_kev })
  }

  // ── Rising exploits / no patch ───────────────────────────────────────────────
  if (rising_exploits?.length > 0) {
    const intro = pick([
      `${rising_exploits.length} exploitable ${rising_exploits.length === 1 ? 'vulnerability has' : 'vulnerabilities have'} no patch available. These carry elevated and sustained risk until vendors respond — network-based exploitation without a patch means exposure cannot be closed through normal remediation channels.`,
      `Watch: ${rising_exploits.length} ${rising_exploits.length === 1 ? 'vulnerability' : 'vulnerabilities'} with known public exploits remain unpatched. Without a vendor fix available, the only options are compensating controls — network segmentation, access restriction, or temporary service suspension.`,
    ])
    lines.push({ type: 'exploit', heading: 'Exploitable — No Patch Available', text: intro, items: rising_exploits })
  }

  // ── Quiet day fallback ────────────────────────────────────────────────────────
  if (lines.length === 1) {
    lines.push({
      type: 'quiet',
      text: pick([
        `No new KEV additions, no sharp EPSS spikes, no newly confirmed exploits without patches. The landscape is stable today — ${current.kev_total.toLocaleString()} known-exploited ${current.kev_total === 1 ? 'vulnerability remains' : 'vulnerabilities remain'} active, and monitoring continues.`,
        `A steady day in the threat landscape. ${current.critical.toLocaleString()} critical ${current.critical === 1 ? 'vulnerability remains' : 'vulnerabilities remain'} in view, no new confirmed exploits were catalogued, and no EPSS scores moved significantly. Continue standard monitoring.`,
      ])
    })
  }

  return lines
}

// ─── Sub-components ────────────────────────────────────────────────────────────

function ScorePill({ score }) {
  const band = getBand(score)
  return (
    <span style={{ ...mono, fontSize: '11px', fontWeight: 500, padding: '2px 7px', borderRadius: '4px', background: band.bg, color: band.text }}>
      {parseFloat(score).toFixed(1)}
    </span>
  )
}

function Tag({ children, bg, text }) {
  return (
    <span style={{ ...mono, fontSize: '10px', fontWeight: 500, padding: '2px 6px', borderRadius: '3px', background: bg, color: text }}>
      {children}
    </span>
  )
}

function CveRow({ cve, showEpss }) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '130px 1fr auto auto',
      gap: '12px',
      alignItems: 'center',
      padding: '9px 14px',
      borderBottom: '0.5px solid #1a1a1a',
    }}>
      <span style={{ ...mono, fontSize: '11px', color: '#5b9bd5' }}>{cve.cve_id}</span>
      <div>
        <div style={{ fontSize: '12px', color: '#e5e5e5' }}>{truncate(cve.description || cve.vulnerability_name, 72)}</div>
        <div style={{ ...mono, fontSize: '10px', color: '#555', marginTop: '2px' }}>
          {cve.attack_vector && <span>{cve.attack_vector}</span>}
          {cve.patch_available === false && <span style={{ color: '#BA7517' }}> · no patch</span>}
          {showEpss && cve.epss_delta_7d && <span style={{ color: '#534AB7' }}> · +{(parseFloat(cve.epss_delta_7d)*100).toFixed(1)}pp 7d</span>}
          {cve.pre_kev_score && <span style={{ color: '#534AB7' }}> · pre-kev score {cve.pre_kev_score}</span>}
          {cve.date_added && <span> · KEV {cve.date_added?.split('T')[0]}</span>}
        </div>
      </div>
      <div style={{ display: 'flex', gap: '4px' }}>
        {cve.kev_member   && <Tag bg="#FCEBEB" text="#A32D2D">KEV</Tag>}
        {cve.exploit_available && <Tag bg="#FAEEDA" text="#854F0B">EXPLOIT</Tag>}
      </div>
      {cve.adjusted_score && <ScorePill score={cve.adjusted_score} />}
    </div>
  )
}

function Section({ block }) {
  const accentMap = {
    kev:     { color: '#E24B4A', border: '#3a1a1a' },
    epss:    { color: '#534AB7', border: '#1a1a2a' },
    prekev:  { color: '#534AB7', border: '#1a1a2a' },
    exploit: { color: '#BA7517', border: '#2a1800' },
    quiet:   { color: '#1D9E75', border: '#0a2a1a' },
  }
  const accent = accentMap[block.type] || { color: '#666', border: '#2a2a2a' }

  return (
    <div style={{
      background: '#111',
      border: `0.5px solid ${accent.border}`,
      borderLeft: `2px solid ${accent.color}`,
      borderRadius: '8px',
      overflow: 'hidden',
      marginBottom: '12px',
    }}>
      {block.heading && (
        <div style={{ padding: '8px 14px', borderBottom: '0.5px solid #1a1a1a' }}>
          <span style={{ ...mono, fontSize: '10px', color: accent.color, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            {block.heading}
          </span>
        </div>
      )}
      <div style={{ padding: '12px 14px', fontSize: '13px', color: '#aaa', lineHeight: 1.75 }}>
        {block.text}
      </div>
      {block.items?.length > 0 && (
        <div style={{ borderTop: '0.5px solid #1a1a1a' }}>
          {block.items.map(cve => (
            <CveRow key={cve.cve_id} cve={cve} showEpss={block.type === 'epss'} />
          ))}
        </div>
      )}
    </div>
  )
}

function StatPill({ label, value, delta, color }) {
  const showDelta = delta !== null && delta !== undefined
  const isUp      = delta > 0
  const isDown    = delta < 0
  return (
    <div style={{
      background: '#111',
      border: '0.5px solid #2a2a2a',
      borderRadius: '8px',
      padding: '12px 16px',
      display: 'flex',
      flexDirection: 'column',
      gap: '4px',
    }}>
      <div style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</div>
      <div style={{ ...mono, fontSize: '22px', fontWeight: 500, color: color || '#e5e5e5', lineHeight: 1 }}>{value?.toLocaleString()}</div>
      {showDelta && (
        <div style={{ ...mono, fontSize: '10px', color: isUp ? '#E24B4A' : isDown ? '#1D9E75' : '#555' }}>
          {isUp ? `▲ +${delta}` : isDown ? `▼ ${delta}` : '— no change'} since yesterday
        </div>
      )}
      {!showDelta && (
        <div style={{ ...mono, fontSize: '10px', color: '#333' }}>no prior snapshot</div>
      )}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Brief() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['brief'],
    queryFn:  getBrief,
    staleTime: 5 * 60 * 1000,
    refetchInterval: 10 * 60 * 1000,
  })

  if (isLoading) return (
    <div style={{ ...mono, color: '#555', padding: '3rem 0', textAlign: 'center', fontSize: '12px' }}>
      Assembling your brief...
    </div>
  )

  if (error) return (
    <div style={{ ...mono, color: '#E24B4A', padding: '2rem' }}>Failed to load brief</div>
  )

  const narrative = buildNarrative(data)
  const { current, delta } = data
  const today = new Date().toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })

  return (
    <div style={{ maxWidth: '860px' }}>

      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ fontSize: '15px', fontWeight: 500, color: '#e5e5e5' }}>Morning Brief</div>
        <div style={{ ...mono, fontSize: '11px', color: '#444', marginTop: '2px' }}>{today}</div>
      </div>

      {/* Lead paragraph */}
      <div style={{
        fontSize: '14px',
        lineHeight: 1.85,
        color: '#bbb',
        marginBottom: '1.75rem',
        paddingBottom: '1.5rem',
        borderBottom: '0.5px solid #1a1a1a',
        fontWeight: 300,
        maxWidth: '720px',
      }}>
        {narrative[0]?.text}
      </div>

      {/* Stat strip */}
      {current && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '1.5rem' }}>
          <StatPill label="Critical"     value={current.critical}      delta={delta?.critical} color="#E24B4A" />
          <StatPill label="KEV Active"   value={current.kev_total}     delta={delta?.kev}      color="#E24B4A" />
          <StatPill label="Pre-KEV"      value={current.pre_kev_count} delta={delta?.pre_kev}  color="#534AB7" />
          <StatPill label="With Exploit" value={current.exploit_count} delta={null}            color="#BA7517" />
        </div>
      )}

      {/* Intelligence sections */}
      {narrative.slice(1).map((block, i) => (
        <Section key={i} block={block} />
      ))}

      {/* Footer */}
      <div style={{ ...mono, fontSize: '10px', color: '#222', marginTop: '2rem', textAlign: 'right' }}>
        CVE /// INTEL · Brief refreshes every 10 minutes
      </div>

    </div>
  )
}

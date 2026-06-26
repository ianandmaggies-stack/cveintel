import { useQuery } from '@tanstack/react-query'
import { getBrief } from '../api/brief.js'
import { getBand } from '../utils/scoring.js'
import { truncate } from '../utils/formatters.js'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

// ─── Template journalism engine ────────────────────────────────────────────

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)]
}

function getGreeting() {
  const h = new Date().getHours()
  if (h < 12) return pick(['Good morning', 'Morning', 'Rise and shine'])
  if (h < 17) return pick(['Good afternoon', 'Afternoon', 'Hello'])
  return pick(['Good evening', 'Evening', 'You need to know'])
}

function fmtDelta(n, noun, opts = {}) {
  if (n === null || n === undefined) return null
  const { up = 'rose', down = 'dropped', flat = 'unchanged' } = opts
  if (n === 0) return `${noun} ${flat}`
  const dir  = n > 0 ? up   : down
  const abs  = Math.abs(n)
  return `${noun} ${dir} by ${abs.toLocaleString()}`
}

function buildNarrative(data) {
  const { current, delta, has_history, new_kev, epss_movers, pre_kev, rising_exploits } = data
  const lines = []

  // ── Opener ──
  if (!current) {
    return [{ type: 'lead', text: `${getGreeting()}. No snapshot data yet — run an ingest to populate the brief.` }]
  }

  // ── Lead sentence ──
  const newCvePhrase = current.new_cves_today > 0
    ? pick([
        `${current.new_cves_today.toLocaleString()} new ${current.new_cves_today === 1 ? 'vulnerability was' : 'vulnerabilities were'} published`,
        `${current.new_cves_today.toLocaleString()} new ${current.new_cves_today === 1 ? 'CVE came' : 'CVEs came'} into view`,
        `the feed ${current.new_cves_today === 1 ? 'added' : 'brought in'} ${current.new_cves_today.toLocaleString()} new ${current.new_cves_today === 1 ? 'entry' : 'entries'}`,
      ])
    : null

  const critPhrase = has_history && delta
    ? fmtDelta(delta.critical, 'critical count',  { up: 'climbed', down: 'fell', flat: 'held steady' })
    : `${current.critical.toLocaleString()} critical ${current.critical === 1 ? 'vulnerability is' : 'vulnerabilities are'} active`

  if (newCvePhrase && critPhrase) {
    lines.push({ type: 'lead', text: `${getGreeting()}. In the last 24 hours, ${newCvePhrase}. The ${critPhrase}.` })
  } else if (critPhrase) {
    lines.push({ type: 'lead', text: `${getGreeting()}. The ${critPhrase}.` })
  } else {
    lines.push({ type: 'lead', text: `${getGreeting()}. Here is today's threat summary.` })
  }

  // ── KEV additions ──
  if (new_kev?.length > 0) {
    const verb = pick(['confirmed', 'catalogued', 'added'])
    const intro = new_kev.length === 1
      ? `CISA ${verb} one new actively-exploited vulnerability`
      : `CISA ${verb} ${new_kev.length} new actively-exploited ${pick(['vulnerabilities', 'entries'])} to the Known Exploited Vulnerabilities catalogue`
    lines.push({ type: 'kev', heading: 'Known Exploited Vulnerabilities', text: intro + '.', items: new_kev })
  }

  // ── EPSS movers ──
  if (epss_movers?.length > 0) {
    const top = epss_movers[0]
    const pct = (parseFloat(top.epss_delta_7d) * 100).toFixed(1)
    const intro = pick([
      `Exploitation probability is climbing on ${epss_movers.length} ${epss_movers.length === 1 ? 'vulnerability' : 'vulnerabilities'}.`,
      `${epss_movers.length} ${epss_movers.length === 1 ? 'vulnerability has' : 'vulnerabilities have'} seen notable rises in exploitation likelihood this week.`,
    ])
    const detail = `The sharpest move: ${top.cve_id} jumped ${pct} points in 7 days.`
    lines.push({ type: 'epss', heading: 'Rising Exploitation Probability', text: `${intro} ${detail}`, items: epss_movers })
  }

  // ── Pre-KEV signals ──
  if (pre_kev?.length > 0) {
    const intro = pick([
      `${pre_kev.length} ${pre_kev.length === 1 ? 'vulnerability is' : 'vulnerabilities are'} showing early signals consistent with KEV listing.`,
      `Our model has flagged ${pre_kev.length} projected KEV ${pre_kev.length === 1 ? 'candidate' : 'candidates'} — watch these.`,
    ])
    lines.push({ type: 'prekev', heading: 'Projected KEV Candidates', text: intro, items: pre_kev })
  }

  // ── Rising exploits / no patch ──
  if (rising_exploits?.length > 0) {
    const intro = pick([
      `${rising_exploits.length} exploitable ${rising_exploits.length === 1 ? 'vulnerability has' : 'vulnerabilities have'} no patch available — these carry elevated risk until vendors respond.`,
      `Watch out: ${rising_exploits.length} ${rising_exploits.length === 1 ? 'vulnerability' : 'vulnerabilities'} with known exploits remain unpatched.`,
    ])
    lines.push({ type: 'exploit', heading: 'Exploitable — No Patch', text: intro, items: rising_exploits })
  }

  // ── Quiet day fallback ──
  if (lines.length === 1) {
    lines.push({
      type: 'quiet',
      text: pick([
        `No new KEV additions, no sharp EPSS spikes. A steady day — ${current.kev_total.toLocaleString()} known-exploited vulnerabilities remain active.`,
        `The landscape is stable today. ${current.critical.toLocaleString()} critical vulnerabilities remain in view; no new confirmed exploits were catalogued.`,
      ])
    })
  }

  return lines
}

// ─── Sub-components ────────────────────────────────────────────────────────

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
        {cve.kev_member && <Tag bg="#FCEBEB" text="#A32D2D">KEV</Tag>}
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
        <div style={{
          padding: '8px 14px',
          borderBottom: '0.5px solid #1a1a1a',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
        }}>
          <span style={{ ...mono, fontSize: '10px', color: accent.color, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            {block.heading}
          </span>
        </div>
      )}
      <div style={{ padding: '12px 14px', fontSize: '13px', color: '#aaa', lineHeight: 1.65 }}>
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

// ─── Main page ─────────────────────────────────────────────────────────────

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

      {/* Lead narrative — first block always plain text */}
      <div style={{
        fontSize: '15px',
        lineHeight: 1.75,
        color: '#ccc',
        marginBottom: '1.75rem',
        paddingBottom: '1.5rem',
        borderBottom: '0.5px solid #1a1a1a',
        fontWeight: 300,
      }}>
        {narrative[0]?.text}
      </div>

      {/* Stat strip */}
      {current && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '1.5rem' }}>
          <StatPill label="Critical"    value={current.critical}      delta={delta?.critical} color="#E24B4A" />
          <StatPill label="KEV Active"  value={current.kev_total}     delta={delta?.kev}      color="#E24B4A" />
          <StatPill label="Pre-KEV"     value={current.pre_kev_count} delta={delta?.pre_kev}  color="#534AB7" />
          <StatPill label="With Exploit" value={current.exploit_count} delta={null}            color="#BA7517" />
        </div>
      )}

      {/* Intelligence sections */}
      {narrative.slice(1).map((block, i) => (
        <Section key={i} block={block} />
      ))}

      {/* Footer */}
      <div style={{ ...mono, fontSize: '10px', color: '#2a2a2a', marginTop: '2rem', textAlign: 'right' }}>
        CVE /// INTEL · Brief refreshes every 10 minutes
      </div>

    </div>
  )
}

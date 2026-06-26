const mono = { fontFamily: 'JetBrains Mono, monospace' }

const SOURCES = [
  {
    name: 'NVD — National Vulnerability Database',
    org: 'NIST / US Government',
    url: 'https://nvd.nist.gov',
    cadence: 'Daily delta · Weekly full',
    description: 'The authoritative source for CVE data. Every published vulnerability, its CVSS score, affected products (CPE), and patch status comes from NVD. Over 340,000 CVEs tracked.',
    color: '#5b9bd5',
  },
  {
    name: 'CISA KEV — Known Exploited Vulnerabilities',
    org: 'CISA / US Government',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    cadence: 'Daily',
    description: 'The US Government\'s definitive list of vulnerabilities confirmed as actively exploited in real-world attacks. KEV listing is the clearest signal that a vulnerability is being weaponised right now.',
    color: '#E24B4A',
  },
  {
    name: 'EPSS — Exploit Prediction Scoring System',
    org: 'FIRST.org',
    url: 'https://www.first.org/epss',
    cadence: 'Daily',
    description: 'A machine-learning model that predicts the probability of a CVE being exploited in the wild within 30 days. CVE Intel tracks EPSS score changes over time — a sharp rise is an early warning signal before exploitation is confirmed.',
    color: '#534AB7',
  },
  {
    name: 'ExploitDB',
    org: 'Offensive Security',
    url: 'https://www.exploit-db.com',
    cadence: 'Weekly',
    description: 'A public archive of working exploit code. When a CVE appears here, it means a usable attack tool exists — not just a theoretical risk. CVE Intel flags these as EXPLOIT and factors them into the risk score.',
    color: '#BA7517',
  },
  {
    name: 'Metasploit Framework',
    org: 'Rapid7 / Open Source',
    url: 'https://www.metasploit.com',
    cadence: 'Weekly',
    description: 'The most widely used penetration testing framework. If a CVE has a Metasploit module, attackers can exploit it with a single command. This is the highest-confidence exploit signal tracked.',
    color: '#BA7517',
  },
  {
    name: 'MITRE ATT&CK + CISA Advisories',
    org: 'MITRE / CISA',
    url: 'https://attack.mitre.org',
    cadence: 'Seeded · Expanding',
    description: 'Threat actor data — who they are, what they target, who they\'re backed by. Currently seeded with 21 tracked actors from MITRE ATT&CK and CISA threat advisories, with CVE-to-actor mapping planned.',
    color: '#1D9E75',
  },
]

const SCORING = [
  { component: 'CVSS Base',         max: 20,  color: '#5b9bd5',  desc: 'Raw severity from NVD. Scaled from the 0–10 CVSS score.' },
  { component: 'EPSS Score',         max: 25,  color: '#534AB7',  desc: 'Exploitation probability. Higher probability = higher score.' },
  { component: 'EPSS Velocity',      max: 10,  color: '#534AB7',  desc: 'How fast the EPSS score is climbing over 7 days. Rising fast = act faster.' },
  { component: 'KEV Membership',     max: 25,  color: '#E24B4A',  desc: 'CISA confirmed active exploitation. Largest single signal.' },
  { component: 'Exploit Available',  max: 10,  color: '#BA7517',  desc: 'Public exploit in ExploitDB or Metasploit. Suppressed if KEV (already captured above).' },
  { component: 'No Patch',           max: 10,  color: '#A32D2D',  desc: 'Extra weight when no vendor fix exists. Elevated risk with no closure available.' },
]

function Card({ children, style }) {
  return (
    <div style={{
      background: '#111', border: '0.5px solid #2a2a2a',
      borderRadius: '10px', padding: '20px', ...style
    }}>
      {children}
    </div>
  )
}

export default function About() {
  return (
    <div style={{ maxWidth: '860px' }}>

      {/* Hero */}
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ fontSize: '22px', fontWeight: 600, color: '#e5e5e5', marginBottom: '6px' }}>
          CVE<span style={{ color: '#E24B4A' }}>///</span>INTEL
        </div>
        <div style={{ fontSize: '14px', color: '#888', lineHeight: 1.75, maxWidth: '640px' }}>
          A real-time vulnerability intelligence platform that turns raw CVE data into
          actionable threat awareness. Built for IT professionals who need to understand
          what is being exploited right now — not what exists in a database.
        </div>
      </div>

      {/* What it does */}
      <Card style={{ marginBottom: '12px' }}>
        <div style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '14px' }}>What this tool does</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
          {[
            { title: 'Morning Brief',      desc: 'Every day opens with a plain-English summary of what changed overnight — new exploited vulnerabilities, rising EPSS scores, and the overall threat posture.' },
            { title: 'Prioritised Risk',   desc: 'CVEs are scored using a multi-factor model combining CVSS severity, exploitation probability, confirmed exploits, KEV status, and patch availability.' },
            { title: 'Pre-KEV Signals',    desc: 'Before CISA confirms active exploitation, CVE Intel flags vulnerabilities showing early indicators. These are projected candidates, not confirmed — but worth watching first.' },
            { title: 'Threat Landscape',   desc: 'Track 21 known threat actors by type, country, and target sector. See geopolitical events mapped against the vulnerability timeline.' },
            { title: 'Executive Reports',  desc: 'Generate board-ready risk summaries or detailed technical breakdowns. Plain English where it counts; raw data where it helps.' },
            { title: 'Full CVE Detail',    desc: 'Every CVE includes its score breakdown, EPSS trend chart, affected products, CVSS vector, and exploit history — all in one place.' },
          ].map(({ title, desc }) => (
            <div key={title}>
              <div style={{ fontSize: '13px', fontWeight: 500, color: '#e5e5e5', marginBottom: '4px' }}>{title}</div>
              <div style={{ fontSize: '12px', color: '#888', lineHeight: 1.6 }}>{desc}</div>
            </div>
          ))}
        </div>
      </Card>

      {/* Scoring model */}
      <Card style={{ marginBottom: '12px' }}>
        <div style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '14px' }}>Scoring model — how risk scores are calculated</div>
        <div style={{ fontSize: '12px', color: '#888', lineHeight: 1.6, marginBottom: '14px' }}>
          CVE Intel does not use CVSS scores alone. A vulnerability can have a high CVSS score but near-zero
          exploitation probability — and vice versa. The adjusted score combines six signals, each capped at
          a maximum contribution, to produce a 0–100 score that reflects real-world risk.
        </div>
        {SCORING.map(s => (
          <div key={s.component} style={{ display: 'grid', gridTemplateColumns: '160px 40px 1fr', gap: '12px', alignItems: 'center', marginBottom: '8px' }}>
            <div style={{ ...mono, fontSize: '11px', color: s.color }}>{s.component}</div>
            <div style={{ ...mono, fontSize: '11px', color: '#555', textAlign: 'right' }}>/{s.max}</div>
            <div style={{ fontSize: '11px', color: '#666', lineHeight: 1.5 }}>{s.desc}</div>
          </div>
        ))}
        <div style={{ borderTop: '0.5px solid #2a2a2a', marginTop: '12px', paddingTop: '10px', ...mono, fontSize: '11px', color: '#555' }}>
          Scores are also modified by attack vector — network-based attacks score higher than local-only vulnerabilities.
        </div>
      </Card>

      {/* Data sources */}
      <div style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px', marginTop: '1.5rem' }}>Data sources</div>
      {SOURCES.map(source => (
        <Card key={source.name} style={{ marginBottom: '8px', borderLeft: `2px solid ${source.color}22` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
            <div>
              <div style={{ fontSize: '13px', fontWeight: 500, color: '#e5e5e5' }}>{source.name}</div>
              <div style={{ ...mono, fontSize: '10px', color: '#555', marginTop: '2px' }}>{source.org}</div>
            </div>
            <div style={{ ...mono, fontSize: '10px', color: source.color, background: source.color + '18', padding: '2px 8px', borderRadius: '10px', flexShrink: 0 }}>
              {source.cadence}
            </div>
          </div>
          <div style={{ fontSize: '12px', color: '#888', lineHeight: 1.6 }}>{source.description}</div>
        </Card>
      ))}

      {/* Footer note */}
      <div style={{ ...mono, fontSize: '11px', color: '#333', marginTop: '2rem', paddingTop: '1rem', borderTop: '0.5px solid #1a1a1a', lineHeight: 1.6 }}>
        CVE Intel does not generate or invent vulnerability data. Every data point originates from
        the authoritative sources listed above. Intelligence is derived — scores, signals, projections
        — but the underlying facts come from NIST, CISA, FIRST, and the security research community.
      </div>
    </div>
  )
}

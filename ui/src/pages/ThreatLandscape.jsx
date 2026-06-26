import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getLandscape } from '../api/landscape.js'
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

const ACTOR_TYPE_LABELS = {
  state_sanctioned: { label: 'State Sanctioned', color: '#E24B4A', bg: '#2a1010' },
  state_affiliated: { label: 'State Affiliated', color: '#BA7517', bg: '#1a1000' },
  criminal:         { label: 'Criminal',         color: '#534AB7', bg: '#12102a' },
  hacktivist:       { label: 'Hacktivist',        color: '#888780', bg: '#1a1a1a' },
  opportunistic:    { label: 'Opportunistic',     color: '#555',    bg: '#111'    },
}

// Full country code -> name mapping
const COUNTRY_NAMES = {
  AF: 'Afghanistan',        AL: 'Albania',            DZ: 'Algeria',
  AD: 'Andorra',            AO: 'Angola',             AG: 'Antigua and Barbuda',
  AR: 'Argentina',          AM: 'Armenia',            AU: 'Australia',
  AT: 'Austria',            AZ: 'Azerbaijan',         BS: 'Bahamas',
  BH: 'Bahrain',            BD: 'Bangladesh',         BB: 'Barbados',
  BY: 'Belarus',            BE: 'Belgium',            BZ: 'Belize',
  BJ: 'Benin',              BT: 'Bhutan',             BO: 'Bolivia',
  BA: 'Bosnia and Herzegovina', BW: 'Botswana',       BR: 'Brazil',
  BN: 'Brunei',             BG: 'Bulgaria',           BF: 'Burkina Faso',
  BI: 'Burundi',            CV: 'Cabo Verde',         KH: 'Cambodia',
  CM: 'Cameroon',           CA: 'Canada',             CF: 'Central African Republic',
  TD: 'Chad',               CL: 'Chile',              CN: 'China',
  CO: 'Colombia',           KM: 'Comoros',            CG: 'Congo',
  CD: 'DR Congo',           CR: 'Costa Rica',         HR: 'Croatia',
  CU: 'Cuba',               CY: 'Cyprus',             CZ: 'Czech Republic',
  DK: 'Denmark',            DJ: 'Djibouti',           DM: 'Dominica',
  DO: 'Dominican Republic', EC: 'Ecuador',            EG: 'Egypt',
  SV: 'El Salvador',        GQ: 'Equatorial Guinea',  ER: 'Eritrea',
  EE: 'Estonia',            SZ: 'Eswatini',           ET: 'Ethiopia',
  FJ: 'Fiji',               FI: 'Finland',            FR: 'France',
  GA: 'Gabon',              GM: 'Gambia',             GE: 'Georgia',
  DE: 'Germany',            GH: 'Ghana',              GR: 'Greece',
  GD: 'Grenada',            GT: 'Guatemala',          GN: 'Guinea',
  GW: 'Guinea-Bissau',      GY: 'Guyana',             HT: 'Haiti',
  HN: 'Honduras',           HU: 'Hungary',            IS: 'Iceland',
  IN: 'India',              ID: 'Indonesia',           IR: 'Iran',
  IQ: 'Iraq',               IE: 'Ireland',            IL: 'Israel',
  IT: 'Italy',              JM: 'Jamaica',             JP: 'Japan',
  JO: 'Jordan',             KZ: 'Kazakhstan',          KE: 'Kenya',
  KI: 'Kiribati',           KP: 'North Korea',        KR: 'South Korea',
  KW: 'Kuwait',             KG: 'Kyrgyzstan',          LA: 'Laos',
  LV: 'Latvia',             LB: 'Lebanon',            LS: 'Lesotho',
  LR: 'Liberia',            LY: 'Libya',              LI: 'Liechtenstein',
  LT: 'Lithuania',          LU: 'Luxembourg',         MG: 'Madagascar',
  MW: 'Malawi',             MY: 'Malaysia',            MV: 'Maldives',
  ML: 'Mali',               MT: 'Malta',              MH: 'Marshall Islands',
  MR: 'Mauritania',         MU: 'Mauritius',           MX: 'Mexico',
  FM: 'Micronesia',         MD: 'Moldova',             MC: 'Monaco',
  MN: 'Mongolia',           ME: 'Montenegro',          MA: 'Morocco',
  MZ: 'Mozambique',         MM: 'Myanmar',             NA: 'Namibia',
  NR: 'Nauru',              NP: 'Nepal',               NL: 'Netherlands',
  NZ: 'New Zealand',        NI: 'Nicaragua',           NE: 'Niger',
  NG: 'Nigeria',            MK: 'North Macedonia',     NO: 'Norway',
  OM: 'Oman',               PK: 'Pakistan',            PW: 'Palau',
  PA: 'Panama',             PG: 'Papua New Guinea',    PY: 'Paraguay',
  PE: 'Peru',               PH: 'Philippines',         PL: 'Poland',
  PT: 'Portugal',           QA: 'Qatar',               RO: 'Romania',
  RU: 'Russia',             RW: 'Rwanda',              KN: 'Saint Kitts and Nevis',
  LC: 'Saint Lucia',        VC: 'Saint Vincent',       WS: 'Samoa',
  SM: 'San Marino',         ST: 'Sao Tome and Principe', SA: 'Saudi Arabia',
  SN: 'Senegal',            RS: 'Serbia',              SC: 'Seychelles',
  SL: 'Sierra Leone',       SG: 'Singapore',           SK: 'Slovakia',
  SI: 'Slovenia',           SB: 'Solomon Islands',     SO: 'Somalia',
  ZA: 'South Africa',       SS: 'South Sudan',         ES: 'Spain',
  LK: 'Sri Lanka',          SD: 'Sudan',               SR: 'Suriname',
  SE: 'Sweden',             CH: 'Switzerland',         SY: 'Syria',
  TW: 'Taiwan',             TJ: 'Tajikistan',          TZ: 'Tanzania',
  TH: 'Thailand',           TL: 'Timor-Leste',         TG: 'Togo',
  TO: 'Tonga',              TT: 'Trinidad and Tobago', TN: 'Tunisia',
  TR: 'Turkey',             TM: 'Turkmenistan',        TV: 'Tuvalu',
  UG: 'Uganda',             UA: 'Ukraine',             AE: 'United Arab Emirates',
  GB: 'United Kingdom',     US: 'United States',       UY: 'Uruguay',
  UZ: 'Uzbekistan',         VU: 'Vanuatu',             VE: 'Venezuela',
  VN: 'Vietnam',            YE: 'Yemen',               ZM: 'Zambia',
  ZW: 'Zimbabwe',
}

const COUNTRY_FLAGS = {
  CN: '\u{1F1E8}\u{1F1F3}',
  RU: '\u{1F1F7}\u{1F1FA}',
  KP: '\u{1F1F0}\u{1F1F5}',
  IR: '\u{1F1EE}\u{1F1F7}',
  UA: '\u{1F1FA}\u{1F1E6}',
  US: '\u{1F1FA}\u{1F1F8}',
  GB: '\u{1F1EC}\u{1F1E7}',
  BY: '\u{1F1E7}\u{1F1FE}',
  KR: '\u{1F1F0}\u{1F1F7}',
  IN: '\u{1F1EE}\u{1F1F3}',
  PK: '\u{1F1F5}\u{1F1F0}',
  SY: '\u{1F1F8}\u{1F1FE}',
  VN: '\u{1F1FB}\u{1F1F3}',
  BR: '\u{1F1E7}\u{1F1F7}',
  NG: '\u{1F1F3}\u{1F1EC}',
}

const IMPACT_COLORS = {
  high:   '#E24B4A',
  medium: '#BA7517',
  low:    '#888780'
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

function FlagWithTooltip({ country }) {
  const [hovered, setHovered] = useState(false)
  const flag = COUNTRY_FLAGS[country]
  const name = COUNTRY_NAMES[country] || country

  if (!flag) return (
    <span style={{ fontSize: '14px' }} title={name}>\uD83C\uDF10</span>
  )

  return (
    <span
      style={{ position: 'relative', display: 'inline-block', lineHeight: 1 }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <span style={{ fontSize: '14px', cursor: 'default' }}>{flag}</span>
      {hovered && (
        <span style={{
          position:    'absolute',
          bottom:      '120%',
          left:        '50%',
          transform:   'translateX(-50%)',
          background:  '#1a1a1a',
          border:      '0.5px solid #2a2a2a',
          borderRadius: '4px',
          padding:     '3px 8px',
          whiteSpace:  'nowrap',
          ...mono,
          fontSize:    '10px',
          color:       '#e5e5e5',
          pointerEvents: 'none',
          zIndex:      100,
        }}>
          {name}
        </span>
      )}
    </span>
  )
}

function ActorCard({ actor, onClick, selected }) {
  const type = ACTOR_TYPE_LABELS[actor.actor_type] || ACTOR_TYPE_LABELS.opportunistic
  return (
    <div onClick={() => onClick(actor)}
      style={{
        padding: '10px 12px', borderRadius: '8px', marginBottom: '6px', cursor: 'pointer',
        background:  selected ? type.bg : '#1a1a1a',
        border:      `0.5px solid ${selected ? type.color + '66' : '#2a2a2a'}`,
        transition:  'all 0.15s'
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {actor.country && <FlagWithTooltip country={actor.country} />}
          <span style={{ fontSize: '13px', fontWeight: 500, color: '#e5e5e5' }}>{actor.display_name}</span>
        </div>
        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
          {actor.cve_count > 0 && (
            <span style={{ ...mono, fontSize: '10px', color: type.color, background: type.bg, padding: '1px 6px', borderRadius: '3px' }}>
              {actor.cve_count} CVEs
            </span>
          )}
          <span style={{ ...mono, fontSize: '10px', color: type.color, background: type.bg, padding: '1px 6px', borderRadius: '3px' }}>
            {type.label}
          </span>
        </div>
      </div>
      {actor.also_known_as?.length > 0 && (
        <div style={{ ...mono, fontSize: '10px', color: '#555' }}>
          aka {actor.also_known_as.slice(0, 3).join(', ')}
        </div>
      )}
    </div>
  )
}

export default function ThreatLandscape() {
  const [selectedActor, setSelectedActor] = useState(null)
  const [actorFilter, setActorFilter]     = useState('all')

  const { data, isLoading, error } = useQuery({
    queryKey: ['landscape'],
    queryFn:  getLandscape,
    staleTime: 10 * 60 * 1000
  })

  if (isLoading) return <div style={{ ...mono, color: '#666', padding: '2rem' }}>Loading threat landscape...</div>
  if (error)     return <div style={{ ...mono, color: '#E24B4A', padding: '2rem' }}>Failed to load landscape data</div>

  const { snapshots, actors, events } = data

  const chartData = snapshots.map(s => ({
    date:     s.snapshot_date?.split('T')[0] || s.snapshot_date,
    critical: parseInt(s.critical_count),
    high:     parseInt(s.high_count),
    kev:      parseInt(s.kev_total),
    pre_kev:  parseInt(s.pre_kev_count),
    exploit:  parseInt(s.exploit_count),
    new_cves: parseInt(s.new_cves_today),
    kev_new:  parseInt(s.kev_added_today),
  }))

  const filteredActors = actorFilter === 'all'
    ? actors
    : actors.filter(a => a.actor_type === actorFilter)

  const hasSnapshots = chartData.length > 0

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div>
          <div style={{ fontSize: '15px', fontWeight: 500, color: '#e5e5e5' }}>Threat Landscape</div>
          <div style={{ ...mono, fontSize: '11px', color: '#666', marginTop: '2px' }}>
            {actors.length} tracked actors · {events.length} geopolitical events · {snapshots.length} day{snapshots.length !== 1 ? 's' : ''} of trend data
          </div>
        </div>
      </div>

      {hasSnapshots ? (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
          <Panel title="Critical CVE trend">
            <ResponsiveContainer width="100%" height={120}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a1a" />
                <XAxis dataKey="date" tick={{ ...mono, fontSize: 9, fill: '#555' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis tick={{ ...mono, fontSize: 9, fill: '#555' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '6px', ...mono, fontSize: '11px' }} />
                <Line type="monotone" dataKey="critical" stroke="#E24B4A" strokeWidth={1.5} dot={false} name="Critical" />
                <Line type="monotone" dataKey="kev"      stroke="#BA7517" strokeWidth={1}   dot={false} name="KEV" strokeDasharray="4 2" />
              </LineChart>
            </ResponsiveContainer>
          </Panel>
          <Panel title="Daily KEV additions">
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a1a" />
                <XAxis dataKey="date" tick={{ ...mono, fontSize: 9, fill: '#555' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis tick={{ ...mono, fontSize: 9, fill: '#555' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '6px', ...mono, fontSize: '11px' }} />
                <Bar dataKey="kev_new" fill="#E24B4A" name="New KEV" radius={[2,2,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </Panel>
        </div>
      ) : (
        <Panel title="Trend data">
          <div style={{ ...mono, fontSize: '12px', color: '#555', textAlign: 'center', padding: '1rem' }}>
            Trend data accumulates daily. Check back tomorrow after the first automated ingest runs.
          </div>
        </Panel>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '12px' }}>
        <div>
          <Panel title={`Threat actors — ${filteredActors.length} shown`} style={{ marginBottom: 0 }}>
            <div style={{ display: 'flex', gap: '6px', marginBottom: '12px', flexWrap: 'wrap' }}>
              {[['all', 'All'], ...Object.entries(ACTOR_TYPE_LABELS).map(([k,v]) => [k, v.label])].map(([val, label]) => (
                <button key={val} onClick={() => setActorFilter(val)} style={{
                  ...mono, fontSize: '10px', padding: '3px 10px', borderRadius: '12px',
                  border: '0.5px solid', cursor: 'pointer',
                  background:   actorFilter === val ? '#e5e5e5' : 'transparent',
                  color:        actorFilter === val ? '#0a0a0a' : '#666',
                  borderColor:  actorFilter === val ? '#e5e5e5' : '#2a2a2a'
                }}>{label}</button>
              ))}
            </div>
            {filteredActors.map(actor => (
              <ActorCard
                key={actor.actor_id}
                actor={actor}
                onClick={a => setSelectedActor(selectedActor?.actor_id === a.actor_id ? null : a)}
                selected={selectedActor?.actor_id === actor.actor_id}
              />
            ))}
          </Panel>

          {selectedActor && (
            <Panel title={selectedActor.display_name} style={{ marginTop: '12px' }}>
              <div style={{ marginBottom: '10px' }}>
                <div style={{ ...mono, fontSize: '10px', color: '#555', marginBottom: '4px' }}>TYPE</div>
                <div style={{ fontSize: '12px', color: ACTOR_TYPE_LABELS[selectedActor.actor_type]?.color || '#888', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {selectedActor.country && <FlagWithTooltip country={selectedActor.country} />}
                  {ACTOR_TYPE_LABELS[selectedActor.actor_type]?.label}
                  {selectedActor.country && ` · ${COUNTRY_NAMES[selectedActor.country] || selectedActor.country}`}
                  {selectedActor.country_relationship && ` (${selectedActor.country_relationship})`}
                </div>
              </div>
              {selectedActor.mitre_id && (
                <div style={{ marginBottom: '10px' }}>
                  <div style={{ ...mono, fontSize: '10px', color: '#555', marginBottom: '4px' }}>MITRE ATT&CK</div>
                  <div style={{ ...mono, fontSize: '12px', color: '#5b9bd5' }}>{selectedActor.mitre_id}</div>
                </div>
              )}
              {selectedActor.also_known_as?.length > 0 && (
                <div style={{ marginBottom: '10px' }}>
                  <div style={{ ...mono, fontSize: '10px', color: '#555', marginBottom: '4px' }}>ALSO KNOWN AS</div>
                  <div style={{ fontSize: '12px', color: '#888' }}>{selectedActor.also_known_as.join(', ')}</div>
                </div>
              )}
              {selectedActor.target_sectors?.length > 0 && (
                <div style={{ marginBottom: '10px' }}>
                  <div style={{ ...mono, fontSize: '10px', color: '#555', marginBottom: '6px' }}>TARGET SECTORS</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {selectedActor.target_sectors.map(s => (
                      <span key={s} style={{ ...mono, fontSize: '10px', padding: '2px 6px', borderRadius: '3px', background: '#1a1a1a', color: '#888' }}>{s}</span>
                    ))}
                  </div>
                </div>
              )}
              <div>
                <div style={{ ...mono, fontSize: '10px', color: '#555', marginBottom: '4px' }}>DESCRIPTION</div>
                <div style={{ fontSize: '12px', color: '#888', lineHeight: 1.6 }}>{selectedActor.description}</div>
              </div>
            </Panel>
          )}
        </div>

        <div>
          <Panel title="Geopolitical timeline">
            {events.map((event, i) => (
              <div key={event.event_id} style={{ marginBottom: i < events.length - 1 ? '14px' : 0 }}>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '16px', flexShrink: 0 }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: IMPACT_COLORS[event.impact_level] || '#555', marginTop: '4px', flexShrink: 0 }} />
                    {i < events.length - 1 && <div style={{ width: '1px', flex: 1, background: '#2a2a2a', marginTop: '4px', minHeight: '16px' }} />}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '12px', fontWeight: 500, color: '#e5e5e5', marginBottom: '2px' }}>{event.event_name}</div>
                    <div style={{ ...mono, fontSize: '10px', color: '#555', marginBottom: '4px' }}>
                      {event.event_date?.split('T')[0]} · {event.region}
                    </div>
                    {event.notes && (
                      <div style={{ fontSize: '11px', color: '#666', lineHeight: 1.5 }}>{event.notes}</div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </Panel>
        </div>
      </div>
    </div>
  )
}

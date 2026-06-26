import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getDiagnostics } from '../api/diagnostics.js'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

const JOB_ORDER  = ['nvd', 'epss', 'kev', 'exploits', 'score_refresh']
const JOB_LABELS = {
  nvd:           'NVD',
  epss:          'EPSS',
  kev:           'CISA KEV',
  exploits:      'Exploits',
  score_refresh: 'Score Refresh',
}

const HEALTH = {
  ok:        { color: '#1D9E75', bg: '#0a2a1a', label: 'Healthy',   dot: '#1D9E75' },
  running:   { color: '#5b9bd5', bg: '#0a1a2a', label: 'Running',   dot: '#5b9bd5' },
  stuck:     { color: '#E24B4A', bg: '#2a1010', label: 'STUCK',     dot: '#E24B4A' },
  failed:    { color: '#E24B4A', bg: '#2a1010', label: 'Failed',    dot: '#E24B4A' },
  never_run: { color: '#BA7517', bg: '#1a1000', label: 'Never run', dot: '#BA7517' },
  unknown:   { color: '#555',    bg: '#111',    label: 'Unknown',   dot: '#555'    },
}

function Panel({ title, children, style }) {
  return (
    <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', overflow: 'hidden', marginBottom: '12px', ...style }}>
      <div style={{ padding: '10px 16px', borderBottom: '0.5px solid #1a1a1a' }}>
        <span style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{title}</span>
      </div>
      <div style={{ padding: '14px 16px' }}>{children}</div>
    </div>
  )
}

function fmt(n)      { return parseInt(n || 0).toLocaleString() }
function duration(s) {
  if (!s && s !== 0) return '—'
  if (s < 60)  return `${s}s`
  return `${Math.floor(s/60)}m ${s % 60}s`
}
function relTime(ts) {
  if (!ts) return '—'
  const diff = Date.now() - new Date(ts).getTime()
  const mins = Math.floor(diff / 60000)
  const hrs  = Math.floor(mins / 60)
  const days = Math.floor(hrs / 24)
  if (days > 0)  return `${days}d ago`
  if (hrs > 0)   return `${hrs}h ago`
  if (mins > 0)  return `${mins}m ago`
  return 'just now'
}
function localDt(ts) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('en-GB')
}

export default function Diagnostics() {
  const [activeJob, setActiveJob] = useState('nvd')

  const { data, isLoading, error, dataUpdatedAt, refetch, isFetching } = useQuery({
    queryKey: ['diagnostics'],
    queryFn:  getDiagnostics,
    staleTime: 60 * 1000,
    refetchInterval: 60 * 1000,
  })

  if (isLoading) return (
    <div style={{ ...mono, color: '#555', padding: '3rem 0', textAlign: 'center', fontSize: '12px' }}>Running diagnostics...</div>
  )
  if (error) return (
    <div style={{ ...mono, color: '#E24B4A', padding: '2rem' }}>Failed to load diagnostics: {error.message}</div>
  )

  const { table_counts, job_health, logs_by_job, snapshot_days, db_size, db_online } = data

  const tableMap = {}
  for (const t of table_counts) tableMap[t.table_name] = parseInt(t.row_count)

  const activeLog = logs_by_job[activeJob] || []

  // Overall system health
  const anyStuck  = JOB_ORDER.some(j => job_health[j]?.health_status === 'stuck')
  const anyFailed = JOB_ORDER.some(j => job_health[j]?.health_status === 'failed')
  const allOk     = JOB_ORDER.every(j => ['ok','running','never_run'].includes(job_health[j]?.health_status))
  const sysColor  = anyStuck || anyFailed ? '#E24B4A' : allOk ? '#1D9E75' : '#BA7517'
  const sysLabel  = anyStuck ? 'STUCK JOB DETECTED' : anyFailed ? 'Job failure detected' : allOk ? 'All systems nominal' : 'Attention needed'

  return (
    <div style={{ maxWidth: '1000px' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div>
          <div style={{ fontSize: '15px', fontWeight: 500, color: '#e5e5e5' }}>System Diagnostics</div>
          <div style={{ ...mono, fontSize: '11px', color: '#444', marginTop: '2px' }}>Last refreshed {relTime(dataUpdatedAt)}</div>
        </div>
        <button onClick={() => refetch()} disabled={isFetching}
          style={{ ...mono, fontSize: '11px', padding: '6px 14px', borderRadius: '6px', border: '0.5px solid #2a2a2a', background: 'transparent', color: isFetching ? '#333' : '#888', cursor: isFetching ? 'not-allowed' : 'pointer' }}>
          {isFetching ? 'Refreshing...' : 'Refresh now'}
        </button>
      </div>

      {/* System health banner */}
      <div style={{ background: sysColor + '12', border: `0.5px solid ${sysColor}44`, borderLeft: `3px solid ${sysColor}`, borderRadius: '8px', padding: '12px 16px', marginBottom: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: sysColor }} />
          <span style={{ ...mono, fontSize: '12px', color: sysColor }}>{sysLabel}</span>
        </div>
        <div style={{ display: 'flex', gap: '16px', ...mono, fontSize: '11px', color: '#555' }}>
          <span>DB: <span style={{ color: db_online ? '#1D9E75' : '#E24B4A' }}>{db_online ? 'online' : 'offline'}</span></span>
          <span>Trend history: <span style={{ color: snapshot_days > 1 ? '#1D9E75' : '#BA7517' }}>{snapshot_days} {snapshot_days === 1 ? 'day' : 'days'}</span></span>
          <span>DB size: <span style={{ color: '#e5e5e5' }}>{db_size.total_size}</span></span>
        </div>
      </div>

      {/* Job health cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px', marginBottom: '12px' }}>
        {JOB_ORDER.map(job => {
          const h = job_health[job]
          if (!h) return null
          const style = HEALTH[h.health_status] || HEALTH.unknown
          const lastOk = h.last_success
          return (
            <div key={job} style={{ background: style.bg, border: `0.5px solid ${style.color}44`, borderRadius: '8px', padding: '12px', cursor: 'pointer' }}
              onClick={() => setActiveJob(job)}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                <span style={{ ...mono, fontSize: '11px', color: '#e5e5e5', fontWeight: 500 }}>{JOB_LABELS[job]}</span>
                <span style={{ ...mono, fontSize: '10px', color: style.color, background: style.color + '22', padding: '1px 6px', borderRadius: '8px' }}>{style.label}</span>
              </div>
              {h.is_stuck && (
                <div style={{ ...mono, fontSize: '10px', color: '#E24B4A', marginBottom: '6px' }}>
                  ⚠ Stuck {h.running_hours.toFixed(1)}h
                </div>
              )}
              {h.is_running && !h.is_stuck && (
                <div style={{ ...mono, fontSize: '10px', color: '#5b9bd5', marginBottom: '6px' }}>
                  Running {h.running_hours.toFixed(1)}h
                </div>
              )}
              <div style={{ ...mono, fontSize: '10px', color: '#555' }}>
                <div>Last run: {relTime(h.last_run?.started_at)}</div>
                {lastOk
                  ? <div style={{ color: '#1D9E75', marginTop: '2px' }}>Last OK: {relTime(lastOk.last_success_at)}</div>
                  : <div style={{ color: '#BA7517', marginTop: '2px' }}>No successful run yet</div>
                }
              </div>
              {lastOk && (
                <div style={{ ...mono, fontSize: '10px', color: '#333', marginTop: '6px', borderTop: '0.5px solid #1a1a1a', paddingTop: '6px' }}>
                  ↑ {fmt(lastOk.records_inserted)} inserted · {fmt(lastOk.records_updated)} updated
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Stuck lock warning */}
      {anyStuck && (
        <div style={{ background: '#2a1010', border: '0.5px solid #E24B4A44', borderRadius: '8px', padding: '12px 16px', marginBottom: '12px', ...mono, fontSize: '12px', color: '#E24B4A' }}>
          ⚠ A stuck ingest lock was detected. Run <span style={{ background: '#1a0000', padding: '2px 6px', borderRadius: '3px' }}>./cveintel.sh reset-locks</span> on the server to clear it, then restart.
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>

        {/* Table counts */}
        <Panel title="Table row counts">
          {[
            ['cve_core',            'CVE Core'],
            ['cve_score',           'CVE Scores'],
            ['cve_epss',            'EPSS Records'],
            ['cve_kev',             'KEV Entries'],
            ['cve_exploits',        'Exploit Records'],
            ['cve_cpe',             'CPE Entries'],
            ['threat_actors',       'Threat Actors'],
            ['geopolitical_events', 'Geo Events'],
            ['global_risk_snapshot','Risk Snapshots'],
            ['ingest_log',          'Ingest Log Entries'],
          ].map(([key, label]) => (
            <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '5px 0', borderBottom: '0.5px solid #1a1a1a' }}>
              <span style={{ ...mono, fontSize: '11px', color: '#888' }}>{label}</span>
              <span style={{ ...mono, fontSize: '11px', fontWeight: 500, color: tableMap[key] > 0 ? '#e5e5e5' : '#E24B4A' }}>
                {tableMap[key] !== undefined ? fmt(tableMap[key]) : '—'}
              </span>
            </div>
          ))}
        </Panel>

        {/* Storage breakdown */}
        <Panel title="Storage breakdown">
          {[
            ['cve_core',     db_size.cve_core_size],
            ['cve_cpe',      db_size.cve_cpe_size],
            ['cve_epss',     db_size.cve_epss_size],
            ['cve_score',    db_size.cve_score_size],
            ['cve_exploits', db_size.cve_exploits_size],
          ].map(([label, size]) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '5px 0', borderBottom: '0.5px solid #1a1a1a' }}>
              <span style={{ ...mono, fontSize: '11px', color: '#888' }}>{label}</span>
              <span style={{ ...mono, fontSize: '11px', fontWeight: 500, color: '#e5e5e5' }}>{size}</span>
            </div>
          ))}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0 0 0', marginTop: '4px' }}>
            <span style={{ ...mono, fontSize: '11px', color: '#555' }}>Total database</span>
            <span style={{ ...mono, fontSize: '13px', fontWeight: 500, color: '#e5e5e5' }}>{db_size.total_size}</span>
          </div>
        </Panel>
      </div>

      {/* Ingest run history */}
      <Panel title="Ingest run history">
        <div style={{ display: 'flex', gap: '6px', marginBottom: '14px', flexWrap: 'wrap' }}>
          {JOB_ORDER.map(job => {
            const h = job_health[job]
            const style = HEALTH[h?.health_status || 'unknown']
            return (
              <button key={job} onClick={() => setActiveJob(job)}
                style={{ ...mono, fontSize: '10px', padding: '3px 10px', borderRadius: '10px', border: '0.5px solid', cursor: 'pointer',
                  background:  activeJob === job ? '#e5e5e5' : 'transparent',
                  color:       activeJob === job ? '#0a0a0a' : style.color,
                  borderColor: activeJob === job ? '#e5e5e5' : style.color + '44',
                }}>{JOB_LABELS[job]}</button>
            )
          })}
        </div>

        {activeLog.length === 0 ? (
          <div style={{ ...mono, fontSize: '12px', color: '#444', padding: '1rem 0' }}>No runs recorded for {JOB_LABELS[activeJob]} yet.</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase' }}>
                  {['Started', 'Completed', 'Status', 'Duration', 'Fetched', 'Inserted', 'Updated', 'Failed', 'Error'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 'normal', borderBottom: '0.5px solid #1a1a1a', whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {activeLog.map((log, i) => (
                  <tr key={i}
                    onMouseEnter={e => e.currentTarget.style.background = '#1a1a1a'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                    <td style={{ ...mono, fontSize: '11px', color: '#888', padding: '6px 8px', whiteSpace: 'nowrap' }}>{localDt(log.started_at)}</td>
                    <td style={{ ...mono, fontSize: '11px', color: '#666', padding: '6px 8px', whiteSpace: 'nowrap' }}>{localDt(log.completed_at)}</td>
                    <td style={{ ...mono, fontSize: '11px', padding: '6px 8px' }}>
                      <span style={{ color: log.status === 'success' ? '#1D9E75' : log.status === 'running' ? '#5b9bd5' : '#E24B4A' }}>
                        {log.status}
                      </span>
                    </td>
                    <td style={{ ...mono, fontSize: '11px', color: '#666',    padding: '6px 8px' }}>{duration(log.duration_seconds)}</td>
                    <td style={{ ...mono, fontSize: '11px', color: '#888',    padding: '6px 8px' }}>{fmt(log.records_fetched)}</td>
                    <td style={{ ...mono, fontSize: '11px', color: '#1D9E75', padding: '6px 8px' }}>{fmt(log.records_inserted)}</td>
                    <td style={{ ...mono, fontSize: '11px', color: '#5b9bd5', padding: '6px 8px' }}>{fmt(log.records_updated)}</td>
                    <td style={{ ...mono, fontSize: '11px', color: log.records_failed > 0 ? '#E24B4A' : '#444', padding: '6px 8px' }}>{fmt(log.records_failed)}</td>
                    <td style={{ ...mono, fontSize: '10px', color: '#E24B4A', padding: '6px 8px', maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {log.error_message || ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div style={{ ...mono, fontSize: '10px', color: '#222', textAlign: 'right' }}>Auto-refreshes every 60 seconds</div>
    </div>
  )
}

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getDiagnostics } from '../api/diagnostics.js'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

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

function StatusDot({ ok }) {
  return <span style={{ display: 'inline-block', width: '7px', height: '7px', borderRadius: '50%', background: ok ? '#1D9E75' : '#E24B4A', marginRight: '6px', flexShrink: 0 }} />
}

function fmt(n) {
  return parseInt(n || 0).toLocaleString();
}

function duration(secs) {
  if (!secs && secs !== 0) return '—';
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs/60)}m ${secs % 60}s`;
}

function relTime(ts) {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  const hrs  = Math.floor(mins / 60);
  const days = Math.floor(hrs / 24);
  if (days > 0)  return `${days}d ago`;
  if (hrs > 0)   return `${hrs}h ago`;
  if (mins > 0)  return `${mins}m ago`;
  return 'just now';
}

const JOB_ORDER = ['nvd', 'epss', 'kev', 'exploits', 'score_refresh'];
const JOB_LABELS = {
  nvd:           'NVD',
  epss:          'EPSS',
  kev:           'CISA KEV',
  exploits:      'Exploits',
  score_refresh: 'Score Refresh',
};

export default function Diagnostics() {
  const [activeJob, setActiveJob] = useState('nvd');

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

  const { table_counts, ingest_status, logs_by_job, snapshot_days, db_size, index_health } = data;

  const statusMap = {};
  for (const s of ingest_status) statusMap[s.job_name] = s;

  const tableMap = {};
  for (const t of table_counts) tableMap[t.table_name] = parseInt(t.row_count);

  const activeLog = logs_by_job[activeJob] || [];

  return (
    <div style={{ maxWidth: '1000px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <div style={{ fontSize: '15px', fontWeight: 500, color: '#e5e5e5' }}>System Diagnostics</div>
          <div style={{ ...mono, fontSize: '11px', color: '#444', marginTop: '2px' }}>
            Last refreshed {dataUpdatedAt ? relTime(dataUpdatedAt) : '—'}
          </div>
        </div>
        <button onClick={() => refetch()} disabled={isFetching}
          style={{ ...mono, fontSize: '11px', padding: '6px 14px', borderRadius: '6px', border: '0.5px solid #2a2a2a', background: 'transparent', color: isFetching ? '#333' : '#888', cursor: isFetching ? 'not-allowed' : 'pointer' }}>
          {isFetching ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {/* Top row — DB size + snapshot count */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '12px' }}>
        {[
          { label: 'Database size',    value: db_size.total_size,        color: '#e5e5e5' },
          { label: 'Trend snapshots',  value: `${snapshot_days} days`,   color: snapshot_days > 1 ? '#1D9E75' : '#BA7517' },
          { label: 'CVE core rows',    value: fmt(tableMap.cve_core),    color: '#e5e5e5' },
          { label: 'CVE score rows',   value: fmt(tableMap.cve_score),   color: '#e5e5e5' },
        ].map(k => (
          <div key={k.label} style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '8px', padding: '12px 14px' }}>
            <div style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase', marginBottom: '4px' }}>{k.label}</div>
            <div style={{ ...mono, fontSize: '18px', fontWeight: 500, color: k.color }}>{k.value}</div>
          </div>
        ))}
      </div>

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
            ['ingest_log',          'Ingest Logs'],
          ].map(([key, label]) => (
            <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '0.5px solid #1a1a1a' }}>
              <span style={{ ...mono, fontSize: '11px', color: '#888' }}>{label}</span>
              <span style={{ ...mono, fontSize: '11px', color: tableMap[key] > 0 ? '#e5e5e5' : '#E24B4A', fontWeight: 500 }}>
                {fmt(tableMap[key])}
              </span>
            </div>
          ))}
        </Panel>

        {/* Ingest job status */}
        <Panel title="Ingest job status">
          {JOB_ORDER.map(job => {
            const s    = statusMap[job];
            const logs = logs_by_job[job] || [];
            const last = logs[0];
            const ok   = last?.status === 'success';
            return (
              <div key={job} style={{ marginBottom: '12px', paddingBottom: '12px', borderBottom: '0.5px solid #1a1a1a' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <StatusDot ok={ok && !s?.is_running} />
                    <span style={{ ...mono, fontSize: '12px', color: '#e5e5e5' }}>{JOB_LABELS[job]}</span>
                    {s?.is_running && <span style={{ ...mono, fontSize: '10px', color: '#BA7517', marginLeft: '6px' }}>RUNNING</span>}
                  </div>
                  <span style={{ ...mono, fontSize: '10px', color: '#555' }}>{relTime(last?.completed_at)}</span>
                </div>
                {last && (
                  <div style={{ ...mono, fontSize: '10px', color: '#555', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                    <span style={{ color: ok ? '#1D9E75' : '#E24B4A' }}>{last.status}</span>
                    <span>fetched: {fmt(last.records_fetched)}</span>
                    <span>inserted: {fmt(last.records_inserted)}</span>
                    <span>updated: {fmt(last.records_updated)}</span>
                    {last.records_failed > 0 && <span style={{ color: '#E24B4A' }}>failed: {fmt(last.records_failed)}</span>}
                    <span>took: {duration(last.duration_seconds)}</span>
                  </div>
                )}
                {last?.error_message && (
                  <div style={{ ...mono, fontSize: '10px', color: '#E24B4A', marginTop: '4px', wordBreak: 'break-all' }}>
                    ⚠ {last.error_message}
                  </div>
                )}
              </div>
            );
          })}
        </Panel>
      </div>

      {/* Ingest history log — per job */}
      <Panel title="Ingest run history">
        <div style={{ display: 'flex', gap: '6px', marginBottom: '14px', flexWrap: 'wrap' }}>
          {JOB_ORDER.map(job => (
            <button key={job} onClick={() => setActiveJob(job)}
              style={{ ...mono, fontSize: '10px', padding: '3px 10px', borderRadius: '10px', border: '0.5px solid', cursor: 'pointer',
                background:  activeJob === job ? '#e5e5e5' : 'transparent',
                color:       activeJob === job ? '#0a0a0a' : '#666',
                borderColor: activeJob === job ? '#e5e5e5' : '#2a2a2a',
              }}>{JOB_LABELS[job]}</button>
          ))}
        </div>

        {activeLog.length === 0 ? (
          <div style={{ ...mono, fontSize: '12px', color: '#444' }}>No runs recorded for {JOB_LABELS[activeJob]} yet.</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ ...mono, fontSize: '10px', color: '#555', textTransform: 'uppercase' }}>
                  {['Started', 'Status', 'Duration', 'Fetched', 'Inserted', 'Updated', 'Failed', 'Error'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 'normal', borderBottom: '0.5px solid #1a1a1a' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {activeLog.map((log, i) => (
                  <tr key={i} style={{ borderBottom: '0.5px solid #1a1a1a' }}
                    onMouseEnter={e  => e.currentTarget.style.background = '#1a1a1a'}
                    onMouseLeave={e  => e.currentTarget.style.background = 'transparent'}>
                    <td style={{ ...mono, fontSize: '11px', color: '#888', padding: '6px 8px', whiteSpace: 'nowrap' }}>{log.started_at ? new Date(log.started_at).toLocaleString('en-GB') : '—'}</td>
                    <td style={{ ...mono, fontSize: '11px', padding: '6px 8px' }}>
                      <span style={{ color: log.status === 'success' ? '#1D9E75' : log.status === 'running' ? '#BA7517' : '#E24B4A' }}>{log.status}</span>
                    </td>
                    <td style={{ ...mono, fontSize: '11px', color: '#666', padding: '6px 8px' }}>{duration(log.duration_seconds)}</td>
                    <td style={{ ...mono, fontSize: '11px', color: '#888', padding: '6px 8px' }}>{fmt(log.records_fetched)}</td>
                    <td style={{ ...mono, fontSize: '11px', color: '#1D9E75', padding: '6px 8px' }}>{fmt(log.records_inserted)}</td>
                    <td style={{ ...mono, fontSize: '11px', color: '#5b9bd5', padding: '6px 8px' }}>{fmt(log.records_updated)}</td>
                    <td style={{ ...mono, fontSize: '11px', color: log.records_failed > 0 ? '#E24B4A' : '#444', padding: '6px 8px' }}>{fmt(log.records_failed)}</td>
                    <td style={{ ...mono, fontSize: '10px', color: '#E24B4A', padding: '6px 8px', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{log.error_message || ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* DB sizing detail */}
      <Panel title="Storage breakdown">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '10px' }}>
          {[
            ['cve_core',     db_size.cve_core_size],
            ['cve_cpe',      db_size.cve_cpe_size],
            ['cve_epss',     db_size.cve_epss_size],
            ['cve_score',    db_size.cve_score_size],
            ['cve_exploits', db_size.cve_exploits_size],
          ].map(([label, size]) => (
            <div key={label} style={{ background: '#1a1a1a', borderRadius: '6px', padding: '10px 12px' }}>
              <div style={{ ...mono, fontSize: '10px', color: '#555', marginBottom: '4px' }}>{label}</div>
              <div style={{ ...mono, fontSize: '14px', color: '#e5e5e5', fontWeight: 500 }}>{size}</div>
            </div>
          ))}
        </div>
      </Panel>

      <div style={{ ...mono, fontSize: '10px', color: '#222', marginTop: '1rem', textAlign: 'right' }}>
        Auto-refreshes every 60 seconds
      </div>
    </div>
  )
}

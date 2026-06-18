import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { getCves } from '../api/cves.js'
import { getClientId } from '../store/authStore.js'
import { getBand } from '../utils/scoring.js'
import { truncate, formatDate } from '../utils/formatters.js'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

export default function CveList() {
  const clientId = getClientId()
  const navigate = useNavigate()
  const [filters, setFilters] = useState({ sort: 'score', page: 1, limit: 25 })

  const { data, isLoading, error } = useQuery({
    queryKey: ['cves', clientId, filters],
    queryFn:  () => getCves(clientId, filters),
    keepPreviousData: true
  })

  function setFilter(key, value) {
    setFilters(f => ({ ...f, [key]: value || undefined, page: 1 }))
  }

  if (isLoading) return <div style={{ ...mono, color: '#666', padding: '2rem' }}>Loading CVEs...</div>
  if (error)     return <div style={{ ...mono, color: '#E24B4A', padding: '2rem' }}>Failed to load CVEs</div>

  const { data: cves, meta } = data

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div>
          <div style={{ fontSize: '15px', fontWeight: 500, color: '#e5e5e5' }}>CVE Intelligence</div>
          <div style={{ ...mono, fontSize: '11px', color: '#666', marginTop: '2px' }}>{meta.total.toLocaleString()} CVEs matched</div>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '1rem', flexWrap: 'wrap' }}>
        {[['All', ''], ['Critical', 'critical'], ['High', 'high'], ['Medium', 'medium'], ['Low', 'low']].map(([label, val]) => (
          <button key={val} onClick={() => setFilter('band', val)}
            style={{ ...mono, fontSize: '11px', padding: '5px 12px', borderRadius: '20px', border: '0.5px solid', cursor: 'pointer',
              background: filters.band === val || (!filters.band && !val) ? '#e5e5e5' : 'transparent',
              color:      filters.band === val || (!filters.band && !val) ? '#0a0a0a' : '#888',
              borderColor: filters.band === val || (!filters.band && !val) ? '#e5e5e5' : '#2a2a2a'
            }}>{label}</button>
        ))}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '6px' }}>
          {[{ key: 'kev', label: 'KEV' }, { key: 'exploit', label: 'Exploit' }].map(({ key, label }) => (
            <button key={key} onClick={() => setFilter(key, filters[key] === 'true' ? '' : 'true')}
              style={{ ...mono, fontSize: '11px', padding: '5px 12px', borderRadius: '20px', border: '0.5px solid', cursor: 'pointer',
                background: filters[key] === 'true' ? '#E24B4A' : 'transparent',
                color:      filters[key] === 'true' ? '#fff' : '#888',
                borderColor: filters[key] === 'true' ? '#E24B4A' : '#2a2a2a'
              }}>{label}</button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', overflow: 'hidden' }}>
        {cves.map((cve, i) => {
          const band = getBand(cve.adjusted_score)
          return (
            <div
              key={cve.cve_id}
              onClick={() => navigate(`/cves/${cve.cve_id}`)}
              style={{
                padding: '10px 16px',
                borderBottom: i < cves.length - 1 ? '0.5px solid #1a1a1a' : 'none',
                display: 'grid',
                gridTemplateColumns: '120px 1fr auto auto',
                gap: '12px',
                alignItems: 'center',
                cursor: 'pointer',
                transition: 'background 0.1s'
              }}
              onMouseEnter={e => e.currentTarget.style.background = '#1a1a1a'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <span style={{ ...mono, fontSize: '11px', color: '#5b9bd5' }}>{cve.cve_id}</span>
              <div>
                <div style={{ fontSize: '12px', color: '#e5e5e5', fontWeight: 500 }}>{truncate(cve.description, 80)}</div>
                <div style={{ ...mono, fontSize: '10px', color: '#555', marginTop: '2px' }}>
                  {cve.attack_vector} · {formatDate(cve.published_date)} · {cve.patch_available ? 'patch available' : 'no patch'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '4px' }}>
                {cve.kev_member    && <span style={{ ...mono, fontSize: '10px', fontWeight: 500, padding: '2px 6px', borderRadius: '3px', background: '#FCEBEB', color: '#A32D2D' }}>KEV</span>}
                {cve.pre_kev_flag && <span style={{ ...mono, fontSize: '10px', fontWeight: 500, padding: '2px 6px', borderRadius: '3px', background: '#EEEDFE', color: '#534AB7' }}>PRE-KEV</span>}
                {cve.exploit_available && <span style={{ ...mono, fontSize: '10px', fontWeight: 500, padding: '2px 6px', borderRadius: '3px', background: '#FAEEDA', color: '#854F0B' }}>EXPLOIT</span>}
              </div>
              <span style={{ ...mono, fontSize: '12px', fontWeight: 500, padding: '3px 8px', borderRadius: '5px', minWidth: '42px', textAlign: 'center', background: band.bg, color: band.text }}>
                {parseFloat(cve.adjusted_score).toFixed(1)}
              </span>
            </div>
          )
        })}
      </div>

      {/* Pagination */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px' }}>
        <span style={{ ...mono, fontSize: '11px', color: '#666' }}>Page {meta.page} of {meta.pages} — {meta.total.toLocaleString()} total</span>
        <div style={{ display: 'flex', gap: '6px' }}>
          <button onClick={() => setFilters(f => ({ ...f, page: f.page - 1 }))} disabled={meta.page <= 1}
            style={{ ...mono, fontSize: '11px', padding: '5px 12px', borderRadius: '6px', border: '0.5px solid #2a2a2a', background: 'transparent', color: meta.page <= 1 ? '#333' : '#888', cursor: meta.page <= 1 ? 'not-allowed' : 'pointer' }}>
            Previous
          </button>
          <button onClick={() => setFilters(f => ({ ...f, page: f.page + 1 }))} disabled={meta.page >= meta.pages}
            style={{ ...mono, fontSize: '11px', padding: '5px 12px', borderRadius: '6px', border: '0.5px solid #2a2a2a', background: 'transparent', color: meta.page >= meta.pages ? '#333' : '#888', cursor: meta.page >= meta.pages ? 'not-allowed' : 'pointer' }}>
            Next
          </button>
        </div>
      </div>
    </div>
  )
}

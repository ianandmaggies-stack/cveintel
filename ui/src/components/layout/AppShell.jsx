import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { clearAuth } from '../../store/authStore.js'

export default function AppShell() {
  const navigate = useNavigate()

  function handleLogout() {
    clearAuth()
    navigate('/login')
  }

  return (
    <div className="min-h-screen" style={{ background: '#0a0a0a', color: '#e5e5e5' }}>
      <nav style={{ borderBottom: '0.5px solid #1a1a1a', padding: '0 1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: '48px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '14px', fontWeight: 500, color: '#e5e5e5' }}>
            CVE<span style={{ color: '#E24B4A' }}>///</span>INTEL
          </span>
          <div style={{ display: 'flex', gap: '4px' }}>
            {[
              ['Brief',       '/brief'],
              ['Dashboard',   '/dashboard'],
              ['CVEs',        '/cves'],
              ['Landscape',   '/landscape'],
              ['Report',      '/report'],
            ].map(([label, path]) => (
              <NavLink key={path} to={path} style={({ isActive }) => ({
                padding: '4px 10px',
                borderRadius: '6px',
                fontSize: '12px',
                fontFamily: 'JetBrains Mono, monospace',
                textDecoration: 'none',
                background: isActive ? '#1a1a1a' : 'transparent',
                color: isActive ? '#e5e5e5' : '#666',
              })}>{label}</NavLink>
            ))}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {[
            ['About',       '/about'],
            ['Diagnostics', '/diagnostics'],
          ].map(([label, path]) => (
            <NavLink key={path} to={path} style={({ isActive }) => ({
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '11px',
              fontFamily: 'JetBrains Mono, monospace',
              textDecoration: 'none',
              background: isActive ? '#1a1a1a' : 'transparent',
              color: isActive ? '#888' : '#3a3a3a',
            })}>{label}</NavLink>
          ))}
          <span style={{ color: '#2a2a2a', fontSize: '12px' }}>|</span>
          <button onClick={handleLogout} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#3a3a3a', background: 'none', border: 'none', cursor: 'pointer' }}>
            logout
          </button>
        </div>
      </nav>
      <main style={{ padding: '1.5rem' }}>
        <Outlet />
      </main>
    </div>
  )
}

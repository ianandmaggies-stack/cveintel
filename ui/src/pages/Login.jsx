import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../api/auth.js'
import { setAuth } from '../store/authStore.js'

export default function Login() {
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)
  const navigate                = useNavigate()

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const data = await login(email, password)
      setAuth({
        token:         data.token,
        refresh_token: data.refresh_token,
        role:          data.role,
        client_id:     'dev-client-id'
      })
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.error?.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: '#0a0a0a',
      padding: '1rem'
    }}>
      <div style={{ width: '100%', maxWidth: '380px' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '22px', fontWeight: 500, color: '#e5e5e5', marginBottom: '8px' }}>
            CVE<span style={{ color: '#E24B4A' }}>///</span>INTEL
          </div>
          <div style={{ fontSize: '13px', color: '#888' }}>Security intelligence platform</div>
        </div>

        <div style={{ background: '#111', border: '0.5px solid #2a2a2a', borderRadius: '10px', padding: '1.5rem' }}>
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: '#888', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                placeholder="admin@cveintel.dev"
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  background: '#0a0a0a',
                  border: '0.5px solid #2a2a2a',
                  borderRadius: '6px',
                  color: '#e5e5e5',
                  fontSize: '13px',
                  fontFamily: 'JetBrains Mono, monospace',
                  boxSizing: 'border-box',
                  outline: 'none'
                }}
              />
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'block', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: '#888', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                placeholder="••••••••"
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  background: '#0a0a0a',
                  border: '0.5px solid #2a2a2a',
                  borderRadius: '6px',
                  color: '#e5e5e5',
                  fontSize: '13px',
                  fontFamily: 'JetBrains Mono, monospace',
                  boxSizing: 'border-box',
                  outline: 'none'
                }}
              />
            </div>

            {error && (
              <div style={{ marginBottom: '1rem', padding: '8px 12px', background: '#FCEBEB', border: '0.5px solid #E24B4A44', borderRadius: '6px', fontSize: '12px', color: '#A32D2D', fontFamily: 'JetBrains Mono, monospace' }}>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%',
                padding: '10px',
                background: loading ? '#5a1a1a' : '#E24B4A',
                color: '#fff',
                border: 'none',
                borderRadius: '6px',
                fontSize: '13px',
                fontFamily: 'JetBrains Mono, monospace',
                fontWeight: 500,
                cursor: loading ? 'not-allowed' : 'pointer'
              }}
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        </div>

        <div style={{ textAlign: 'center', marginTop: '1rem', fontSize: '11px', color: '#555', fontFamily: 'JetBrains Mono, monospace' }}>
          CVE Intel — Prototype build
        </div>
      </div>
    </div>
  )
}

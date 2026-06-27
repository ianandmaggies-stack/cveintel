import { useState, useEffect } from 'react'
import { STACK_CONFIG, getCategorySubIds, isCategoryFullyEnabled, isCategoryPartiallyEnabled, DEFAULT_STACK } from '../config/stackConfig.js'
import { loadStack, saveStack, resetStack } from '../hooks/useStackFilter.js'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

const D = {
  bg:        '#0a0a0a',
  bg2:       '#111',
  bg3:       '#1a1a1a',
  border:    '#2a2a2a',
  text:      '#e5e5e5',
  muted:     '#888',
  dim:       '#444',
}

function Checkbox({ checked, indeterminate, onChange, size = 14 }) {
  return (
    <span
      onClick={e => { e.stopPropagation(); onChange(); }}
      style={{
        display:        'inline-flex',
        alignItems:     'center',
        justifyContent: 'center',
        width:          size,
        height:         size,
        borderRadius:   '3px',
        border:         `1.5px solid ${checked || indeterminate ? '#5b9bd5' : '#3a3a3a'}`,
        background:     checked ? '#5b9bd5' : indeterminate ? '#5b9bd522' : 'transparent',
        cursor:         'pointer',
        flexShrink:     0,
        transition:     'all 0.1s',
      }}
    >
      {checked      && <span style={{ color: '#fff', fontSize: size * 0.7, lineHeight: 1, fontWeight: 700 }}>✓</span>}
      {indeterminate && !checked && <span style={{ color: '#5b9bd5', fontSize: size * 0.8, lineHeight: 1 }}>─</span>}
    </span>
  )
}

function CategoryBlock({ category, enabled, onToggleCategory, onToggleSub }) {
  const [expanded, setExpanded] = useState(false)
  const fullyEnabled     = isCategoryFullyEnabled(category, enabled)
  const partiallyEnabled = isCategoryPartiallyEnabled(category, enabled)

  return (
    <div style={{ border: `0.5px solid ${fullyEnabled || partiallyEnabled ? '#5b9bd544' : D.border}`, borderRadius: '8px', overflow: 'hidden', marginBottom: '8px' }}>

      {/* Category header */}
      <div
        style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '11px 14px', background: fullyEnabled || partiallyEnabled ? '#0d1a24' : D.bg2, cursor: 'pointer', userSelect: 'none' }}
        onClick={() => setExpanded(e => !e)}
      >
        <Checkbox
          checked={fullyEnabled}
          indeterminate={partiallyEnabled}
          onChange={() => onToggleCategory(category)}
          size={15}
        />
        <span style={{ fontSize: '16px' }}>{category.icon}</span>
        <span style={{ fontSize: '13px', fontWeight: 500, color: fullyEnabled || partiallyEnabled ? D.text : D.muted, flex: 1 }}>
          {category.label}
        </span>
        <span style={{ ...mono, fontSize: '10px', color: D.dim }}>
          {enabled.filter(id => getCategorySubIds(category).includes(id)).length} / {category.subs.length}
        </span>
        <span style={{ ...mono, fontSize: '10px', color: D.dim, marginLeft: '4px' }}>
          {expanded ? '▲' : '▼'}
        </span>
      </div>

      {/* Subcategories */}
      {expanded && (
        <div style={{ borderTop: `0.5px solid ${D.border}`, background: D.bg }}>
          {category.subs.map(sub => {
            const isEnabled = enabled.includes(sub.id)
            return (
              <div
                key={sub.id}
                onClick={() => onToggleSub(sub.id)}
                style={{
                  display:    'flex',
                  alignItems: 'center',
                  gap:        '10px',
                  padding:    '8px 14px 8px 38px',
                  cursor:     'pointer',
                  borderBottom: `0.5px solid ${D.border}`,
                  background: isEnabled ? '#0a1520' : 'transparent',
                  userSelect: 'none',
                }}
              >
                <Checkbox checked={isEnabled} onChange={() => onToggleSub(sub.id)} size={13} />
                <span style={{ fontSize: '12px', color: isEnabled ? D.text : D.muted }}>
                  {sub.label}
                </span>
                {sub.other && (
                  <span style={{ ...mono, fontSize: '10px', color: '#534AB7', marginLeft: 'auto' }}>catch-all</span>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default function Settings() {
  const [enabled, setEnabled]   = useState(() => loadStack().enabled)
  const [saved, setSaved]       = useState(false)
  const [isConfigured, setIsConfigured] = useState(() => loadStack().stack_configured)

  // Count total enabled
  const totalSubs    = STACK_CONFIG.reduce((acc, c) => acc + c.subs.length, 0)
  const enabledCount = enabled.length

  function toggleCategory(category) {
    const subIds       = getCategorySubIds(category)
    const fullyEnabled = subIds.every(id => enabled.includes(id))
    if (fullyEnabled) {
      setEnabled(prev => prev.filter(id => !subIds.includes(id)))
    } else {
      setEnabled(prev => [...new Set([...prev, ...subIds])])
    }
    setSaved(false)
  }

  function toggleSub(subId) {
    setEnabled(prev =>
      prev.includes(subId)
        ? prev.filter(id => id !== subId)
        : [...prev, subId]
    )
    setSaved(false)
  }

  function handleSave() {
    saveStack({ enabled, stack_configured: true })
    setIsConfigured(true)
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  function handleReset() {
    if (!window.confirm('Reset to default profile? This will re-enable the default Microsoft and Linux view and clear your configuration.')) return
    resetStack()
    setEnabled([...DEFAULT_STACK.enabled])
    setIsConfigured(false)
    setSaved(false)
  }

  function handleSelectAll() {
    const all = STACK_CONFIG.flatMap(c => getCategorySubIds(c))
    setEnabled(all)
    setSaved(false)
  }

  function handleClearAll() {
    setEnabled([])
    setSaved(false)
  }

  return (
    <div style={{ maxWidth: '720px' }}>

      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ fontSize: '15px', fontWeight: 500, color: D.text }}>Settings</div>
        <div style={{ ...mono, fontSize: '11px', color: D.dim, marginTop: '2px' }}>Personalise CVE Intel to your environment</div>
      </div>

      {/* Tech Stack section */}
      <div style={{ background: D.bg2, border: `0.5px solid ${D.border}`, borderRadius: '10px', overflow: 'hidden', marginBottom: '12px' }}>
        <div style={{ padding: '14px 16px', borderBottom: `0.5px solid ${D.border}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '13px', fontWeight: 500, color: D.text }}>Tech Stack Profile</div>
              <div style={{ fontSize: '12px', color: D.muted, marginTop: '2px', lineHeight: 1.5 }}>
                Select the technologies in your environment. CVE Intel will filter the Brief,
                Dashboard, and Reports to show only relevant vulnerabilities.
              </div>
            </div>
            <div style={{ ...mono, fontSize: '11px', color: '#5b9bd5', flexShrink: 0, marginLeft: '16px' }}>
              {enabledCount} / {totalSubs} selected
            </div>
          </div>

          {/* Status banner */}
          <div style={{
            marginTop: '12px',
            padding: '8px 12px',
            borderRadius: '6px',
            background: isConfigured ? '#0a1a0a' : '#1a1000',
            border: `0.5px solid ${isConfigured ? '#1D9E7544' : '#BA751744'}`,
            ...mono, fontSize: '11px',
            color: isConfigured ? '#1D9E75' : '#BA7517',
          }}>
            {isConfigured
              ? '✓ Profile configured — showing filtered results across the platform'
              : '⚠ Default view active — showing Microsoft and Linux only. Configure your stack for accurate results.'}
          </div>
        </div>

        {/* Quick actions */}
        <div style={{ padding: '10px 16px', borderBottom: `0.5px solid ${D.border}`, display: 'flex', gap: '8px' }}>
          <button onClick={handleSelectAll} style={{ ...mono, fontSize: '10px', padding: '4px 10px', borderRadius: '4px', border: `0.5px solid ${D.border}`, background: 'transparent', color: D.muted, cursor: 'pointer' }}>Select all</button>
          <button onClick={handleClearAll}  style={{ ...mono, fontSize: '10px', padding: '4px 10px', borderRadius: '4px', border: `0.5px solid ${D.border}`, background: 'transparent', color: D.muted, cursor: 'pointer' }}>Clear all</button>
          <button onClick={handleReset}     style={{ ...mono, fontSize: '10px', padding: '4px 10px', borderRadius: '4px', border: `0.5px solid ${D.border}`, background: 'transparent', color: '#E24B4A', cursor: 'pointer' }}>Reset to default</button>
        </div>

        {/* Category list */}
        <div style={{ padding: '12px 16px' }}>
          {STACK_CONFIG.map(category => (
            <CategoryBlock
              key={category.id}
              category={category}
              enabled={enabled}
              onToggleCategory={toggleCategory}
              onToggleSub={toggleSub}
            />
          ))}

          {/* Global catch-all */}
          <div
            onClick={() => toggleSub('__everything_else')}
            style={{
              display: 'flex', alignItems: 'center', gap: '10px',
              padding: '11px 14px',
              border: `0.5px solid ${enabled.includes('__everything_else') ? '#5b9bd544' : D.border}`,
              borderRadius: '8px',
              background: enabled.includes('__everything_else') ? '#0d1a24' : D.bg2,
              cursor: 'pointer', marginBottom: '8px', userSelect: 'none',
            }}
          >
            <Checkbox checked={enabled.includes('__everything_else')} onChange={() => toggleSub('__everything_else')} size={15} />
            <span style={{ fontSize: '16px' }}>🌐</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '13px', fontWeight: 500, color: enabled.includes('__everything_else') ? D.text : D.muted }}>Everything else</div>
              <div style={{ fontSize: '11px', color: D.dim, marginTop: '2px' }}>Any vendor not covered by the categories above</div>
            </div>
            <span style={{ ...mono, fontSize: '10px', color: '#534AB7' }}>catch-all</span>
          </div>
        </div>

        {/* Save */}
        <div style={{ padding: '12px 16px', borderTop: `0.5px solid ${D.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ ...mono, fontSize: '11px', color: saved ? '#1D9E75' : 'transparent' }}>
            ✓ Saved — your preferences are active
          </div>
          <button
            onClick={handleSave}
            style={{
              ...mono, fontSize: '12px', padding: '8px 24px',
              borderRadius: '6px', border: 'none',
              background: '#5b9bd5', color: '#fff',
              cursor: 'pointer', fontWeight: 500,
            }}
          >
            Save profile
          </button>
        </div>
      </div>

      {/* Account section — stub */}
      <div style={{ background: D.bg2, border: `0.5px solid ${D.border}`, borderRadius: '10px', overflow: 'hidden' }}>
        <div style={{ padding: '14px 16px', borderBottom: `0.5px solid ${D.border}` }}>
          <div style={{ fontSize: '13px', fontWeight: 500, color: D.text }}>Account</div>
          <div style={{ fontSize: '12px', color: D.muted, marginTop: '2px' }}>Manage your login credentials and preferences</div>
        </div>
        <div style={{ padding: '16px' }}>
          {[
            { label: 'Email address', value: '—', note: 'Account management coming soon' },
            { label: 'Password',      value: '••••••••', note: 'Password change coming soon' },
          ].map(row => (
            <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: `0.5px solid ${D.border}` }}>
              <div>
                <div style={{ fontSize: '12px', color: D.text }}>{row.label}</div>
                <div style={{ ...mono, fontSize: '11px', color: D.dim, marginTop: '2px' }}>{row.note}</div>
              </div>
              <span style={{ ...mono, fontSize: '12px', color: D.dim }}>{row.value}</span>
            </div>
          ))}
          <div style={{ ...mono, fontSize: '11px', color: D.dim, marginTop: '12px', padding: '10px', background: D.bg3, borderRadius: '6px' }}>
            Full account management — password reset, profile editing, and subscription settings — will be available in an upcoming release.
          </div>
        </div>
      </div>
    </div>
  )
}

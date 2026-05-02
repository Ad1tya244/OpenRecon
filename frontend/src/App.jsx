import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import './index.css'
import SearchBar from './components/SearchBar'
import Dashboard from './components/Dashboard'

// --- Memoized Matrix Rain (generated once, never re-renders) ---
const COLUMNS = Array.from({ length: 18 }, (_, i) => {
  const chars = Array.from({ length: 32 }, () =>
    Math.random() > 0.5
      ? String.fromCharCode(0x30A0 + Math.floor(Math.random() * 96))
      : Math.floor(Math.random() * 10)
  ).join('\n')
  return { id: i, chars, delay: i * 0.25, duration: 3 + (i % 5) }
})

const MatrixRain = () => (
  <div style={{
    position: 'fixed', inset: 0, overflow: 'hidden',
    pointerEvents: 'none', zIndex: 0, opacity: 0.04
  }}>
    {COLUMNS.map(col => (
      <div key={col.id} style={{
        position: 'absolute',
        top: '-20%',
        left: `${(col.id / COLUMNS.length) * 100}%`,
        fontFamily: 'Share Tech Mono, monospace',
        fontSize: '13px',
        color: '#00ff9d',
        lineHeight: '1.3',
        animation: `data-stream ${col.duration}s linear ${col.delay}s infinite`,
        whiteSpace: 'pre',
        userSelect: 'none',
      }}>
        {col.chars}
      </div>
    ))}
  </div>
)

// --- Typewriter hook ---
function useTypewriter(text, speed = 45, startDelay = 300) {
  const [displayed, setDisplayed] = useState('')
  const [done, setDone] = useState(false)
  useEffect(() => {
    setDisplayed('')
    setDone(false)
    let i = 0
    const timeout = setTimeout(() => {
      const interval = setInterval(() => {
        i++
        setDisplayed(text.slice(0, i))
        if (i >= text.length) { clearInterval(interval); setDone(true) }
      }, speed)
      return () => clearInterval(interval)
    }, startDelay)
    return () => clearTimeout(timeout)
  }, [text, speed, startDelay])
  return { displayed, done }
}

// --- Toast notification ---
let toastTimer = null
const ToastContext = { show: null }

const Toast = ({ message, type = 'info', onDone }) => {
  useEffect(() => {
    const t = setTimeout(onDone, 3500)
    return () => clearTimeout(t)
  }, [onDone])
  const colors = {
    info: 'var(--cyan)',
    success: 'var(--green)',
    error: 'var(--red)',
    warn: 'var(--amber)',
  }
  return (
    <div className="toast" style={{
      borderColor: colors[type],
      boxShadow: `0 4px 24px rgba(0,0,0,0.7), 0 0 12px ${colors[type]}22`
    }}>
      <span style={{ color: colors[type], marginRight: '0.5rem' }}>
        {type === 'success' ? '✓' : type === 'error' ? '✗' : type === 'warn' ? '⚠' : '◈'}
      </span>
      {message}
    </div>
  )
}

// --- System status items ---
const STATUS_ITEMS = [
  { label: 'SYS', value: 'ACTIVE', color: 'var(--text-dim)' },
  { label: 'NET', value: 'ONLINE', color: 'var(--green)' },
  { label: 'MODE', value: 'PASSIVE', color: 'var(--text-dim)' },
  { label: 'ENC', value: 'TLS1.3', color: 'var(--cyan)' },
]

// --- Main App ---
function App() {
  const [target, setTarget] = useState(null)
  const [loading, setLoading] = useState(false)
  const [time, setTime] = useState(new Date())
  const [toast, setToast] = useState(null)
  const [scanCount, setScanCount] = useState(() => {
    return parseInt(localStorage.getItem('or_scan_count') || '0')
  })

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const showToast = useCallback((message, type = 'info') => {
    setToast({ message, type, key: Date.now() })
  }, [])

  const handleSearch = useCallback((domain) => {
    setLoading(true)
    setTarget(domain)
    setLoading(false)
    const next = scanCount + 1
    setScanCount(next)
    localStorage.setItem('or_scan_count', next)
    showToast(`Initiating scan on ${domain}`, 'info')
  }, [scanCount, showToast])

  const handleReset = useCallback(() => {
    setTarget(null)
    showToast('Target cleared. Ready for new acquisition.', 'success')
  }, [showToast])

  const timeStr = time.toTimeString().split(' ')[0]
  const dateStr = time.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })

  const { displayed: typedSubtitle, done: subtitleDone } = useTypewriter(
    'PASSIVE OSINT ENGINE v2.0',
    60,
    800
  )

  return (
    <div className="app-layout">
      <MatrixRain />

      {/* Sticky Header */}
      <header style={{
        padding: 0,
        borderBottom: '1px solid var(--border-color)',
        background: 'rgba(2, 4, 8, 0.96)',
        backdropFilter: 'blur(24px)',
        position: 'sticky', top: 0, zIndex: 100,
        boxShadow: '0 1px 0 var(--border-color), 0 4px 24px rgba(0, 255, 180, 0.04)'
      }}>
        {/* Top ticker bar */}
        <div style={{
          background: 'rgba(0, 255, 180, 0.04)',
          borderBottom: '1px solid var(--border-color)',
          padding: '0.28rem 1.5rem',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center'
        }}>
          <div style={{ display: 'flex', gap: '2rem', fontFamily: 'var(--font-mono)', fontSize: '0.68rem' }}>
            {STATUS_ITEMS.map(s => (
              <span key={s.label}>
                <span style={{ color: 'var(--text-dim)' }}>{s.label}:</span>
                <span style={{ color: s.color, marginLeft: '0.3rem' }}>{s.value}</span>
              </span>
            ))}
            {scanCount > 0 && (
              <span>
                <span style={{ color: 'var(--text-dim)' }}>SCANS:</span>
                <span style={{ color: 'var(--amber)', marginLeft: '0.3rem' }}>{String(scanCount).padStart(4, '0')}</span>
              </span>
            )}
          </div>
          <div style={{ display: 'flex', gap: '1.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.68rem' }}>
            <span style={{ color: 'var(--text-dim)' }}>{dateStr}</span>
            <span style={{ color: 'var(--cyan)', letterSpacing: '0.05em' }}>{timeStr}</span>
          </div>
        </div>

        {/* Logo + nav */}
        <div className="container" style={{
          display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', padding: '0.85rem 1.5rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.9rem' }}>
            {/* Icon */}
            <div style={{
              width: '38px', height: '38px',
              border: '1px solid var(--cyan)',
              borderRadius: '4px',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 12px var(--cyan-glow)',
              background: 'var(--cyan-dim)',
              flexShrink: 0
            }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="1.5" strokeLinecap="round">
                <circle cx="11" cy="11" r="8"/>
                <path d="m21 21-4.35-4.35"/>
                <path d="M8 11h6M11 8v6"/>
              </svg>
            </div>
            <div>
              <h1 className="logo-glitch" style={{
                fontFamily: 'var(--font-display)', fontSize: '1.35rem',
                fontWeight: '700', letterSpacing: '0.12em', lineHeight: 1,
                cursor: 'default'
              }}>
                OPEN<span className="text-gradient">RECON</span>
              </h1>
              <p style={{
                fontFamily: 'var(--font-mono)', fontSize: '0.58rem',
                color: 'var(--text-dim)', letterSpacing: '0.18em', marginTop: '3px'
              }}>
                {typedSubtitle}{!subtitleDone && <span className="cursor-blink" />}
              </p>
            </div>
          </div>

          {/* Right side */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
            {target && (
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: '0.78rem',
                color: 'var(--text-secondary)',
                padding: '0.35rem 0.85rem',
                border: '1px solid var(--border-color)',
                borderRadius: '4px',
                background: 'var(--cyan-dim)',
                animation: 'slide-in-right 0.3s ease',
                display: 'flex', alignItems: 'center', gap: '0.5rem'
              }}>
                <span style={{
                  width: '6px', height: '6px', borderRadius: '50%',
                  background: 'var(--cyan)',
                  boxShadow: '0 0 6px var(--cyan)',
                  animation: 'blink 1.5s ease-in-out infinite',
                  flexShrink: 0
                }} />
                <span style={{ color: 'var(--text-dim)' }}>TARGET:</span>
                <span style={{ color: 'var(--cyan)' }}>{target}</span>
              </div>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div className="status-dot" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--green)', letterSpacing: '0.08em' }}>OPERATIONAL</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="container" style={{ padding: '2rem 1.5rem', flex: 1, position: 'relative', zIndex: 1 }}>
        {!target && (
          <div style={{ maxWidth: '680px', margin: '0 auto', animation: 'fade-in-up 0.6s ease' }}>
            <HeroSection />
            <SearchBar onSearch={handleSearch} loading={loading} showToast={showToast} />
          </div>
        )}
        {target && (
          <Dashboard domain={target} onReset={handleReset} showToast={showToast} />
        )}
      </main>

      {/* Footer */}
      <footer style={{
        padding: '0.85rem 1.5rem',
        borderTop: '1px solid var(--border-color)',
        background: 'rgba(2,4,8,0.95)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        position: 'relative', zIndex: 1
      }}>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-dim)' }}>
          OpenRecon © 2026 — <span style={{ color: 'var(--red)' }}>Strictly educational &amp; defensive use only</span>
        </p>
        <div style={{ display: 'flex', gap: '1.5rem' }}>
          <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-dim)' }}>PASSIVE MODE</p>
          <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-dim)' }}>NO ACTIVE PROBING</p>
        </div>
      </footer>

      {/* Toast */}
      {toast && (
        <Toast
          key={toast.key}
          message={toast.message}
          type={toast.type}
          onDone={() => setToast(null)}
        />
      )}
    </div>
  )
}

// --- Hero section (separate component, no state, stable) ---
const FEATURE_TAGS = ['DNS RECON', 'SSL AUDIT', 'SUBDOMAIN MAP', 'PORT SCAN', 'CODE LEAKS', 'THREAT INTEL', 'WHOIS', 'IP INTEL']

function HeroSection() {
  const { displayed: line1, done: line1Done } = useTypewriter('ATTACK SURFACE', 55, 400)
  const { displayed: line2 } = useTypewriter('MAPPING SYSTEM', 55, line1Done ? 100 : 99999)

  return (
    <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
      {/* Boot label */}
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--cyan)',
        letterSpacing: '0.2em', textTransform: 'uppercase', marginBottom: '0.4rem',
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.6rem'
      }}>
        <span style={{ color: 'var(--green)', fontSize: '0.8rem' }}>▶</span>
        INITIALIZING RECONNAISSANCE SUITE
        <span style={{ color: 'var(--green)', animation: 'blink 1s step-end infinite' }}>_</span>
      </div>

      {/* Big title with typewriter */}
      <h2 style={{
        fontFamily: 'var(--font-display)',
        fontSize: 'clamp(1.8rem, 5vw, 3.2rem)',
        fontWeight: '900',
        lineHeight: 1.15,
        marginBottom: '0.5rem',
        letterSpacing: '0.05em',
        minHeight: '2.6em'
      }}>
        <span className="text-gradient glow-text" style={{ display: 'block' }}>
          {line1}{!line1Done && <span className="cursor-blink" />}
        </span>
        <span style={{ color: 'var(--text-primary)', fontSize: '0.65em', display: 'block' }}>
          {line1Done ? line2 : ''}
          {line1Done && line2.length < 14 && <span className="cursor-blink" />}
        </span>
      </h2>

      <p style={{
        color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)',
        fontSize: '0.83rem', lineHeight: 1.9, maxWidth: '480px', margin: '0 auto'
      }}>
        Passive OSINT intelligence gathering across DNS, SSL, subdomains,
        open ports, code leaks, and network footprint.
      </p>

      {/* Feature tags */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: '0.45rem',
        justifyContent: 'center', marginTop: '1.5rem'
      }}>
        {FEATURE_TAGS.map((tag, i) => (
          <span
            key={tag}
            className="cyber-tag tag-info"
            style={{
              animation: `fade-in-up 0.4s ease ${0.8 + i * 0.06}s both`,
              cursor: 'default'
            }}
          >
            {tag}
          </span>
        ))}
      </div>
    </div>
  )
}

export default App

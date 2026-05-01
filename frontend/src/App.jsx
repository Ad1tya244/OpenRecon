import { useState, useEffect } from 'react'
import './index.css'
import SearchBar from './components/SearchBar'
import Dashboard from './components/Dashboard'

// Animated matrix rain characters for background ambiance
const MatrixRain = () => {
  return (
    <div style={{
      position: 'fixed', inset: 0, overflow: 'hidden',
      pointerEvents: 'none', zIndex: 0, opacity: 0.03
    }}>
      {Array.from({ length: 15 }).map((_, i) => (
        <div key={i} style={{
          position: 'absolute',
          top: '-20%',
          left: `${(i / 15) * 100}%`,
          fontFamily: 'Share Tech Mono, monospace',
          fontSize: '14px',
          color: '#00ff9d',
          lineHeight: '1.2',
          animation: `data-stream ${3 + (i % 4)}s linear ${i * 0.3}s infinite`,
          whiteSpace: 'pre',
          userSelect: 'none',
        }}>
          {Array.from({ length: 30 }, () =>
            Math.random() > 0.5
              ? String.fromCharCode(0x30A0 + Math.floor(Math.random() * 96))
              : Math.floor(Math.random() * 10)
          ).join('\n')}
        </div>
      ))}
    </div>
  )
}

function App() {
  const [target, setTarget] = useState(null)
  const [loading, setLoading] = useState(false)
  const [time, setTime] = useState(new Date())

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const handleSearch = async (domain) => {
    setLoading(true)
    setTarget(domain)
    setLoading(false)
  }

  const timeStr = time.toTimeString().split(' ')[0]
  const dateStr = time.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })

  return (
    <div className="app-layout">
      <MatrixRain />

      <header style={{
        padding: '0',
        borderBottom: '1px solid var(--border-color)',
        background: 'rgba(2, 4, 8, 0.95)',
        backdropFilter: 'blur(20px)',
        position: 'sticky', top: 0, zIndex: 100,
        boxShadow: '0 1px 0 var(--border-color), 0 4px 20px rgba(0, 255, 180, 0.05)'
      }}>
        {/* Top bar */}
        <div style={{
          background: 'rgba(0, 255, 180, 0.05)',
          borderBottom: '1px solid var(--border-color)',
          padding: '0.3rem 1.5rem',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center'
        }}>
          <div style={{ display: 'flex', gap: '1.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
            <span>SYS:ACTIVE</span>
            <span style={{ color: 'var(--green)' }}>NET:ONLINE</span>
            <span>MODE:PASSIVE</span>
          </div>
          <div style={{ display: 'flex', gap: '1.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
            <span>{dateStr}</span>
            <span style={{ color: 'var(--cyan)' }}>{timeStr}</span>
          </div>
        </div>

        {/* Main nav */}
        <div className="container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1rem 1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ position: 'relative' }}>
              <div style={{
                width: '36px', height: '36px',
                border: '1px solid var(--cyan)',
                borderRadius: '4px',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                boxShadow: '0 0 10px var(--cyan-glow)',
                background: 'var(--cyan-dim)'
              }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="1.5">
                  <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
                  <path d="M11 8v6M8 11h6" strokeLinecap="round"/>
                </svg>
              </div>
            </div>
            <div>
              <h1 style={{
                fontFamily: 'var(--font-display)', fontSize: '1.4rem', fontWeight: '700',
                letterSpacing: '0.1em', lineHeight: 1
              }}>
                OPEN<span className="text-gradient">RECON</span>
              </h1>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: 'var(--text-dim)', letterSpacing: '0.15em', marginTop: '2px' }}>
                PASSIVE OSINT ENGINE v2.0
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            {target && (
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
                color: 'var(--text-secondary)',
                padding: '0.4rem 0.8rem',
                border: '1px solid var(--border-color)',
                borderRadius: '4px',
                background: 'var(--cyan-dim)'
              }}>
                TARGET: <span style={{ color: 'var(--cyan)' }}>{target}</span>
              </div>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div className="status-dot" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--green)' }}>OPERATIONAL</span>
            </div>
          </div>
        </div>
      </header>

      <main className="container" style={{ padding: '2rem 1.5rem', flex: 1, position: 'relative', zIndex: 1 }}>
        {!target && (
          <div style={{ maxWidth: '680px', margin: '5rem auto 0', animation: 'fade-in-up 0.6s ease' }}>
            {/* Hero */}
            <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--cyan)',
                letterSpacing: '0.2em', textTransform: 'uppercase', marginBottom: '1rem',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem'
              }}>
                <span style={{ color: 'var(--green)' }}>▶</span>
                INITIALIZING RECONNAISSANCE SUITE
                <span style={{ color: 'var(--green)', animation: 'blink 1s step-end infinite' }}>_</span>
              </div>
              <h2 style={{
                fontFamily: 'var(--font-display)',
                fontSize: 'clamp(2rem, 5vw, 3.5rem)',
                fontWeight: '900',
                lineHeight: 1.1,
                marginBottom: '1rem',
                letterSpacing: '0.05em'
              }}>
                <span className="text-gradient glow-text">ATTACK SURFACE</span>
                <br />
                <span style={{ color: 'var(--text-primary)', fontSize: '0.7em' }}>MAPPING SYSTEM</span>
              </h2>
              <p style={{
                color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem', lineHeight: 1.8, maxWidth: '500px', margin: '0 auto'
              }}>
                Passive OSINT intelligence gathering across DNS, SSL, subdomains,
                open ports, code leaks, and network footprint — all in one terminal.
              </p>

              {/* Feature tags */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', justifyContent: 'center', marginTop: '1.5rem' }}>
                {['DNS RECON', 'SSL AUDIT', 'SUBDOMAIN MAP', 'PORT SCAN', 'CODE LEAKS', 'THREAT INTEL'].map(tag => (
                  <span key={tag} className="cyber-tag tag-info">{tag}</span>
                ))}
              </div>
            </div>

            <SearchBar onSearch={handleSearch} loading={loading} />
          </div>
        )}

        {target && (
          <Dashboard domain={target} onReset={() => setTarget(null)} />
        )}
      </main>

      <footer style={{
        padding: '1rem 1.5rem',
        borderTop: '1px solid var(--border-color)',
        background: 'rgba(2,4,8,0.9)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        position: 'relative', zIndex: 1
      }}>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
          OpenRecon © 2026 — <span style={{ color: 'var(--red)' }}>Strictly educational & defensive use only</span>
        </p>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
          PASSIVE MODE | NO ACTIVE PROBING
        </p>
      </footer>
    </div>
  )
}

export default App

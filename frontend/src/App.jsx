import { useState } from 'react'
import './index.css'
import SearchBar from './components/SearchBar'
import Dashboard from './components/Dashboard'

function App() {
  const [target, setTarget] = useState(null)
  const [scanData, setScanData] = useState(null)
  const [loading, setLoading] = useState(false)

  const handleSearch = async (domain) => {
    setLoading(true)
    setTarget(domain)
    setScanData(null)

    // Simulate loading for now, will replace with real API calls
    // In a real app we might fetch these in parallel or one by one
    try {
      // TODO: Implement actual API calls to FastAPI backend
      // For now, pass the domain to the dashboard to handle fetching or mock it
      setScanData({ domain })
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app-layout">
      <header style={{ padding: '2rem 0', textAlign: 'center', borderBottom: '1px solid var(--border-color)' }}>
        <div className="container">
          <h1 style={{ fontSize: '2.5rem', fontWeight: '800', letterSpacing: '-0.05em', marginBottom: '0.5rem' }}>
            OPEN<span className="text-gradient">RECON</span>
          </h1>
          <p style={{ color: 'var(--text-secondary)' }}>Passive OSINT Intelligence & Attack Surface Mapping</p>
        </div>
      </header>

      <main className="container" style={{ padding: '3rem 1.5rem', flex: 1 }}>
        {!target && (
          <div style={{ maxWidth: '600px', margin: '0 auto', textAlign: 'center', marginTop: '4rem' }}>
            <SearchBar onSearch={handleSearch} loading={loading} />
          </div>
        )}

        {target && (
          <Dashboard domain={target} onReset={() => setTarget(null)} />
        )}
      </main>

      <footer style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.875rem' }}>
        <p>OpenRecon &copy; 2026. Strictly for educational and defensive use.</p>
      </footer>
    </div>
  )
}

export default App

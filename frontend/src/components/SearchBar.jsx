import { useState } from 'react'

const SearchBar = ({ onSearch, loading }) => {
    const [input, setInput] = useState('')
    const [error, setError] = useState('')
    const [focused, setFocused] = useState(false)

    const handleSubmit = (e) => {
        e.preventDefault()
        if (!input.trim()) { setError('// ERROR: target domain required'); return }
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/
        const clean = input.replace('https://', '').replace('http://', '').split('/')[0]
        if (!domainRegex.test(clean)) { setError('// ERROR: invalid domain format'); return }
        setError('')
        onSearch(clean)
    }

    return (
        <div style={{ position: 'relative' }}>
            {/* Corner decorations */}
            <div className="corner-decoration corner-tl" />
            <div className="corner-decoration corner-tr" />
            <div className="corner-decoration corner-bl" />
            <div className="corner-decoration corner-br" />

            <div className="card" style={{
                padding: '2rem',
                border: focused ? '1px solid var(--cyan)' : '1px solid var(--border-color)',
                boxShadow: focused ? '0 0 30px var(--cyan-dim), 0 0 60px rgba(0,255,225,0.05)' : 'none',
                transition: 'all 0.3s ease'
            }}>
                {/* Card header */}
                <div style={{
                    display: 'flex', alignItems: 'center', gap: '0.75rem',
                    marginBottom: '1.5rem', paddingBottom: '1rem',
                    borderBottom: '1px solid var(--border-color)'
                }}>
                    <div style={{
                        width: '8px', height: '8px', borderRadius: '50%',
                        background: 'var(--green)',
                        boxShadow: '0 0 6px var(--green)',
                        animation: 'blink 2s ease-in-out infinite'
                    }} />
                    <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.75rem',
                        color: 'var(--cyan)', letterSpacing: '0.15em', textTransform: 'uppercase'
                    }}>
                        TARGET ACQUISITION
                    </span>
                </div>

                <form onSubmit={handleSubmit}>
                    {/* Input field */}
                    <div style={{ marginBottom: '1.25rem' }}>
                        <div style={{
                            display: 'flex', alignItems: 'center',
                            border: `1px solid ${error ? 'var(--red)' : focused ? 'var(--cyan)' : 'var(--border-color)'}`,
                            borderRadius: '4px',
                            background: 'rgba(0,0,0,0.4)',
                            transition: 'all 0.2s ease',
                            boxShadow: focused ? `0 0 15px ${error ? 'var(--red-dim)' : 'var(--cyan-dim)'}` : 'none'
                        }}>
                            <span style={{
                                fontFamily: 'var(--font-mono)', fontSize: '1rem',
                                color: 'var(--cyan)', padding: '0.9rem 0.75rem',
                                borderRight: '1px solid var(--border-color)',
                                userSelect: 'none'
                            }}>$&gt;</span>
                            <input
                                type="text"
                                value={input}
                                onChange={(e) => { setInput(e.target.value); setError('') }}
                                onFocus={() => setFocused(true)}
                                onBlur={() => setFocused(false)}
                                placeholder="target.domain.com"
                                autoComplete="off"
                                spellCheck="false"
                                style={{
                                    flex: 1,
                                    padding: '0.9rem 1rem',
                                    backgroundColor: 'transparent',
                                    border: 'none',
                                    color: 'var(--green)',
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: '1.1rem',
                                    letterSpacing: '0.05em',
                                    outline: 'none',
                                    caretColor: 'var(--cyan)'
                                }}
                            />
                        </div>

                        {error && (
                            <p style={{
                                color: 'var(--red)', marginTop: '0.5rem',
                                fontSize: '0.8rem', fontFamily: 'var(--font-mono)'
                            }}>{error}</p>
                        )}
                    </div>

                    <button
                        type="submit"
                        className="btn btn-primary"
                        style={{ width: '100%', padding: '0.85rem', fontSize: '0.9rem', letterSpacing: '0.15em' }}
                        disabled={loading}
                    >
                        {loading ? (
                            <>
                                <span style={{ animation: 'cyber-spin 1s linear infinite', display: 'inline-block' }}>⟳</span>
                                SCANNING TARGET...
                            </>
                        ) : '[ INITIATE SCAN ]'}
                    </button>
                </form>

                {/* Warning */}
                <div style={{
                    marginTop: '1.25rem', padding: '0.6rem 0.8rem',
                    background: 'rgba(255,183,0,0.05)',
                    border: '1px solid rgba(255,183,0,0.2)',
                    borderRadius: '4px',
                    display: 'flex', alignItems: 'center', gap: '0.5rem'
                }}>
                    <span style={{ color: 'var(--amber)', fontSize: '0.8rem' }}>⚠</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)', letterSpacing: '0.05em' }}>
                        PASSIVE MODE — No active probing or exploitation
                    </span>
                </div>
            </div>
        </div>
    )
}

export default SearchBar

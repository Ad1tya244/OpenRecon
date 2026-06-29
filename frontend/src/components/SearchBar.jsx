import { useState, useEffect, useRef } from 'react'

const EXAMPLES = ['google.com', 'github.com', 'cloudflare.com', 'amazon.com']

const SearchBar = ({ onSearch, loading, showToast }) => {
    const [input, setInput] = useState('')
    const [error, setError] = useState('')
    const [focused, setFocused] = useState(false)
    const [history, setHistory] = useState(() => {
        try { return JSON.parse(localStorage.getItem('or_history') || '[]') } catch { return [] }
    })
    const [showSuggestions, setShowSuggestions] = useState(false)
    const inputRef = useRef(null)
    const wrapRef = useRef(null)

    // Close suggestions on outside click
    useEffect(() => {
        const handler = (e) => {
            if (wrapRef.current && !wrapRef.current.contains(e.target)) {
                setShowSuggestions(false)
            }
        }
        document.addEventListener('mousedown', handler)
        return () => document.removeEventListener('mousedown', handler)
    }, [])

    const validate = (val) => {
        const clean = val.replace('https://', '').replace('http://', '').split('/')[0].trim()
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(?:\.[a-zA-Z]{2,})+$/
        return domainRegex.test(clean) ? clean : null
    }

    const handleSubmit = (e) => {
        e?.preventDefault()
        if (!input.trim()) { setError('// TARGET REQUIRED'); return }
        const clean = validate(input)
        if (!clean) { setError('// INVALID DOMAIN FORMAT'); return }
        setError('')
        setShowSuggestions(false)

        // Save to history
        const newHistory = [clean, ...history.filter(h => h !== clean)].slice(0, 5)
        setHistory(newHistory)
        localStorage.setItem('or_history', JSON.stringify(newHistory))

        onSearch(clean)
    }

    const pickSuggestion = (val) => {
        setInput(val)
        setShowSuggestions(false)
        setError('')
        inputRef.current?.focus()
    }

    const suggestions = input.length >= 2
        ? history.filter(h => h.includes(input) && h !== input)
        : []

    const showDropdown = (focused || showSuggestions) && (suggestions.length > 0 || input.length === 0)

    return (
        <div ref={wrapRef} style={{ position: 'relative' }}>
            {/* Corner decorations */}
            <div className="corner-decoration corner-tl" />
            <div className="corner-decoration corner-tr" />
            <div className="corner-decoration corner-bl" />
            <div className="corner-decoration corner-br" />

            <div className="card" style={{
                padding: '1.75rem',
                border: focused ? '1px solid var(--cyan)' : error ? '1px solid var(--red)' : '1px solid var(--border-color)',
                boxShadow: focused
                    ? '0 0 30px var(--cyan-dim), 0 0 60px rgba(0,255,225,0.04)'
                    : error ? '0 0 20px var(--red-dim)' : 'none',
                transition: 'all 0.3s ease'
            }}>
                {/* Card header */}
                <div style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    marginBottom: '1.25rem', paddingBottom: '0.85rem',
                    borderBottom: '1px solid var(--border-color)'
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <div style={{
                            width: '7px', height: '7px', borderRadius: '50%',
                            background: 'var(--green)',
                            boxShadow: '0 0 6px var(--green)',
                            animation: 'blink 2s ease-in-out infinite'
                        }} />
                        <span style={{
                            fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
                            color: 'var(--cyan)', letterSpacing: '0.18em', textTransform: 'uppercase'
                        }}>
                            Target Acquisition
                        </span>
                    </div>
                    {history.length > 0 && (
                        <span style={{
                            fontFamily: 'var(--font-mono)', fontSize: '0.65rem',
                            color: 'var(--text-dim)', cursor: 'pointer',
                            transition: 'color 0.2s'
                        }}
                            onMouseEnter={e => e.target.style.color = 'var(--cyan)'}
                            onMouseLeave={e => e.target.style.color = 'var(--text-dim)'}
                            onClick={() => setShowSuggestions(!showSuggestions)}
                        >
                            HISTORY [{history.length}]
                        </span>
                    )}
                </div>

                <form onSubmit={handleSubmit}>
                    {/* Input */}
                    <div style={{ marginBottom: '1rem', position: 'relative' }}>
                        <div style={{
                            display: 'flex', alignItems: 'center',
                            border: `1px solid ${error ? 'var(--red)' : focused ? 'var(--cyan)' : 'rgba(0,255,180,0.15)'}`,
                            borderRadius: '4px',
                            background: 'rgba(0,0,0,0.5)',
                            transition: 'all 0.2s ease',
                            boxShadow: focused
                                ? `0 0 0 1px ${error ? 'var(--red-dim)' : 'var(--cyan-dim)'}`
                                : 'none'
                        }}>
                            <span style={{
                                fontFamily: 'var(--font-mono)', fontSize: '1rem',
                                color: 'var(--cyan)', padding: '0.9rem 0.85rem',
                                borderRight: '1px solid rgba(0,255,180,0.1)',
                                userSelect: 'none', flexShrink: 0
                            }}>$&gt;</span>
                            <input
                                ref={inputRef}
                                type="text"
                                value={input}
                                onChange={(e) => { setInput(e.target.value); setError('') }}
                                onFocus={() => { setFocused(true); setShowSuggestions(true) }}
                                onBlur={() => setFocused(false)}
                                onKeyDown={(e) => {
                                    if (e.key === 'Escape') { setShowSuggestions(false); setInput('') }
                                }}
                                placeholder="target.domain.com"
                                autoComplete="off"
                                spellCheck="false"
                                style={{
                                    flex: 1,
                                    padding: '0.9rem 0.85rem',
                                    backgroundColor: 'transparent',
                                    border: 'none',
                                    color: 'var(--green)',
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: '1.05rem',
                                    letterSpacing: '0.04em',
                                    caretColor: 'var(--cyan)'
                                }}
                            />
                            {input && (
                                <button
                                    type="button"
                                    onClick={() => { setInput(''); setError(''); inputRef.current?.focus() }}
                                    style={{
                                        background: 'none', border: 'none',
                                        color: 'var(--text-dim)', cursor: 'pointer',
                                        padding: '0 0.85rem', fontSize: '1rem',
                                        transition: 'color 0.2s'
                                    }}
                                    onMouseEnter={e => e.target.style.color = 'var(--red)'}
                                    onMouseLeave={e => e.target.style.color = 'var(--text-dim)'}
                                >✕</button>
                            )}
                        </div>

                        {/* Dropdown (history or examples) */}
                        {showDropdown && (
                            <div style={{
                                position: 'absolute', top: 'calc(100% + 4px)', left: 0, right: 0,
                                background: 'rgba(2,6,10,0.98)',
                                border: '1px solid var(--border-color)',
                                borderRadius: '4px',
                                zIndex: 50,
                                overflow: 'hidden',
                                backdropFilter: 'blur(16px)',
                                boxShadow: '0 8px 32px rgba(0,0,0,0.7)'
                            }}>
                                {/* History */}
                                {suggestions.length > 0 && (
                                    <>
                                        <div style={{ padding: '0.4rem 0.75rem', fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-dim)', letterSpacing: '0.12em', borderBottom: '1px solid var(--border-color)' }}>
                                            RECENT TARGETS
                                        </div>
                                        {suggestions.map(h => (
                                            <div key={h}
                                                onMouseDown={() => pickSuggestion(h)}
                                                style={{
                                                    padding: '0.55rem 0.85rem',
                                                    fontFamily: 'var(--font-mono)', fontSize: '0.85rem',
                                                    color: 'var(--text-secondary)', cursor: 'pointer',
                                                    display: 'flex', alignItems: 'center', gap: '0.5rem',
                                                    transition: 'all 0.15s',
                                                    borderBottom: '1px solid rgba(0,255,180,0.04)'
                                                }}
                                                onMouseEnter={e => { e.currentTarget.style.background = 'var(--cyan-dim)'; e.currentTarget.style.color = 'var(--cyan)' }}
                                                onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'var(--text-secondary)' }}
                                            >
                                                <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>↺</span>
                                                {h}
                                            </div>
                                        ))}
                                    </>
                                )}

                                {/* Examples when input is empty */}
                                {input.length === 0 && (
                                    <>
                                        <div style={{ padding: '0.4rem 0.75rem', fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-dim)', letterSpacing: '0.12em', borderBottom: '1px solid var(--border-color)' }}>
                                            EXAMPLE TARGETS
                                        </div>
                                        {EXAMPLES.map(ex => (
                                            <div key={ex}
                                                onMouseDown={() => pickSuggestion(ex)}
                                                style={{
                                                    padding: '0.55rem 0.85rem',
                                                    fontFamily: 'var(--font-mono)', fontSize: '0.85rem',
                                                    color: 'var(--text-dim)', cursor: 'pointer',
                                                    display: 'flex', alignItems: 'center', gap: '0.5rem',
                                                    transition: 'all 0.15s',
                                                    borderBottom: '1px solid rgba(0,255,180,0.04)'
                                                }}
                                                onMouseEnter={e => { e.currentTarget.style.background = 'var(--cyan-dim)'; e.currentTarget.style.color = 'var(--cyan)' }}
                                                onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'var(--text-dim)' }}
                                            >
                                                <span style={{ color: 'var(--border-color)', fontSize: '0.75rem' }}>›</span>
                                                {ex}
                                            </div>
                                        ))}
                                    </>
                                )}
                            </div>
                        )}

                        {error && (
                            <p style={{
                                color: 'var(--red)', marginTop: '0.5rem',
                                fontSize: '0.78rem', fontFamily: 'var(--font-mono)',
                                animation: 'fade-in-up 0.2s ease'
                            }}>{error}</p>
                        )}
                    </div>

                    <button
                        type="submit"
                        className="btn btn-primary"
                        style={{
                            width: '100%', padding: '0.9rem',
                            fontSize: '0.88rem', letterSpacing: '0.18em',
                            opacity: loading ? 0.7 : 1
                        }}
                        disabled={loading}
                    >
                        {loading ? (
                            <>
                                <span style={{ animation: 'cyber-spin 0.8s linear infinite', display: 'inline-block', marginRight: '0.5rem' }}>⟳</span>
                                SCANNING TARGET...
                            </>
                        ) : '[ INITIATE SCAN ]'}
                    </button>
                </form>

                {/* Keyboard hint */}
                <div className="search-bar-footer">
                    <div style={{
                        padding: '0.5rem 0.75rem',
                        background: 'rgba(255,183,0,0.05)',
                        border: '1px solid rgba(255,183,0,0.18)',
                        borderRadius: '4px',
                        display: 'flex', alignItems: 'center', gap: '0.5rem',
                        flex: 1
                    }}>
                        <span style={{ color: 'var(--amber)', fontSize: '0.8rem' }}>⚠</span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-dim)', letterSpacing: '0.04em' }}>
                            PASSIVE ONLY — No active probing or exploitation
                        </span>
                    </div>
                    <div style={{ marginLeft: '0.75rem', display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                        {['ESC', 'ENTER'].map(k => (
                            <span key={k} style={{
                                fontFamily: 'var(--font-mono)', fontSize: '0.62rem',
                                color: 'var(--text-dim)', padding: '0.2rem 0.4rem',
                                border: '1px solid var(--border-color)', borderRadius: '3px',
                                background: 'rgba(0,0,0,0.3)'
                            }}>{k}</span>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    )
}

export default SearchBar

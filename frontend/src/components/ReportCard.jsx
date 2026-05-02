import React from 'react'

const spinnerStyle = {
    display: 'inline-block',
    width: '14px', height: '14px',
    border: '2px solid rgba(0, 255, 225, 0.15)',
    borderTopColor: 'var(--cyan)',
    borderRadius: '50%',
    animation: 'cyber-spin 0.8s linear infinite',
    flexShrink: 0
}

// Shimmer skeleton rows while loading
const SkeletonRows = ({ count = 5, type = 'kv' }) => (
    <div style={{ display: 'grid', gap: '0.5rem' }}>
        {Array.from({ length: count }).map((_, i) => (
            <div key={i} style={{
                display: 'flex', justifyContent: type === 'kv' ? 'space-between' : 'flex-start',
                alignItems: 'center', gap: '0.5rem',
                padding: '0.3rem 0',
                borderBottom: '1px solid rgba(0,255,180,0.05)'
            }}>
                <div className="shimmer" style={{
                    height: '10px',
                    width: type === 'kv' ? `${30 + (i * 13) % 25}%` : `${50 + (i * 17) % 35}%`,
                    borderRadius: '3px'
                }} />
                {type === 'kv' && (
                    <div className="shimmer" style={{
                        height: '10px',
                        width: `${25 + (i * 11) % 30}%`,
                        borderRadius: '3px'
                    }} />
                )}
            </div>
        ))}
    </div>
)

const renderValue = (v) => {
    const str = String(v)
    if (str === '✅ Present') return <span style={{ color: 'var(--green)' }}>● PRESENT</span>
    if (str === '❌ Missing') return <span style={{ color: 'var(--red)' }}>● MISSING</span>
    if (str === '✅ Yes' || str === 'Yes') return <span style={{ color: 'var(--green)' }}>● YES</span>
    if (str === '❌ No' || str === 'No') return <span style={{ color: 'var(--red)' }}>● NO</span>
    if (str.startsWith('❓')) return <span style={{ color: 'var(--amber)' }}>? {str.replace('❓ ', '')}</span>
    return <span style={{ color: 'var(--text-primary)' }}>{str}</span>
}

const ReportCard = ({ title, data, type = 'list', loading, icon, onRetry }) => {
    const isError = data && !loading && data.error
    const isEmpty = !loading && (!data || Object.keys(data).length === 0)

    return (
        <div className="card card-stagger" style={{ height: '100%', position: 'relative' }}>
            {/* Corner marks */}
            <div className="corner-decoration corner-tl" style={{ opacity: 0.3 }} />
            <div className="corner-decoration corner-br" style={{ opacity: 0.3 }} />

            {/* Header */}
            <div style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                marginBottom: '1rem', paddingBottom: '0.75rem',
                borderBottom: '1px solid var(--border-color)'
            }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    {icon && <span style={{ fontSize: '0.95rem', lineHeight: 1 }}>{icon}</span>}
                    <h3 style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.78rem', fontWeight: '600',
                        color: isError ? 'var(--red)' : 'var(--cyan)',
                        letterSpacing: '0.1em', textTransform: 'uppercase'
                    }}>{title}</h3>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {loading && (
                        <>
                            <div style={spinnerStyle} />
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-dim)', letterSpacing: '0.1em' }}>SCANNING</span>
                        </>
                    )}
                    {!loading && isError && onRetry && (
                        <button
                            onClick={onRetry}
                            title="Retry this module"
                            style={{
                                background: 'none', border: '1px solid var(--red)',
                                color: 'var(--red)', borderRadius: '3px',
                                fontFamily: 'var(--font-mono)', fontSize: '0.62rem',
                                padding: '0.15rem 0.4rem', cursor: 'pointer',
                                transition: 'all 0.2s', letterSpacing: '0.05em'
                            }}
                            onMouseEnter={e => { e.currentTarget.style.background = 'var(--red-dim)' }}
                            onMouseLeave={e => { e.currentTarget.style.background = 'none' }}
                        >
                            ↺ RETRY
                        </button>
                    )}
                    {!loading && !isError && data && (
                        <span style={{
                            fontFamily: 'var(--font-mono)', fontSize: '0.62rem',
                            color: 'var(--green)', letterSpacing: '0.1em'
                        }}>● DONE</span>
                    )}
                </div>
            </div>

            {/* Body */}
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
                {loading ? (
                    <SkeletonRows count={type === 'list' ? 4 : 5} type={type} />
                ) : isError ? (
                    <div style={{
                        padding: '1rem', textAlign: 'center',
                        background: 'var(--red-dim)', borderRadius: '4px',
                        border: '1px solid rgba(255,0,60,0.2)'
                    }}>
                        <div style={{ color: 'var(--red)', fontSize: '0.75rem', letterSpacing: '0.08em', marginBottom: '0.25rem' }}>
                            // FETCH ERROR
                        </div>
                        <div style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>{data.error}</div>
                    </div>
                ) : !data ? (
                    <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.72rem', letterSpacing: '0.1em' }}>
                        NO DATA RETRIEVED
                    </div>
                ) : (
                    <>
                        {type === 'kv' && (
                            <div style={{ display: 'grid', gap: '0.4rem' }}>
                                {Object.entries(data).map(([k, v]) => (
                                    <div key={k} style={{
                                        display: 'flex', justifyContent: 'space-between',
                                        alignItems: 'flex-start', gap: '0.5rem',
                                        padding: '0.3rem 0',
                                        borderBottom: '1px solid rgba(0,255,180,0.05)'
                                    }}>
                                        <span style={{ color: 'var(--text-dim)', flexShrink: 0, fontSize: '0.75rem' }}>{k}:</span>
                                        <div style={{ textAlign: 'right', overflowWrap: 'anywhere', fontSize: '0.75rem' }}>
                                            {renderValue(v)}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                        {type === 'list' && (
                            <ul style={{ listStyle: 'none', display: 'grid', gap: '0.25rem' }}>
                                {Array.isArray(data) && data.map((item, i) => (
                                    <li key={i} style={{
                                        padding: '0.28rem 0',
                                        borderBottom: '1px solid rgba(0,255,180,0.05)',
                                        color: 'var(--text-secondary)',
                                        display: 'flex', alignItems: 'flex-start', gap: '0.5rem',
                                        fontSize: '0.75rem'
                                    }}>
                                        <span style={{ color: 'var(--cyan)', flexShrink: 0, marginTop: '1px' }}>›</span>
                                        <span style={{ overflowWrap: 'anywhere' }}>{item}</span>
                                    </li>
                                ))}
                            </ul>
                        )}
                        {type === 'json' && (
                            <pre style={{ overflowX: 'auto', whiteSpace: 'pre-wrap', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                                {JSON.stringify(data, null, 2)}
                            </pre>
                        )}
                    </>
                )}
            </div>
        </div>
    )
}

export default ReportCard

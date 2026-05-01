import React from 'react'

const spinnerStyle = {
    display: 'inline-block',
    width: '14px', height: '14px',
    border: '2px solid rgba(0, 255, 225, 0.2)',
    borderTopColor: 'var(--cyan)',
    borderRadius: '50%',
    animation: 'cyber-spin 0.8s linear infinite',
    flexShrink: 0
}

const ReportCard = ({ title, data, type = 'list', loading, icon }) => {
    const renderValue = (v) => {
        const str = String(v)
        if (str === '✅ Present') return <span style={{ color: 'var(--green)' }}>● PRESENT</span>
        if (str === '❌ Missing') return <span style={{ color: 'var(--red)' }}>● MISSING</span>
        if (str === '✅ Yes' || str === 'Yes') return <span style={{ color: 'var(--green)' }}>● YES</span>
        if (str === '✅ No' || str === 'No') return <span style={{ color: 'var(--red)' }}>● NO</span>
        if (str.startsWith('❓')) return <span style={{ color: 'var(--amber)' }}>? {str.replace('❓ ', '')}</span>
        return <span style={{ color: 'var(--text-primary)' }}>{str}</span>
    }

    return (
        <div className="card" style={{ height: '100%', position: 'relative' }}>
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
                    {icon && <span style={{ fontSize: '1rem' }}>{icon}</span>}
                    <h3 style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: '600',
                        color: 'var(--cyan)', letterSpacing: '0.1em', textTransform: 'uppercase'
                    }}>{title}</h3>
                </div>
                {loading && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <div style={spinnerStyle} />
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-dim)', letterSpacing: '0.1em' }}>SCANNING</span>
                    </div>
                )}
                {!loading && data && (
                    <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.65rem',
                        color: 'var(--green)', letterSpacing: '0.1em'
                    }}>● DONE</span>
                )}
            </div>

            {/* Body */}
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
                {loading ? (
                    <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-dim)' }}>
                        <div style={{ ...spinnerStyle, width: '20px', height: '20px', margin: '0 auto 0.5rem' }} />
                        <span style={{ fontSize: '0.75rem', letterSpacing: '0.1em' }}>ACQUIRING DATA...</span>
                    </div>
                ) : !data ? (
                    <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.75rem', letterSpacing: '0.1em' }}>
                        NO DATA RETRIEVED
                    </div>
                ) : (
                    <>
                        {type === 'kv' && (
                            <div style={{ display: 'grid', gap: '0.45rem' }}>
                                {Object.entries(data).map(([k, v]) => (
                                    <div key={k} style={{
                                        display: 'flex', justifyContent: 'space-between',
                                        alignItems: 'flex-start', gap: '0.5rem',
                                        padding: '0.35rem 0',
                                        borderBottom: '1px solid rgba(0,255,180,0.05)'
                                    }}>
                                        <span style={{ color: 'var(--text-dim)', flexShrink: 0, fontSize: '0.78rem' }}>{k}:</span>
                                        <div style={{ textAlign: 'right', overflowWrap: 'anywhere', fontSize: '0.78rem' }}>
                                            {renderValue(v)}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                        {type === 'list' && (
                            <ul style={{ listStyle: 'none', display: 'grid', gap: '0.3rem' }}>
                                {Array.isArray(data) && data.map((item, i) => (
                                    <li key={i} style={{
                                        padding: '0.3rem 0',
                                        borderBottom: '1px solid rgba(0,255,180,0.05)',
                                        color: 'var(--text-secondary)',
                                        display: 'flex', alignItems: 'flex-start', gap: '0.5rem',
                                        fontSize: '0.78rem'
                                    }}>
                                        <span style={{ color: 'var(--cyan)', flexShrink: 0, marginTop: '2px' }}>›</span>
                                        <span style={{ overflowWrap: 'anywhere' }}>{item}</span>
                                    </li>
                                ))}
                            </ul>
                        )}
                        {type === 'json' && (
                            <pre style={{
                                overflowX: 'auto', whiteSpace: 'pre-wrap',
                                fontSize: '0.72rem', color: 'var(--text-secondary)'
                            }}>
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

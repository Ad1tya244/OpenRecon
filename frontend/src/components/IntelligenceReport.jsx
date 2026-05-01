import React, { useState, useEffect } from 'react';

const IntelligenceReport = ({ domain, initialData, onBack, filter }) => {
    const [findings, setFindings] = useState(initialData || []);
    const [loading, setLoading] = useState(!initialData);
    const [error, setError] = useState(null);

    const displayFindings = filter
        ? findings.filter(f => f.title?.toLowerCase().includes(filter.toLowerCase()))
        : findings.filter(f => !f.title?.toLowerCase().includes('attack vector'));

    useEffect(() => {
        if (initialData) { setFindings(initialData); setLoading(false); return; }
        const fetchIntelligence = async () => {
            try {
                const response = await fetch(`http://localhost:8000/scan/intelligence?domain=${domain}`);
                if (!response.ok) throw new Error('Failed to fetch intelligence report');
                const data = await response.json();
                setFindings(data);
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };
        if (domain) fetchIntelligence();
    }, [domain, initialData]);

    const getSeverityColor = (severity) => {
        switch (severity?.toLowerCase()) {
            case 'high': return { color: 'var(--red)', border: 'var(--red)', bg: 'var(--red-dim)', accent: '#ff003c' };
            case 'medium': return { color: 'var(--amber)', border: 'var(--amber)', bg: 'rgba(255,183,0,0.1)', accent: '#ffb700' };
            case 'low': return { color: '#60a5fa', border: '#3b82f6', bg: 'rgba(59,130,246,0.1)', accent: '#3b82f6' };
            default: return { color: 'var(--text-dim)', border: 'var(--border-color)', bg: 'transparent', accent: '#555' };
        }
    };

    return (
        <div style={{ animation: 'fade-in-up 0.4s ease' }}>
            {/* Header */}
            <div style={{
                marginBottom: '1.5rem',
                padding: '1.25rem 1.5rem',
                background: 'var(--bg-glass)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                backdropFilter: 'blur(10px)',
                position: 'relative', overflow: 'hidden',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between'
            }}>
                <div style={{
                    position: 'absolute', top: 0, left: 0, right: 0, height: '2px',
                    background: filter
                        ? 'linear-gradient(90deg, transparent, var(--red), var(--amber), transparent)'
                        : 'linear-gradient(90deg, transparent, var(--green), var(--cyan), transparent)'
                }} />
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <button onClick={onBack} className="btn btn-outline">← Back</button>
                    <div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)', letterSpacing: '0.15em' }}>
                            {filter ? 'ATTACK PATH ANALYSIS' : 'STRATEGIC INTELLIGENCE REPORT'}
                        </div>
                        <h1 style={{ fontFamily: 'var(--font-display)', fontSize: '1.4rem', margin: 0, marginTop: '0.2rem' }}>
                            <span className={filter ? 'text-red-gradient' : 'text-gradient'}>{domain}</span>
                        </h1>
                    </div>
                </div>
                {!loading && (
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                        <span style={{ color: filter ? 'var(--red)' : 'var(--cyan)' }}>{displayFindings.length}</span> findings
                    </div>
                )}
            </div>

            {loading ? (
                <div style={{
                    textAlign: 'center', padding: '5rem 2rem',
                    background: 'var(--bg-glass)', border: '1px solid var(--border-color)',
                    borderRadius: '6px', backdropFilter: 'blur(10px)'
                }}>
                    <div style={{
                        width: '40px', height: '40px',
                        border: '2px solid rgba(0,255,225,0.15)',
                        borderTopColor: 'var(--cyan)',
                        borderRadius: '50%',
                        animation: 'cyber-spin 1s linear infinite',
                        margin: '0 auto 1.5rem'
                    }} />
                    <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.2rem', color: 'var(--cyan)', marginBottom: '0.5rem' }}>
                        ANALYZING SIGNALS
                    </h2>
                    <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                        Correlating recon data across all intelligence layers...
                    </p>
                </div>
            ) : error ? (
                <div style={{
                    padding: '2rem', background: 'var(--red-dim)',
                    border: '1px solid var(--red)', borderRadius: '6px'
                }}>
                    <h3 style={{ fontFamily: 'var(--font-mono)', color: 'var(--red)', marginBottom: '0.5rem' }}>
                        // ERROR: REPORT GENERATION FAILED
                    </h3>
                    <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{error}</p>
                </div>
            ) : displayFindings.length === 0 ? (
                <div style={{
                    textAlign: 'center', padding: '4rem 2rem',
                    background: 'var(--bg-glass)', border: '1px solid var(--border-color)',
                    borderRadius: '6px'
                }}>
                    <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>✓</div>
                    <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.1rem', color: 'var(--green)', marginBottom: '0.5rem' }}>
                        {filter ? 'NO ATTACK PATHS IDENTIFIED' : 'NO HIGH-PRIORITY FINDINGS'}
                    </h2>
                    <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                        {filter
                            ? 'No high-confidence attack paths detected via passive OSINT.'
                            : 'No correlated exposure patterns detected. Maintain standard security practices.'}
                    </p>
                </div>
            ) : (
                <div style={{ display: 'grid', gap: '1rem' }}>
                    {displayFindings.map((finding, index) => {
                        const s = getSeverityColor(finding.severity);
                        return (
                            <div key={index} style={{
                                background: 'var(--bg-glass)',
                                borderRadius: '6px',
                                border: '1px solid var(--border-color)',
                                borderLeft: `3px solid ${s.accent}`,
                                padding: '1.25rem 1.5rem',
                                backdropFilter: 'blur(10px)',
                                position: 'relative', overflow: 'hidden',
                                animation: `fade-in-up 0.4s ease ${index * 0.05}s both`
                            }}>
                                <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '1px', background: `linear-gradient(90deg, ${s.accent}, transparent)` }} />

                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                                    <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1rem', margin: 0, letterSpacing: '0.03em' }}>
                                        {finding.title}
                                    </h3>
                                    <span className={`cyber-tag tag-${finding.severity?.toLowerCase() || 'info'}`}>
                                        {finding.severity || 'INFO'}
                                    </span>
                                </div>

                                <p style={{ fontFamily: 'var(--font-sans)', color: 'var(--text-secondary)', lineHeight: '1.7', marginBottom: '1rem', fontSize: '0.9rem' }}>
                                    {finding.description}
                                </p>

                                {finding.signals?.length > 0 && (
                                    <div style={{
                                        background: 'rgba(0,0,0,0.3)',
                                        padding: '0.75rem 1rem',
                                        borderRadius: '4px',
                                        border: '1px solid rgba(0,255,180,0.08)'
                                    }}>
                                        <h4 style={{
                                            fontFamily: 'var(--font-mono)', fontSize: '0.68rem',
                                            color: 'var(--text-dim)', textTransform: 'uppercase',
                                            letterSpacing: '0.12em', marginBottom: '0.5rem'
                                        }}>
                                            {filter ? '// ATTACK SEQUENCE & EVIDENCE' : '// CONTRIBUTING SIGNALS'}
                                        </h4>
                                        <ul style={{ margin: 0, paddingLeft: '0', listStyle: 'none', display: 'grid', gap: '0.3rem' }}>
                                            {finding.signals.map((signal, idx) => (
                                                <li key={idx} style={{
                                                    fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
                                                    color: 'var(--text-secondary)',
                                                    display: 'flex', alignItems: 'flex-start', gap: '0.5rem'
                                                }}>
                                                    <span style={{ color: s.color, flexShrink: 0 }}>›</span>
                                                    {signal}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
};

export default IntelligenceReport;

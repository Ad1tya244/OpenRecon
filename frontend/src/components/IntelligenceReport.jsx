import React, { useState, useEffect } from 'react';

const IntelligenceReport = ({ domain, initialData, onBack, filter }) => {
    const [findings, setFindings] = useState(initialData || []);
    const [loading, setLoading] = useState(!initialData);
    const [error, setError] = useState(null);

    // Filter findings if a filter is provided
    const displayFindings = filter
        ? findings.filter(f => f.title && f.title.toLowerCase().includes(filter.toLowerCase()))
        : findings.filter(f => !f.title || !f.title.toLowerCase().includes('attack vector'));

    useEffect(() => {
        console.log("IntelligenceReport Multi-Stage Debug:", { initialData, domain });
        if (initialData) {
            console.log("Using initialData:", initialData);
            setFindings(initialData);
            setLoading(false);
            return;
        }

        const fetchIntelligence = async () => {
            try {
                // In a production app, we might pass the full scan data from Dashboard 
                // to avoid re-fetching, but triggering the specific endpoint ensures 
                // we run the latest logic.
                const response = await fetch(`http://localhost:8000/scan/intelligence?domain=${domain}`);
                if (!response.ok) {
                    throw new Error('Failed to fetch intelligence report');
                }
                const data = await response.json();
                console.log("Fetched Data from API:", data);
                setFindings(data);
            } catch (err) {
                console.error("Fetch Error:", err);
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        if (domain) {
            fetchIntelligence();
        }
    }, [domain, initialData]);

    // Helper for severity badges
    const getSeverityStyle = (severity) => {
        switch (severity?.toLowerCase()) {
            case 'high': return { backgroundColor: '#ef4444', color: 'white' };
            case 'medium': return { backgroundColor: '#f97316', color: 'white' };
            case 'low': return { backgroundColor: '#3b82f6', color: 'white' };
            default: return { backgroundColor: '#64748b', color: 'white' };
        }
    };

    // Helper for confidence badges
    const getConfidenceStyle = (confidence) => {
        switch (confidence?.toLowerCase()) {
            case 'high': return { backgroundColor: '#10b981', color: 'white' }; // Emerald
            case 'medium': return { backgroundColor: '#f59e0b', color: 'white' }; // Amber
            case 'low': return { backgroundColor: '#94a3b8', color: 'white' }; // Slate
            default: return { backgroundColor: '#94a3b8', color: 'white' };
        }
    };

    return (
        <div style={{ padding: '2rem', maxWidth: '1200px', margin: '0 auto', color: 'var(--text-primary)' }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '2rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <button
                        onClick={onBack}
                        className="btn btn-outline"
                    >
                        &larr; Back
                    </button>
                    <h1 style={{ margin: 0, fontSize: '1.8rem' }}>
                        {filter ? "Attack Path Analysis" : "Strategic Intelligence Report"}: <span className="text-gradient">{domain}</span>
                    </h1>
                </div>
            </div>

            {/* Content */}
            {loading ? (
                <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-dim)' }}>
                    <h2>Analyzing Intelligence Signals...</h2>
                    <p>Correlating recon data across all layers.</p>
                </div>
            ) : error ? (
                <div style={{ padding: '2rem', background: '#fee2e2', color: '#b91c1c', borderRadius: '12px' }}>
                    <h3>Error Generating Report</h3>
                    <p>{error}</p>
                </div>
            ) : displayFindings.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '4rem', background: 'var(--card-bg)', borderRadius: '12px', border: '1px solid var(--border)' }}>
                    <h2>{filter ? "No Probable Attack Paths Identified" : "No High-Priority Intelligence Findings"}</h2>
                    <p style={{ color: 'var(--text-dim)' }}>
                        {filter
                            ? "Based on OSINT inference, no high-confidence attack paths were detected."
                            : "No correlated exposure patterns (like exposed admin panels or critical leak chains) were detected. Ensure standard security practices are maintained."}
                    </p>
                </div>
            ) : (
                <div style={{ display: 'grid', gap: '1.5rem' }}>
                    {displayFindings.map((finding, index) => (
                        <div key={index} style={{
                            background: 'var(--card-bg)',
                            borderRadius: '12px',
                            border: '1px solid var(--border)',
                            padding: '1.5rem',
                            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                            borderLeft: `5px solid ${getSeverityStyle(finding.severity).backgroundColor}`
                        }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '1rem' }}>
                                <h3 style={{ margin: 0, fontSize: '1.4rem' }}>{finding.title}</h3>
                                <span style={{
                                    padding: '0.25rem 0.75rem',
                                    borderRadius: '9999px',
                                    fontSize: '0.875rem',
                                    fontWeight: '600',
                                    ...getSeverityStyle(finding.severity)
                                }}>
                                    {finding.severity} Severity
                                </span>
                            </div>

                            <p style={{ color: 'var(--text-secondary)', lineHeight: '1.6', marginBottom: '1.5rem' }}>
                                {finding.description}
                            </p>

                            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px' }}>
                                <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.9rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                    {filter ? "Attack Sequence & Evidence" : "Contributing Signals"}
                                </h4>
                                <ul style={{ margin: 0, paddingLeft: '1.2rem', color: 'var(--text-primary)' }}>
                                    {finding.signals && finding.signals.map((signal, idx) => (
                                        <li key={idx} style={{ marginBottom: '0.25rem' }}>{signal}</li>
                                    ))}
                                </ul>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default IntelligenceReport;

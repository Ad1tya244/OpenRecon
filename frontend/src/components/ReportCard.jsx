import React from 'react'

const ReportCard = ({ title, data, type = 'list', loading }) => {
    const globalConf = data?.confidence?._global;

    const getConfColor = (score) => {
        if (score === 'High') return '#10b981';
        if (score === 'Medium') return '#f59e0b';
        if (score === 'Low') return '#94a3b8'; // Slate for low confidence (heuristic)
        return 'transparent';
    };

    return (
        <div className="card" style={{ height: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <h3 style={{ fontSize: '1.1rem', fontWeight: '600', color: 'var(--primary)' }}>{title}</h3>
                    {globalConf && (
                        <span
                            title={`Confidence: ${globalConf}`}
                            style={{
                                width: '10px',
                                height: '10px',
                                borderRadius: '50%',
                                backgroundColor: getConfColor(globalConf),
                                display: 'inline-block'
                            }}
                        />
                    )}
                </div>
                {loading && <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Loading...</span>}
            </div>

            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                {loading ? (
                    <div style={{ padding: '1rem', textAlign: 'center' }}>Scanning...</div>
                ) : !data ? (
                    <div style={{ padding: '1rem', textAlign: 'center' }}>No Data</div>
                ) : (
                    <>
                        {type === 'kv' && (
                            <div style={{ display: 'grid', gap: '0.5rem' }}>
                                {Object.entries(data).map(([k, v]) => {
                                    if (k === 'confidence') return null;

                                    const confScore = data.confidence ? data.confidence[k] : null;

                                    return (
                                        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                            <span style={{ color: 'var(--text-dim)' }}>{k}:</span>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                                <span style={{ color: 'var(--text-primary)', overflowWrap: 'anywhere', textAlign: 'right' }}>{String(v)}</span>
                                                {confScore && (
                                                    <div
                                                        title={`Confidence: ${confScore}`}
                                                        style={{
                                                            width: '8px',
                                                            height: '8px',
                                                            borderRadius: '50%',
                                                            backgroundColor: getConfColor(confScore),
                                                            flexShrink: 0
                                                        }}
                                                    />
                                                )}
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                        {type === 'list' && (
                            <ul style={{ listStyle: 'none' }}>
                                {Array.isArray(data) && data.map((item, i) => (
                                    <li key={i} style={{ marginBottom: '0.25rem', borderBottom: '1px solid #222', paddingBottom: '0.25rem' }}>
                                        {item}
                                    </li>
                                ))}
                            </ul>
                        )}
                        {type === 'json' && (
                            <pre style={{ overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
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

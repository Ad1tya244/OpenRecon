import React, { useEffect, useState, useMemo } from 'react'
import ReportCard from './ReportCard'
import AttackSurfaceGraph from './AttackSurfaceGraph'
import IntelligenceReport from './IntelligenceReport'

const CARD_ICONS = {
    dns: '🌐', whois: '📋', ssl: '🔒', headers: '🛡️',
    subdomains: '🗺️', email: '📧', tech: '⚙️', ip: '📡',
    network: '🕸️', dirs: '📂', ports: '🔌', leaks: '🔍',
    files: '📄', historical: '⏳'
}

const MODULE_LABELS = {
    dns: 'DNS', whois: 'WHOIS', ssl: 'SSL', headers: 'HDR',
    subdomains: 'SUB', tech: 'TECH', ports: 'PORT',
    directory_exposure: 'DIR', ip_intelligence: 'IP',
    network_footprint: 'NET', code_leaks: 'LEAK',
    public_files: 'FILE', historical: 'HIST', intelligence: 'INTEL'
}

const ScanProgress = ({ loading }) => {
    const modules = Object.keys(loading)
    const done = modules.filter(k => !loading[k]).length
    const pct = Math.round((done / modules.length) * 100)
    const complete = pct === 100

    return (
        <div style={{
            marginBottom: '1.5rem',
            padding: '0.85rem 1.1rem',
            background: 'var(--bg-glass)',
            border: `1px solid ${complete ? 'rgba(0,255,157,0.25)' : 'var(--border-color)'}`,
            borderRadius: '4px',
            backdropFilter: 'blur(10px)',
            transition: 'border-color 0.5s'
        }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    {complete
                        ? <span style={{ color: 'var(--green)', fontSize: '0.8rem' }}>✓</span>
                        : <span style={{ display: 'inline-block', width: '10px', height: '10px', border: '1.5px solid rgba(0,255,225,0.2)', borderTopColor: 'var(--cyan)', borderRadius: '50%', animation: 'cyber-spin 0.8s linear infinite' }} />
                    }
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: complete ? 'var(--green)' : 'var(--text-dim)', letterSpacing: '0.1em' }}>
                        {complete ? 'SCAN COMPLETE' : 'SCANNING...'}
                    </span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: complete ? 'var(--green)' : 'var(--cyan)' }}>
                    {done}/{modules.length} — {pct}%
                </span>
            </div>

            {/* Progress bar */}
            <div style={{ height: '3px', background: 'rgba(0,255,180,0.08)', borderRadius: '2px', overflow: 'hidden', marginBottom: '0.75rem' }}>
                <div style={{
                    height: '100%',
                    width: `${pct}%`,
                    background: complete
                        ? 'linear-gradient(90deg, var(--green), var(--cyan))'
                        : 'linear-gradient(90deg, var(--cyan), var(--purple))',
                    borderRadius: '2px',
                    transition: 'width 0.5s cubic-bezier(0.4,0,0.2,1)',
                    boxShadow: complete ? '0 0 8px var(--green)' : '0 0 6px var(--cyan)',
                    animation: complete ? 'none' : 'progress-glow 2s ease-in-out infinite'
                }} />
            </div>

            {/* Module pills */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                {modules.map(k => (
                    <span key={k} style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.6rem',
                        padding: '0.15rem 0.45rem',
                        borderRadius: '3px',
                        border: `1px solid ${loading[k] ? 'rgba(0,255,225,0.15)' : 'rgba(0,255,157,0.25)'}`,
                        color: loading[k] ? 'var(--text-dim)' : 'var(--green)',
                        background: loading[k] ? 'transparent' : 'rgba(0,255,157,0.05)',
                        transition: 'all 0.3s',
                        letterSpacing: '0.06em'
                    }}>
                        {MODULE_LABELS[k] || k.toUpperCase()}
                    </span>
                ))}
            </div>
        </div>
    )
}

// Compute quick risk summary from loaded data
const useRiskSummary = (data, loading) => {
    return useMemo(() => {
        const items = []
        const allDone = Object.values(loading).every(v => !v)
        if (!allDone) return { items, score: null }

        let score = 100
        // SSL check
        if (data.ssl && !data.ssl.valid) { items.push({ label: 'SSL Invalid', level: 'high' }); score -= 20 }
        // Security headers
        const h = data.headers?.headers || {}
        const missingHeaders = ['strict-transport-security','content-security-policy','x-frame-options']
            .filter(hdr => !h[hdr] && !h[hdr.toUpperCase()])
        if (missingHeaders.length >= 2) { items.push({ label: `${missingHeaders.length} Headers Missing`, level: 'medium' }); score -= missingHeaders.length * 5 }
        // Open ports
        const portCount = data.ports?.open_ports?.length || 0
        if (portCount >= 5) { items.push({ label: `${portCount} Open Ports`, level: 'medium' }); score -= 10 }
        else if (portCount > 0) { items.push({ label: `${portCount} Open Port${portCount > 1 ? 's' : ''}`, level: 'low' }); score -= 5 }
        // Code leaks
        if (data.code_leaks?.findings?.length > 0) { items.push({ label: 'Code Leaks Found', level: 'high' }); score -= 20 }
        // Exposed dirs
        if (data.directory_exposure?.exposed_directories?.length > 0) { items.push({ label: 'Exposed Directories', level: 'medium' }); score -= 10 }
        // DMARC
        if (data.dns?.email_security && !data.dns.email_security.dmarc.present) { items.push({ label: 'No DMARC', level: 'low' }); score -= 5 }
        if (items.length === 0) items.push({ label: 'No Critical Issues', level: 'ok' })
        return { items, score: Math.max(0, score) }
    }, [data, loading])
}

const RiskSummary = ({ summary, domain }) => {
    if (summary.score === null) return null
    const { score, items } = summary
    const scoreColor = score >= 80 ? 'var(--green)' : score >= 50 ? 'var(--amber)' : 'var(--red)'
    const scoreLabel = score >= 80 ? 'LOW RISK' : score >= 50 ? 'MEDIUM RISK' : 'HIGH RISK'
    return (
        <div className="risk-summary-row" style={{
            marginBottom: '1.5rem',
            padding: '1rem 1.25rem',
            background: 'var(--bg-glass)',
            border: `1px solid ${scoreColor}33`,
            borderRadius: '4px',
            backdropFilter: 'blur(10px)',
            animation: 'fade-in-up 0.5s ease'
        }}>
            {/* Score */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                <div style={{
                    width: '52px', height: '52px',
                    border: `2px solid ${scoreColor}`,
                    borderRadius: '4px',
                    display: 'flex', flexDirection: 'column',
                    alignItems: 'center', justifyContent: 'center',
                    boxShadow: `0 0 12px ${scoreColor}44`,
                    background: `${scoreColor}0d`
                }}>
                    <span style={{ fontFamily: 'var(--font-display)', fontSize: '1.2rem', fontWeight: '700', color: scoreColor, lineHeight: 1 }}>{score}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.5rem', color: scoreColor, letterSpacing: '0.05em', marginTop: '2px' }}>/ 100</span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.58rem', color: scoreColor, marginTop: '0.35rem', letterSpacing: '0.1em' }}>{scoreLabel}</span>
            </div>
            {/* Divider */}
            <div className="risk-summary-divider" />
            {/* Flags */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', flex: 1 }}>
                {items.map((item, i) => {
                    const c = item.level === 'high' ? 'var(--red)' : item.level === 'medium' ? 'var(--amber)' : item.level === 'low' ? '#60a5fa' : 'var(--green)'
                    return (
                        <span key={i} style={{
                            fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
                            padding: '0.2rem 0.6rem',
                            border: `1px solid ${c}44`,
                            borderRadius: '3px',
                            color: c,
                            background: `${c}0d`
                        }}>
                            {item.level === 'high' ? '▲ ' : item.level === 'medium' ? '◆ ' : item.level === 'ok' ? '✓ ' : '● '}
                            {item.label}
                        </span>
                    )
                })}
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-dim)', marginLeft: 'auto', flexShrink: 0 }}>RISK ASSESSMENT</span>
        </div>
    )
}

const Dashboard = ({ domain, onReset, showToast }) => {
    const handleDownloadReport = async () => {
        showToast?.('Generating PDF report...', 'info')
        try {
            const response = await fetch('/scan/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ...data, target: domain })
            })
            if (!response.ok) throw new Error('Report generation failed')
            const blob = await response.blob()
            const url = window.URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `OpenRecon_Report_${domain}.pdf`
            document.body.appendChild(a)
            a.click()
            a.remove()
            showToast?.('Report downloaded successfully!', 'success')
        } catch (e) {
            console.error('Download failed:', e)
            showToast?.('Failed to generate report. Please try again.', 'error')
        }
    }

    const [viewGraph, setViewGraph] = useState(false)
    const [viewIntel, setViewIntel] = useState(false)
    const [intelFilter, setIntelFilter] = useState(null)

    const [data, setData] = useState({
        dns: null, whois: null, ssl: null, headers: null, subdomains: null,
        tech: null, ports: null, directory_exposure: null, ip_intelligence: null,
        network_footprint: null, code_leaks: null, public_files: null,
        historical: null, intelligence: null
    })
    const [loading, setLoading] = useState({
        dns: true, whois: true, ssl: true, headers: true, subdomains: true,
        tech: true, ports: true, directory_exposure: true, ip_intelligence: true,
        network_footprint: true, code_leaks: true, public_files: true,
        historical: true, intelligence: true
    })

    const riskSummary = useRiskSummary(data, loading)

    const allLoaded = Object.values(loading).every(v => !v);
    useEffect(() => {
        if (allLoaded) {
            showToast?.('Scan complete', 'success');
        }
    }, [allLoaded, showToast]);

    // Session-level cache so the same domain isn't re-fetched on re-render
    const cacheRef = React.useRef(new Map())
    const [retries, setRetries] = React.useState({})

    const ENDPOINTS = React.useMemo(() => [
        ['dns', 'dns'], ['whois', 'whois'], ['ssl', 'ssl'], ['headers', 'headers'],
        ['subdomains', 'subdomains'], ['tech', 'tech'], ['ports', 'ports'],
        ['directory-exposure', 'directory_exposure'], ['ip-intelligence', 'ip_intelligence'],
        ['network-footprint', 'network_footprint'], ['code-leaks', 'code_leaks'],
        ['public-files', 'public_files'], ['historical', 'historical'], ['intelligence', 'intelligence']
    ], [])

    const fetchModule = React.useCallback(async (endpoint, key, domain, signal, forceRefresh = false) => {
        const cacheKey = `${domain}:${key}`
        if (!forceRefresh && cacheRef.current.has(cacheKey)) {
            const cached = cacheRef.current.get(cacheKey)
            setData(prev => ({ ...prev, [key]: cached }))
            setLoading(prev => ({ ...prev, [key]: false }))
            return
        }
        try {
            const response = await fetch(`/scan/${endpoint}?domain=${domain}`, { signal })
            if (!response.ok) throw new Error(`HTTP ${response.status}`)
            const result = await response.json()
            cacheRef.current.set(cacheKey, result)
            setData(prev => ({ ...prev, [key]: result }))
        } catch (e) {
            if (e.name === 'AbortError') return // Request cancelled, ignore
            console.error(`Failed to fetch ${key}:`, e.message)
            setData(prev => ({ ...prev, [key]: { error: e.message || 'Failed to fetch' } }))
        } finally {
            setLoading(prev => ({ ...prev, [key]: false }))
        }
    }, [])

    useEffect(() => {
        if (!domain) return

        const controller = new AbortController()

        setRetries({})
        setLoading({
            dns: true, whois: true, ssl: true, headers: true, subdomains: true,
            tech: true, ports: true, directory_exposure: true, ip_intelligence: true,
            network_footprint: true, code_leaks: true, public_files: true, historical: true, intelligence: true
        })
        setData({
            dns: null, whois: null, ssl: null, headers: null, subdomains: null,
            tech: null, ports: null, directory_exposure: null, ip_intelligence: null,
            network_footprint: null, code_leaks: null, public_files: null, historical: null, intelligence: null
        })

        ENDPOINTS.forEach(([endpoint, key]) => fetchModule(endpoint, key, domain, controller.signal))

        return () => controller.abort() // Cancel all in-flight requests on domain change
    }, [domain, ENDPOINTS, fetchModule])

    const handleRetry = React.useCallback((endpoint, key) => {
        setLoading(prev => ({ ...prev, [key]: true }))
        setData(prev => ({ ...prev, [key]: null }))
        setRetries(prev => ({ ...prev, [key]: (prev[key] || 0) + 1 }))
        fetchModule(endpoint, key, domain, new AbortController().signal, true) // force-bypass cache
    }, [domain, fetchModule])

    if (viewGraph) return <AttackSurfaceGraph domain={domain} onBack={() => setViewGraph(false)} />
    if (viewIntel) return (
        <IntelligenceReport
            domain={domain}
            initialData={intelFilter ? null : data.intelligence}
            filter={intelFilter}
            onBack={() => { setViewIntel(false); setIntelFilter(null) }}
        />
    )

    return (
        <div className="dashboard-grid">
            {/* Dashboard header */}
            <div style={{
                marginBottom: '1.5rem',
                padding: '1.25rem 1.5rem',
                background: 'var(--bg-glass)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                backdropFilter: 'blur(10px)',
                position: 'relative', overflow: 'hidden'
            }}>
                {/* Glow accent line */}
                <div style={{
                    position: 'absolute', top: 0, left: 0, right: 0, height: '2px',
                    background: 'linear-gradient(90deg, transparent, var(--cyan), var(--green), transparent)'
                }} />

                <div className="dashboard-header-container">
                    <div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)', letterSpacing: '0.15em', marginBottom: '0.3rem' }}>
                            ACTIVE TARGET
                        </div>
                        <h2 style={{
                            fontFamily: 'var(--font-display)', fontSize: '1.6rem',
                            letterSpacing: '0.05em', margin: 0
                        }}>
                            <span className="text-gradient">{domain}</span>
                        </h2>
                        <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                            OSINT INTELLIGENCE REPORT
                        </p>
                    </div>

                    <div className="btn-group" style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
                        <button onClick={() => setViewIntel(true)} className="btn btn-emerald">
                            ◈ Intel Report
                        </button>
                        <button onClick={() => { setIntelFilter('Attack Vector'); setViewIntel(true) }} className="btn btn-danger">
                            ⚡ Attack Paths
                        </button>
                        <button onClick={() => setViewGraph(true)} className="btn btn-indigo">
                            ⬡ Surface Graph
                        </button>
                        <button onClick={handleDownloadReport} className="btn btn-primary">
                            ↓ PDF Report
                        </button>
                        <button onClick={onReset} className="btn btn-outline">
                            ↺ New Target
                        </button>
                    </div>
                </div>
            </div>

            {/* Progress bar */}
            <ScanProgress loading={loading} />

            {/* Risk summary (appears when all scans complete) */}
            <RiskSummary summary={riskSummary} domain={domain} />

            {/* Cards grid */}
            <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', alignItems: 'start' }}>
                <ReportCard
                    title="DNS Records" icon={CARD_ICONS.dns}
                    loading={loading.dns}
                    data={data.dns ? (
                        Object.entries(data.dns).reduce((acc, [type, records]) => {
                            if (records && records.length > 0 && type !== 'email_security' && type !== 'flags')
                                acc[type] = Array.isArray(records) ? records.join(', ') : records
                            return acc
                        }, {})
                    ) : null}
                    type="kv"
                    onRetry={() => handleRetry('dns', 'dns')}
                />
                <ReportCard
                    title="Domain Registration" icon={CARD_ICONS.whois}
                    loading={loading.whois}
                    data={data.whois ? {
                        Registrar: data.whois.registrar,
                        Created: (data.whois.creation_date_iso || data.whois.creation_date) ? new Date(data.whois.creation_date_iso || data.whois.creation_date).toLocaleDateString('en-GB') : 'Unknown',
                        Age: data.whois.age_days ? `${data.whois.age_days} days` : 'Unknown',
                        Expires: data.whois.expiration_date ? new Date(data.whois.expiration_date).toLocaleDateString('en-GB') : 'Unknown',
                        Flags: data.whois.flags?.length > 0 ? data.whois.flags.join(', ') : 'None'
                    } : null}
                    type="kv"
                    onRetry={() => handleRetry('whois', 'whois')}
                />
                <ReportCard
                    title="SSL/TLS Security" icon={CARD_ICONS.ssl}
                    loading={loading.ssl}
                    data={data.ssl ? {
                        Valid: data.ssl.valid ? '✅ Yes' : '❌ No',
                        Issuer: data.ssl.issuer?.organizationName || data.ssl.issuer?.commonName || 'Unknown',
                        'Valid From': data.ssl.valid_from ? new Date(data.ssl.valid_from).toLocaleDateString('en-GB') : 'Unknown',
                        'Valid Until': data.ssl.valid_until ? new Date(data.ssl.valid_until).toLocaleDateString('en-GB') : 'Unknown',
                        'Serial Number': data.ssl.serial_number,
                        'Signature Algo': data.ssl.signature_algorithm
                    } : null}
                    type="kv"
                    onRetry={() => handleRetry('ssl', 'ssl')}
                />
                <ReportCard
                    title="Security Headers" icon={CARD_ICONS.headers}
                    loading={loading.headers}
                    data={data.headers && !data.headers.error ? {
                        'Server': data.headers.server || 'Unknown',
                        'Strict-Transport-Security': data.headers.headers?.['strict-transport-security'] || data.headers.headers?.['Strict-Transport-Security'] ? '✅ Present' : '❌ Missing',
                        'Content-Security-Policy': data.headers.headers?.['content-security-policy'] || data.headers.headers?.['Content-Security-Policy'] ? '✅ Present' : '❌ Missing',
                        'X-Frame-Options': data.headers.headers?.['x-frame-options'] || data.headers.headers?.['X-Frame-Options'] ? '✅ Present' : '❌ Missing',
                        'X-Content-Type-Options': data.headers.headers?.['x-content-type-options'] || data.headers.headers?.['X-Content-Type-Options'] ? '✅ Present' : '❌ Missing',
                        'Referrer-Policy': data.headers.headers?.['referrer-policy'] || data.headers.headers?.['Referrer-Policy'] ? '✅ Present' : '❌ Missing',
                        'Permissions-Policy': data.headers.headers?.['permissions-policy'] || data.headers.headers?.['Permissions-Policy'] ? '✅ Present' : '❌ Missing'
                    } : (data.headers?.error ? { Error: data.headers.error } : null)}
                    type="kv"
                    onRetry={() => handleRetry('headers', 'headers')}
                />
                <ReportCard
                    title={`Subdomains${data.subdomains && (data.subdomains.subdomains?.length || (Array.isArray(data.subdomains) ? data.subdomains.length : 0)) ? ` [${data.subdomains.subdomains?.length || data.subdomains.length} Found]` : ''}`}
                    icon={CARD_ICONS.subdomains}
                    loading={loading.subdomains}
                    data={data.subdomains ? (
                        data.subdomains.subdomains ? (
                            data.subdomains.subdomains.length > 0
                                ? data.subdomains.subdomains.map(s => s.flags?.length > 0 ? `${s.hostname} [${s.flags.join(', ')}]` : s.hostname)
                                : ['No subdomains found.']
                        ) : (data.subdomains.length > 0 ? data.subdomains : ['No subdomains found.'])
                    ) : ['Fetching...']}
                    type="list"
                    onRetry={() => handleRetry('subdomains', 'subdomains')}
                />
                <ReportCard
                    title="Email Security (DMARC/SPF)" icon={CARD_ICONS.email}
                    loading={loading.dns}
                    data={data.dns?.email_security ? {
                        'SPF Record': data.dns.email_security.spf.present ? '✅ Present' : '❌ Missing',
                        'SPF Status': data.dns.email_security.spf.status,
                        'DMARC Record': data.dns.email_security.dmarc.present ? '✅ Present' : '❌ Missing',
                        'DMARC Policy': data.dns.email_security.dmarc.policy,
                        'DKIM Hint': data.dns.email_security.dkim_dns_check?._domainkey_exists ? '✅ Present' : '❓ Not Found (Passive)'
                    } : null}
                    type="kv"
                />
                <ReportCard
                    title="Technology Stack" icon={CARD_ICONS.tech}
                    loading={loading.tech}
                    data={data.tech && !data.tech.error ? {
                        Server: data.tech.server || 'Unknown',
                        Frameworks: data.tech.frameworks?.join(', ') || 'None Detected',
                        Proxies: data.tech.proxies?.join(', ') || 'None',
                        'Aggregated OS': data.tech.os_hint || 'Unknown'
                    } : (data.tech?.error ? { Error: data.tech.error } : null)}
                    type="kv"
                    onRetry={() => handleRetry('tech', 'tech')}
                />
                <ReportCard
                    title="Infrastructure & Hosting" icon={CARD_ICONS.ip}
                    loading={loading.ip_intelligence}
                    data={data.ip_intelligence?.ips?.length > 0 ? {
                        'Primary IP': data.ip_intelligence.ips[0].ip,
                        Location: data.ip_intelligence.ips[0].location,
                        'ISP / Org': data.ip_intelligence.ips[0].isp,
                        ASN: data.ip_intelligence.ips[0].asn,
                        'Hosting Type': data.ip_intelligence.ips[0].hosting_type,
                        'Risk Flags': data.ip_intelligence.flags?.join(', ') || 'None'
                    } : { Status: 'No IP intelligence data found' }}
                    type="kv"
                    onRetry={() => handleRetry('ip-intelligence', 'ip_intelligence')}
                />
                <ReportCard
                    title="Network Footprint" icon={CARD_ICONS.network}
                    loading={loading.network_footprint}
                    data={data.network_footprint && !data.network_footprint.error ? {
                        'Total Unique IPs': data.network_footprint.summary?.unique_ips,
                        'Unique ASNs': data.network_footprint.summary?.unique_asns,
                        'Hosting Providers': data.network_footprint.summary?.hosting_providers?.join(', ') || 'None',
                        'CDNs Detected': data.network_footprint.network_graph?.cdns?.join(', ') || 'None',
                        'Cloud IPs': data.network_footprint.exposure_analysis?.cloud_ips,
                        'Unprotected IPs': data.network_footprint.exposure_analysis?.unprotected_ips > 0
                            ? `${data.network_footprint.exposure_analysis.unprotected_ips} ${data.network_footprint.exposure_analysis.unprotected_ips_list ? `(${data.network_footprint.exposure_analysis.unprotected_ips_list.join(', ')})` : ''}` : 0
                    } : (data.network_footprint?.error ? { Error: data.network_footprint.error } : null)}
                    type="kv"
                    onRetry={() => handleRetry('network-footprint', 'network_footprint')}
                />
                <ReportCard
                    title="Exposed Directories" icon={CARD_ICONS.dirs}
                    loading={loading.directory_exposure}
                    data={data.directory_exposure?.exposed_directories?.length > 0
                        ? data.directory_exposure.exposed_directories
                        : ['No sensitive directories exposed.']}
                    type="list"
                    onRetry={() => handleRetry('directory-exposure', 'directory_exposure')}
                />
                <ReportCard
                    title="Open Ports" icon={CARD_ICONS.ports}
                    loading={loading.ports}
                    data={data.ports?.open_ports ? (
                        data.ports.open_ports.length > 0
                            ? data.ports.open_ports.sort((a, b) => a.port - b.port).map(p => `${p.port}/${p.service}`)
                            : ['No open ports found (Top 10 scanned)']
                    ) : null}
                    type="list"
                    onRetry={() => handleRetry('ports', 'ports')}
                />
                <ReportCard
                    title="Code Leak Intelligence" icon={CARD_ICONS.leaks}
                    loading={loading.code_leaks}
                    data={data.code_leaks ? (
                        data.code_leaks.findings?.length > 0
                            ? data.code_leaks.findings.map(f => `${f.repository} (${f.url})`)
                            : [data.code_leaks.message || 'No leaks found.']
                    ) : null}
                    type="list"
                    onRetry={() => handleRetry('code-leaks', 'code_leaks')}
                />
                <ReportCard
                    title="Public Files" icon={CARD_ICONS.files}
                    loading={loading.public_files}
                    data={data.public_files ? {
                        'Found Files': data.public_files.found?.join(', ') || 'None',
                        Insights: data.public_files.interesting_findings?.join(', ') || 'None'
                    } : null}
                    type="kv"
                    onRetry={() => handleRetry('public-files', 'public_files')}
                />
                <ReportCard
                    title="Historical Intelligence" icon={CARD_ICONS.historical}
                    loading={loading.historical}
                    data={data.historical ? {
                        'Past Tech Stack': data.historical.tech_stack_history?.join(', ') || 'None',
                        'Interesting Old Files': data.historical.interesting_files?.slice(0, 5).join(', ') || 'None',
                        'Wayback Endpoints': `${data.historical.historical_endpoints?.length || 0} unique paths found`
                    } : null}
                    type="kv"
                    onRetry={() => handleRetry('historical', 'historical')}
                />
            </div>
        </div>
    )
}

export default Dashboard

import React, { useEffect, useState } from 'react'
import ReportCard from './ReportCard'
import AttackSurfaceGraph from './AttackSurfaceGraph'
import IntelligenceReport from './IntelligenceReport'

const CARD_ICONS = {
    dns: '🌐', whois: '📋', ssl: '🔒', headers: '🛡️',
    subdomains: '🗺️', email: '📧', tech: '⚙️', ip: '📡',
    network: '🕸️', dirs: '📂', ports: '🔌', leaks: '🔍',
    files: '📄', historical: '⏳'
}

const ScanProgress = ({ loading }) => {
    const modules = Object.keys(loading)
    const done = modules.filter(k => !loading[k]).length
    const pct = Math.round((done / modules.length) * 100)

    return (
        <div style={{
            marginBottom: '1.5rem',
            padding: '0.75rem 1rem',
            background: 'var(--bg-glass)',
            border: '1px solid var(--border-color)',
            borderRadius: '4px',
            backdropFilter: 'blur(10px)'
        }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-dim)', letterSpacing: '0.1em' }}>
                    SCAN PROGRESS
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: pct === 100 ? 'var(--green)' : 'var(--cyan)' }}>
                    {done}/{modules.length} MODULES — {pct}%
                </span>
            </div>
            <div style={{ height: '4px', background: 'rgba(0,255,180,0.1)', borderRadius: '2px', overflow: 'hidden' }}>
                <div style={{
                    height: '100%',
                    width: `${pct}%`,
                    background: pct === 100
                        ? 'linear-gradient(90deg, var(--green), var(--cyan))'
                        : 'linear-gradient(90deg, var(--cyan), var(--purple))',
                    borderRadius: '2px',
                    transition: 'width 0.4s ease',
                    boxShadow: pct === 100 ? '0 0 8px var(--green)' : '0 0 8px var(--cyan)'
                }} />
            </div>
        </div>
    )
}

const Dashboard = ({ domain, onReset }) => {
    const handleDownloadReport = async () => {
        try {
            const response = await fetch('http://localhost:8000/scan/report', {
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
        } catch (e) {
            console.error('Download failed:', e)
            alert('Failed to generate report. Please try again.')
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

    useEffect(() => {
        if (!domain) return
        const fetchData = async (endpoint, key) => {
            try {
                const response = await fetch(`http://localhost:8000/scan/${endpoint}?domain=${domain}`)
                const result = await response.json()
                setData(prev => ({ ...prev, [key]: result }))
            } catch (e) {
                console.error(`Failed to fetch ${key}`, e)
                setData(prev => ({ ...prev, [key]: { error: 'Failed to fetch' } }))
            } finally {
                setLoading(prev => ({ ...prev, [key]: false }))
            }
        }
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
        fetchData('dns', 'dns')
        fetchData('whois', 'whois')
        fetchData('ssl', 'ssl')
        fetchData('headers', 'headers')
        fetchData('subdomains', 'subdomains')
        fetchData('tech', 'tech')
        fetchData('ports', 'ports')
        fetchData('directory-exposure', 'directory_exposure')
        fetchData('ip-intelligence', 'ip_intelligence')
        fetchData('network-footprint', 'network_footprint')
        fetchData('code-leaks', 'code_leaks')
        fetchData('public-files', 'public_files')
        fetchData('historical', 'historical')
        fetchData('intelligence', 'intelligence')
    }, [domain])

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

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
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

                    <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
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

            {/* Cards grid */}
            <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
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
                />
                <ReportCard
                    title="Exposed Directories" icon={CARD_ICONS.dirs}
                    loading={loading.directory_exposure}
                    data={data.directory_exposure?.exposed_directories?.length > 0
                        ? data.directory_exposure.exposed_directories
                        : ['No sensitive directories exposed.']}
                    type="list"
                />
                <ReportCard
                    title="Open Ports" icon={CARD_ICONS.ports}
                    loading={loading.ports}
                    data={data.ports?.open_ports ? (
                        data.ports.open_ports.length > 0
                            ? data.ports.open_ports.sort((a, b) => a.port - b.port).map(p => `${p.port}/${p.service}`)
                            : ['No open ports found (Top 10 scanned)']
                    ) : ['Scanning...']}
                    type="list"
                />
                <ReportCard
                    title="Code Leak Intelligence" icon={CARD_ICONS.leaks}
                    loading={loading.code_leaks}
                    data={data.code_leaks ? (
                        data.code_leaks.findings?.length > 0
                            ? data.code_leaks.findings.map(f => `${f.repository} (${f.url})`)
                            : [data.code_leaks.message || 'No leaks found.']
                    ) : ['Checking GitHub...']}
                    type="list"
                />
                <ReportCard
                    title="Public Files" icon={CARD_ICONS.files}
                    loading={loading.public_files}
                    data={data.public_files ? {
                        'Found Files': data.public_files.found?.join(', ') || 'None',
                        Insights: data.public_files.interesting_findings?.join(', ') || 'None'
                    } : null}
                    type="kv"
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
                />
            </div>
        </div>
    )
}

export default Dashboard

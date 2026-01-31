import React, { useEffect, useState } from 'react'
import ReportCard from './ReportCard'

import AttackSurfaceGraph from './AttackSurfaceGraph'
import IntelligenceReport from './IntelligenceReport'

const Dashboard = ({ domain, onReset }) => {
    const handleDownloadReport = async () => {
        try {
            const response = await fetch('http://localhost:8000/scan/report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ...data, target: domain })
            });

            if (!response.ok) throw new Error("Report generation failed");

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `OpenRecon_Report_${domain}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
        } catch (e) {
            console.error("Download failed:", e);
            alert("Failed to generate report. Please try again.");
        }
    }

    const [viewGraph, setViewGraph] = useState(false)
    const [viewIntel, setViewIntel] = useState(false)
    const [data, setData] = useState({
        // ... (existing)
        dns: null,
        whois: null,
        ssl: null,
        headers: null,
        subdomains: null,
        tech: null,
        ports: null,
        directory_exposure: null,
        ip_intelligence: null,
        network_footprint: null,
        code_leaks: null,
        public_files: null,
        historical: null,
        intelligence: null
    })

    const [loading, setLoading] = useState({
        dns: true,
        whois: true,
        ssl: true,
        headers: true,
        subdomains: true,
        tech: true,
        ports: true,
        directory_exposure: true,
        ip_intelligence: true,
        network_footprint: true,
        code_leaks: true,
        public_files: true,
        historical: true,
        intelligence: true
    })

    useEffect(() => {
        if (!domain) return

        const fetchData = async (endpoint, key) => {
            try {
                // Assume backend runs on port 8000
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

        // Reset state
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

        // Parallel fetch
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

    if (viewGraph) {
        return <AttackSurfaceGraph domain={domain} onBack={() => setViewGraph(false)} />
    }

    if (viewIntel) {
        return <IntelligenceReport domain={domain} initialData={data.intelligence} onBack={() => setViewIntel(false)} />
    }

    return (
        <div className="dashboard-grid">
            <div style={{ marginBottom: '2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <h2 style={{ fontSize: '1.5rem', margin: 0 }}>Target: <span className="text-gradient">{domain}</span></h2>
                    <p style={{ color: 'var(--text-dim)', marginTop: '0.25rem' }}>Intelligence Report</p>
                </div>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
                    <button
                        onClick={() => setViewIntel(true)}
                        className="btn btn-emerald"
                    >
                        View Intelligence Report
                    </button>
                    <button
                        onClick={() => setViewGraph(true)}
                        className="btn btn-indigo"
                    >
                        View Attack Surface Graph
                    </button>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        <button
                            onClick={onReset}
                            className="btn"
                            style={{ backgroundColor: '#4b5563', color: 'white' }}
                        >
                            Check New Domain
                        </button>
                        <button
                            onClick={handleDownloadReport}
                            className="btn btn-primary"
                        >
                            Download PDF Report
                        </button>
                    </div>
                </div>
            </div>

            <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
                {/* DNS Recon */}
                <ReportCard
                    title="DNS Records"
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

                {/* Whois */}
                <ReportCard
                    title="Domain Registration"
                    loading={loading.whois}
                    data={data.whois ? {
                        Registrar: data.whois.registrar,
                        // Helper function definition at the top of component logic or inline usage?
                        // Since I can't easily insert a helper function inside the component body with replace_file (it's fragmented), I'll just change the calls to use 'en-GB' directly for now.

                        Created: (data.whois.creation_date_iso || data.whois.creation_date) ? new Date(data.whois.creation_date_iso || data.whois.creation_date).toLocaleDateString('en-GB') : 'Unknown',
                        Age: data.whois.age_days ? `${data.whois.age_days} days` : 'Unknown',
                        Expires: data.whois.expiration_date ? new Date(data.whois.expiration_date).toLocaleDateString('en-GB') : 'Unknown',
                        Flags: data.whois.flags?.length > 0 ? data.whois.flags.join(", ") : "None"
                    } : null}
                    type="kv"
                />

                {/* SSL */}
                <ReportCard
                    title="SSL/TLS Security"
                    loading={loading.ssl}
                    data={data.ssl ? {
                        Valid: data.ssl.valid ? 'Yes' : 'No',
                        Issuer: data.ssl.issuer?.organizationName || data.ssl.issuer?.commonName || 'Unknown',
                        "Valid From": data.ssl.valid_from ? new Date(data.ssl.valid_from).toLocaleDateString('en-GB') : 'Unknown',
                        "Valid Until": data.ssl.valid_until ? new Date(data.ssl.valid_until).toLocaleDateString('en-GB') : 'Unknown',
                        "Serial Number": data.ssl.serial_number,
                        "Signature Algo": data.ssl.signature_algorithm
                    } : null}
                    type="kv"
                />

                {/* Headers */}
                <ReportCard
                    title="Security Headers"
                    loading={loading.headers}
                    data={data.headers && !data.headers.error ? (
                        {
                            "Server": data.headers.server || "Unknown",
                            "Strict-Transport-Security": data.headers.headers?.["strict-transport-security"] || data.headers.headers?.["Strict-Transport-Security"] ? "✅ Present" : "❌ Missing",
                            "Content-Security-Policy": data.headers.headers?.["content-security-policy"] || data.headers.headers?.["Content-Security-Policy"] ? "✅ Present" : "❌ Missing",
                            "X-Frame-Options": data.headers.headers?.["x-frame-options"] || data.headers.headers?.["X-Frame-Options"] ? "✅ Present" : "❌ Missing",
                            "X-Content-Type-Options": data.headers.headers?.["x-content-type-options"] || data.headers.headers?.["X-Content-Type-Options"] ? "✅ Present" : "❌ Missing",
                            "Referrer-Policy": data.headers.headers?.["referrer-policy"] || data.headers.headers?.["Referrer-Policy"] ? "✅ Present" : "❌ Missing",
                            "Permissions-Policy": data.headers.headers?.["permissions-policy"] || data.headers.headers?.["Permissions-Policy"] ? "✅ Present" : "❌ Missing"
                        }
                    ) : (data.headers?.error ? { "Error": data.headers.error } : null)}
                    type="kv"
                />

                {/* Subdomains */}
                <ReportCard
                    title={`Subdomains (Passive)${data.subdomains && (data.subdomains.subdomains?.length || (Array.isArray(data.subdomains) ? data.subdomains.length : 0)) ? ` - ${data.subdomains.subdomains?.length || data.subdomains.length} Found` : ''}`}
                    loading={loading.subdomains}
                    data={data.subdomains ? (
                        data.subdomains.subdomains ? (
                            data.subdomains.subdomains.length > 0 ?
                                data.subdomains.subdomains.map(s => s.flags && s.flags.length > 0 ? `${s.hostname} [${s.flags.join(', ')}]` : s.hostname)
                                : ["No subdomains found."]
                        ) : (
                            data.subdomains.length > 0 ? data.subdomains : ["No subdomains found."]
                        )
                    ) : ["Fetching..."]}
                    type="list"
                />

                {/* Email Security */}
                <ReportCard
                    title="Email Security (DMARC/SPF)"
                    loading={loading.dns}
                    data={data.dns?.email_security ? {
                        "SPF Record": data.dns.email_security.spf.present ? "✅ Present" : "❌ Missing",
                        "SPF Status": data.dns.email_security.spf.status,
                        "DMARC Record": data.dns.email_security.dmarc.present ? "✅ Present" : "❌ Missing",
                        "DMARC Policy": data.dns.email_security.dmarc.policy,
                        "DKIM Hint": data.dns.email_security.dkim_dns_check?._domainkey_exists ? "✅ Present" : "❓ Not Found (Passive)"
                    } : null}
                    type="kv"
                />

                {/* Tech Stack */}
                <ReportCard
                    title="Technology Stack"
                    loading={loading.tech}
                    data={data.tech && !data.tech.error ? {
                        "Server": data.tech.server || "Unknown",
                        "Frameworks": data.tech.frameworks?.join(", ") || "None Detected",
                        "Proxies": data.tech.proxies?.join(", ") || "None",
                        "Aggregated OS": data.tech.os_hint || "Unknown"
                    } : (data.tech?.error ? { "Error": data.tech.error } : null)}
                    type="kv"
                />

                {/* Infrastructure / IP Intelligence */}
                <ReportCard
                    title="Infrastructure & Hosting"
                    loading={loading.ip_intelligence}
                    data={data.ip_intelligence && data.ip_intelligence.ips && data.ip_intelligence.ips.length > 0 ? {
                        "Primary IP": data.ip_intelligence.ips[0].ip,
                        "Location": data.ip_intelligence.ips[0].location,
                        "ISP / Org": data.ip_intelligence.ips[0].isp,
                        "ASN": data.ip_intelligence.ips[0].asn,
                        "Hosting Type": data.ip_intelligence.ips[0].hosting_type,
                        "Risk Flags": data.ip_intelligence.flags?.join(", ") || "None"
                    } : { "Status": "No IP intelligence data found" }}
                    type="kv"
                />

                <ReportCard
                    title="Network Footprint"
                    loading={loading.network_footprint}
                    data={data.network_footprint && !data.network_footprint.error ? {
                        "Total Unique IPs": data.network_footprint.summary?.unique_ips,
                        "Unique ASNs": data.network_footprint.summary?.unique_asns,
                        "Hosting Providers": data.network_footprint.summary?.hosting_providers?.join(", ") || "None",
                        "CDNs Detected": data.network_footprint.network_graph?.cdns?.join(", ") || "None",
                        "Cloud IPs": data.network_footprint.exposure_analysis?.cloud_ips,
                        "Unprotected IPs": data.network_footprint.exposure_analysis?.unprotected_ips > 0
                            ? `${data.network_footprint.exposure_analysis.unprotected_ips} ${data.network_footprint.exposure_analysis.unprotected_ips_list ? `(${data.network_footprint.exposure_analysis.unprotected_ips_list.join(', ')})` : ''}`
                            : 0
                    } : (data.network_footprint?.error ? { "Error": data.network_footprint.error } : null)}
                    type="kv"
                />

                {/* Directory Exposure */}
                <ReportCard
                    title="Exposed Directories"
                    loading={loading.directory_exposure}
                    data={data.directory_exposure?.exposed_directories && data.directory_exposure.exposed_directories.length > 0 ?
                        data.directory_exposure.exposed_directories : ["No sensitive directories exposed."]}
                    type="list"
                />

                {/* Open Ports */}
                <ReportCard
                    title="Open Ports"
                    loading={loading.ports}
                    data={data.ports && data.ports.open_ports ? (
                        data.ports.open_ports.length > 0 ?
                            data.ports.open_ports.sort((a, b) => a.port - b.port).map(p => `${p.port}/${p.service}`)
                            : ["No open ports found (Top 10 scanned)"]
                    ) : ["Scanning..."]}
                    type="list"
                />

                {/* Code Leaks */}
                <ReportCard
                    title="Code Leak Intelligence"
                    loading={loading.code_leaks}
                    data={data.code_leaks ? (
                        data.code_leaks.findings && data.code_leaks.findings.length > 0 ?
                            data.code_leaks.findings.map(f => `${f.repository} (${f.url})`)
                            : (data.code_leaks.message ? [data.code_leaks.message] : ["No leaks found."])
                    ) : ["Checking GitHub..."]}
                    type="list"
                />

                {/* Public Files */}
                <ReportCard
                    title="Public Files"
                    loading={loading.public_files}
                    data={data.public_files ? {
                        "Found Files": data.public_files.found?.join(", ") || "None",
                        "Insights": data.public_files.interesting_findings?.join(", ") || "None"
                    } : null}
                    type="kv"
                />

                {/* Historical Data */}
                <ReportCard
                    title="Historical Intelligence"
                    loading={loading.historical}
                    data={data.historical ? {
                        "Past Tech Stack": data.historical.tech_stack_history?.join(", ") || "None",
                        "Interesting Old Files": data.historical.interesting_files?.slice(0, 5).join(", ") || "None",
                        "Wayback Endpoints": `${data.historical.historical_endpoints?.length || 0} unique paths found`
                    } : null}
                    type="kv"
                />
            </div>
        </div>
    )
}

export default Dashboard

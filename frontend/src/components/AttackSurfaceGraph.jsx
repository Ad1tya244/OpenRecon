import React, { useEffect, useRef, useState } from 'react'

const AttackSurfaceGraph = ({ domain, onBack }) => {
    const [graphData, setGraphData] = useState({ nodes: [], links: [] })
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const svgRef = useRef(null)
    const [nodes, setNodes] = useState([])
    const [links, setLinks] = useState([])
    const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

    useEffect(() => {
        const fetchGraph = async () => {
            try {
                const res = await fetch(`http://localhost:8000/scan/graph?domain=${domain}`)
                const data = await res.json()
                if (!data.nodes) throw new Error("Invalid graph data")

                // Initialize positions
                const clientWidth = svgRef.current ? svgRef.current.clientWidth : 0
                const clientHeight = svgRef.current ? svgRef.current.clientHeight : 0
                const width = clientWidth || 800
                const height = clientHeight || 600
                console.log(`Graph initialized: ${data.nodes.length} nodes, ${data.links.length} links. Dim: ${width}x${height}`)
                setDimensions({ width, height })

                const initializedNodes = data.nodes.map(n => ({
                    ...n,
                    x: Math.random() * width,
                    y: Math.random() * height,
                    vx: 0,
                    vy: 0
                }))

                setGraphData(data)
                setNodes(initializedNodes)
                setLinks(data.links)
                setLoading(false)
            } catch (e) {
                console.error("Graph Error:", e)
                setError(e.message)
                setLoading(false)
            }
        }
        fetchGraph()
    }, [domain])

    const [settled, setSettled] = useState(false)

    // Simple Force Simulation — stops automatically when converged
    useEffect(() => {
        if (loading || nodes.length === 0) return

        let animationFrameId
        let frameCount = 0

        const simulate = () => {
            const width = dimensions.width
            const height = dimensions.height
            const k = 40.0        // Repulsion constant
            const c = 0.05        // Spring constant
            const centerForce = 0.02
            const CONVERGENCE_THRESHOLD = 0.3

            setNodes(prevNodes => {
                const newNodes = prevNodes.map(n => ({ ...n }))
                const nodeMap = new Map(newNodes.map(n => [n.id, n]))

                // Repulsion
                for (let i = 0; i < newNodes.length; i++) {
                    for (let j = i + 1; j < newNodes.length; j++) {
                        const n1 = newNodes[i]
                        const n2 = newNodes[j]
                        const dx = n1.x - n2.x
                        const dy = n1.y - n2.y
                        const dist = Math.sqrt(dx * dx + dy * dy) || 1
                        const force = (k * k) / dist
                        const fx = (dx / dist) * force
                        const fy = (dy / dist) * force
                        n1.vx += fx; n1.vy += fy
                        n2.vx -= fx; n2.vy -= fy
                    }
                }

                // Springs (Links)
                links.forEach(link => {
                    const source = nodeMap.get(link.source)
                    const target = nodeMap.get(link.target)
                    if (source && target) {
                        const dx = target.x - source.x
                        const dy = target.y - source.y
                        const dist = Math.sqrt(dx * dx + dy * dy) || 1
                        const force = (dist - 150) * c
                        const fx = (dx / dist) * force
                        const fy = (dy / dist) * force
                        source.vx += fx; source.vy += fy
                        target.vx -= fx; target.vy -= fy
                    }
                })

                // Center force + damping + apply velocity
                let maxVelocity = 0
                newNodes.forEach(n => {
                    n.vx += (width / 2 - n.x) * centerForce
                    n.vy += (height / 2 - n.y) * centerForce
                    n.vx *= 0.9
                    n.vy *= 0.9
                    n.x += n.vx
                    n.y += n.vy
                    const v = Math.sqrt(n.vx * n.vx + n.vy * n.vy)
                    if (v > maxVelocity) maxVelocity = v
                })

                // Stop simulation when converged
                frameCount++
                if (maxVelocity < CONVERGENCE_THRESHOLD && frameCount > 30) {
                    cancelAnimationFrame(animationFrameId)
                    setSettled(true)
                    return newNodes
                }

                animationFrameId = requestAnimationFrame(simulate)
                return newNodes
            })
        }

        setSettled(false)
        animationFrameId = requestAnimationFrame(simulate)
        return () => cancelAnimationFrame(animationFrameId)
    }, [loading, links, dimensions])

    const getNodeColor = (type) => {
        switch (type) {
            case 'domain': return '#00ff9d'
            case 'subdomain': return '#00ffe1'
            case 'ip': return '#bf80ff'
            case 'technology': return '#ffb700'
            case 'risk': return '#ff003c'
            default: return '#4a6b5f'
        }
    }

    const getNodeGlow = (type) => {
        switch (type) {
            case 'domain': return 'drop-shadow(0 0 6px #00ff9d)'
            case 'subdomain': return 'drop-shadow(0 0 4px #00ffe1)'
            case 'ip': return 'drop-shadow(0 0 4px #bf80ff)'
            case 'technology': return 'drop-shadow(0 0 4px #ffb700)'
            case 'risk': return 'drop-shadow(0 0 6px #ff003c)'
            default: return 'none'
        }
    }

    const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 })
    const [isDragging, setIsDragging] = useState(false)
    const [dragStart, setDragStart] = useState({ x: 0, y: 0 })

    const handleWheel = (e) => {
        e.preventDefault()

        if (e.ctrlKey) {
            // Pinch Zoom
            const zoomFactor = 1 - e.deltaY * 0.005
            const newScale = Math.max(0.1, Math.min(transform.k * zoomFactor, 10))

            const rect = svgRef.current.getBoundingClientRect()
            const mouseX = e.clientX - rect.left
            const mouseY = e.clientY - rect.top

            const newX = mouseX - (mouseX - transform.x) * (newScale / transform.k)
            const newY = mouseY - (mouseY - transform.y) * (newScale / transform.k)

            setTransform({ x: newX, y: newY, k: newScale })
        } else {
            // Trackpad Pan
            setTransform(prev => ({
                ...prev,
                x: prev.x - e.deltaX,
                y: prev.y - e.deltaY
            }))
        }
    }

    const handleMouseDown = (e) => {
        e.preventDefault() // Prevent browser drag
        if (e.button !== 0) return // Only left click
        setIsDragging(true)
        setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y })
    }

    const handleMouseMove = (e) => {
        if (!isDragging) return
        setTransform(prev => ({
            ...prev,
            x: e.clientX - dragStart.x,
            y: e.clientY - dragStart.y
        }))
    }

    const handleMouseUp = () => {
        setIsDragging(false)
    }

    const zoomToCenter = (factor) => {
        const newScale = Math.max(0.1, Math.min(transform.k * factor, 5))
        const centerX = dimensions.width / 2
        const centerY = dimensions.height / 2

        const newX = centerX - (centerX - transform.x) * (newScale / transform.k)
        const newY = centerY - (centerY - transform.y) * (newScale / transform.k)

        setTransform({ x: newX, y: newY, k: newScale })
    }

    const zoomIn = () => zoomToCenter(1.2)
    const zoomOut = () => zoomToCenter(1 / 1.2)
    const resetZoom = () => setTransform({ x: 0, y: 0, k: 1 })

    return (
        <div style={{ height: '100%', display: 'flex', flexDirection: 'column', animation: 'fade-in-up 0.4s ease' }}>
            <div style={{
                marginBottom: '1rem', padding: '1rem 1.25rem',
                background: 'var(--bg-glass)', border: '1px solid var(--border-color)',
                borderRadius: '6px', backdropFilter: 'blur(10px)',
                display: 'flex', alignItems: 'center', gap: '1rem',
                position: 'relative', overflow: 'hidden'
            }}>
                <div style={{
                    position: 'absolute', top: 0, left: 0, right: 0, height: '2px',
                    background: 'linear-gradient(90deg, transparent, var(--purple), var(--cyan), transparent)'
                }} />
                <button onClick={onBack} className="btn btn-outline">← Back</button>
                <div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)', letterSpacing: '0.15em' }}>VISUALIZATION</div>
                    <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1.2rem', margin: 0, letterSpacing: '0.05em' }}>
                        ATTACK SURFACE <span className="text-gradient">GRAPH</span>
                    </h3>
                </div>
            </div>

            <div
                style={{ flex: 1, background: 'rgba(2,6,10,0.95)', border: '1px solid var(--border-color)', borderRadius: '6px', overflow: 'hidden', position: 'relative', minHeight: '500px' }}
                ref={svgRef}
                onWheel={handleWheel}
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
            >
                {/* Legend */}
                <div style={{ position: 'absolute', bottom: '20px', left: '20px', background: 'rgba(0,10,8,0.9)', padding: '12px 14px', borderRadius: '4px', border: '1px solid var(--border-color)', pointerEvents: 'none', zIndex: 10, backdropFilter: 'blur(10px)' }}>
                    <h4 style={{ margin: '0 0 8px 0', fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)', letterSpacing: '0.15em', textTransform: 'uppercase' }}>NODE TYPES</h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        {[['#00ff9d','Domain'],['#00ffe1','Subdomain'],['#bf80ff','IP Address'],['#ffb700','Technology'],['#ff003c','Risk/Vuln']].map(([color, label]) => (
                            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}`, flexShrink: 0 }}></span>
                                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-secondary)' }}>{label}</span>
                            </div>
                        ))}
                    </div>
                </div>


                {/* Controls - Only show when graph is visible */}

                <div style={{ position: 'absolute', bottom: '20px', right: '20px', display: 'flex', flexDirection: 'column', gap: '6px', zIndex: 10 }}>
                    {[{fn: zoomIn, label: '+', title: 'Zoom In'},{fn: zoomOut, label: '−', title: 'Zoom Out'},{fn: resetZoom, label: '⌂', title: 'Reset'}].map(({fn, label, title}) => (
                        <button key={title} onClick={fn} title={title} style={{
                            width: '34px', height: '34px',
                            cursor: 'pointer',
                            background: 'rgba(0,10,8,0.9)',
                            color: 'var(--cyan)',
                            border: '1px solid var(--border-color)',
                            borderRadius: '4px',
                            fontSize: '16px',
                            fontFamily: 'var(--font-mono)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            backdropFilter: 'blur(10px)',
                            transition: 'all 0.2s'
                        }}>{label}</button>
                    ))}
                </div>

                {/* Settled indicator */}
                {settled && !loading && (
                    <div style={{
                        position: 'absolute', top: '12px', left: '50%', transform: 'translateX(-50%)',
                        fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--green)',
                        background: 'rgba(0,10,8,0.85)', padding: '0.25rem 0.7rem',
                        borderRadius: '3px', border: '1px solid rgba(0,255,157,0.2)',
                        pointerEvents: 'none', letterSpacing: '0.1em', zIndex: 10
                    }}>✓ GRAPH STABILIZED</div>
                )}

                {loading && (
                    <div style={{
                        position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
                        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                        zIndex: 20, background: 'rgba(2,4,8,0.85)', backdropFilter: 'blur(4px)'
                    }}>
                        <div style={{ width: '36px', height: '36px', border: '2px solid rgba(0,255,225,0.15)', borderTopColor: 'var(--cyan)', borderRadius: '50%', animation: 'cyber-spin 1s linear infinite', marginBottom: '1rem' }} />
                        <h2 style={{ fontFamily: 'var(--font-display)', color: 'var(--cyan)', fontSize: '1rem', letterSpacing: '0.1em' }}>RENDERING GRAPH...</h2>
                    </div>
                )}
                {error && (
                    <div style={{
                        position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        zIndex: 20
                    }}>
                        <div style={{ color: '#ef4444', fontSize: '1.2rem' }}>Error: {error}</div>
                    </div>
                )}
                {(!loading && !error && nodes.length === 0) && (
                    <div style={{
                        position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        zIndex: 20, color: '#9ca3af', fontSize: '1.1rem'
                    }}>
                        No graph nodes found.
                    </div>
                )}

                {!loading && !error && (
                    <svg width="100%" height="100%" viewBox={`0 0 ${dimensions.width} ${dimensions.height}`} style={{ cursor: isDragging ? 'grabbing' : 'grab' }}>
                        <defs>
                            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="20" refY="3.5" orient="auto">
                                <polygon points="0 0, 10 3.5, 0 7" fill="rgba(0,255,225,0.4)" />
                            </marker>
                        </defs>

                        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
                            {/* Build node map once for O(1) link lookups */}
                            {(() => {
                                const nodeMap = new Map(nodes.map(n => [n.id, n]))
                                return (
                                    <>
                                        {/* Links */}
                                        {links.map((link, i) => {
                                            const source = nodeMap.get(link.source)
                                            const target = nodeMap.get(link.target)
                                            if (!source || !target) return null
                                            return (
                                                <line
                                                    key={i}
                                                    x1={source.x} y1={source.y}
                                                    x2={target.x} y2={target.y}
                                                    stroke="rgba(0,255,180,0.2)"
                                                    strokeWidth={1 / transform.k}
                                                    markerEnd="url(#arrowhead)"
                                                />
                                            )
                                        })}

                                        {/* Nodes */}
                                        {nodes.map((node) => (
                                            <g key={node.id} transform={`translate(${node.x},${node.y})`} style={{ filter: getNodeGlow(node.group) }}>
                                                <circle
                                                    r={(node.group === 'domain' ? 10 : (node.group === 'risk' ? 5 : 7)) / transform.k}
                                                    fill={getNodeColor(node.group)}
                                                    fillOpacity={0.85}
                                                    stroke={getNodeColor(node.group)}
                                                    strokeWidth={1.5 / transform.k}
                                                    strokeOpacity={0.5}
                                                />
                                                <text
                                                    dy={(node.group === 'domain' ? 26 : 18) / transform.k}
                                                    textAnchor="middle"
                                                    fill="rgba(224,255,232,0.8)"
                                                    fontSize={`${10 / transform.k}px`}
                                                    fontFamily="Share Tech Mono, monospace"
                                                >
                                                    {node.label}
                                                </text>
                                                <title>{JSON.stringify(node.meta, null, 2)}</title>
                                            </g>
                                        ))}
                                    </>
                                )
                            })()}
                        </g>
                    </svg>
                )}
            </div>
        </div>
    )
}

export default AttackSurfaceGraph

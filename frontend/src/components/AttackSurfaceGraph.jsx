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

    // Simple Force Simulation
    useEffect(() => {
        if (loading || nodes.length === 0) return

        let animationFrameId

        const simulate = () => {
            const width = dimensions.width
            const height = dimensions.height
            const k = 40.0 // Repulsion constant
            const c = 0.05 // Spring constant
            const centerForce = 0.02

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

                        n1.vx += fx
                        n1.vy += fy
                        n2.vx -= fx
                        n2.vy -= fy
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
                        const force = (dist - 150) * c // Ideal length 150

                        const fx = (dx / dist) * force
                        const fy = (dy / dist) * force

                        source.vx += fx
                        source.vy += fy
                        target.vx -= fx
                        target.vy -= fy
                    }
                })

                // Center Force & Apply Velocity
                newNodes.forEach(n => {
                    const dx = width / 2 - n.x
                    const dy = height / 2 - n.y
                    n.vx += dx * centerForce
                    n.vy += dy * centerForce

                    // Damping
                    n.vx *= 0.9
                    n.vy *= 0.9

                    n.x += n.vx
                    n.y += n.vy
                })

                return newNodes
            })

            animationFrameId = requestAnimationFrame(simulate)
        }

        simulate()

        return () => cancelAnimationFrame(animationFrameId)
    }, [loading, links, dimensions]) // Only re-run if loading changes or critical data changes

    const getNodeColor = (type) => {
        switch (type) {
            case 'domain': return '#4ade80' // Green
            case 'subdomain': return '#60a5fa' // Blue
            case 'ip': return '#f472b6' // Pink
            case 'technology': return '#fbbf24' // Amber
            case 'risk': return '#ef4444' // Red
            default: return '#94a3b8'
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
        <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <div style={{ marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h3 style={{ fontSize: '1.5rem' }}>Attack Surface Graph</h3>
                <button onClick={onBack} className="btn btn-outline">
                    &larr; Back to Report
                </button>
            </div>

            <div
                style={{ flex: 1, background: '#111', borderRadius: '12px', overflow: 'hidden', position: 'relative' }}
                ref={svgRef}
                onWheel={handleWheel}
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
            >
                {/* Legend */}
                <div style={{ position: 'absolute', bottom: '20px', left: '20px', background: 'rgba(0,0,0,0.8)', padding: '12px', borderRadius: '8px', border: '1px solid #333', pointerEvents: 'none', zIndex: 10 }}>
                    <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', color: '#eee' }}>Legend</h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#4ade80' }}></span>
                            <span style={{ fontSize: '12px', color: '#ccc' }}>Domain</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#60a5fa' }}></span>
                            <span style={{ fontSize: '12px', color: '#ccc' }}>Subdomain</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#f472b6' }}></span>
                            <span style={{ fontSize: '12px', color: '#ccc' }}>IP Address</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#fbbf24' }}></span>
                            <span style={{ fontSize: '12px', color: '#ccc' }}>Technology</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#ef4444' }}></span>
                            <span style={{ fontSize: '12px', color: '#ccc' }}>Risk / Vuln</span>
                        </div>
                    </div>
                </div>

                {/* Controls */}
                <div style={{ position: 'absolute', bottom: '20px', right: '20px', display: 'flex', flexDirection: 'column', gap: '8px', zIndex: 10 }}>
                    <button onClick={zoomIn} style={{
                        width: '36px', height: '36px',
                        cursor: 'pointer', background: '#222', color: '#fff',
                        border: '1px solid #444', borderRadius: '8px',
                        fontSize: '18px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                        boxShadow: '0 2px 4px rgba(0,0,0,0.5)'
                    }} title="Zoom In">+</button>
                    <button onClick={zoomOut} style={{
                        width: '36px', height: '36px',
                        cursor: 'pointer', background: '#222', color: '#fff',
                        border: '1px solid #444', borderRadius: '8px',
                        fontSize: '18px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                        boxShadow: '0 2px 4px rgba(0,0,0,0.5)'
                    }} title="Zoom Out">-</button>
                    <button onClick={resetZoom} style={{
                        width: '36px', height: '36px',
                        cursor: 'pointer', background: '#222', color: '#fff',
                        border: '1px solid #444', borderRadius: '8px',
                        fontSize: '14px', fontWeight: 'bold', display: 'flex', alignItems: 'center', justifyContent: 'center',
                        boxShadow: '0 2px 4px rgba(0,0,0,0.5)'
                    }} title="Reset View">R</button>
                </div>

                {loading && (
                    <div style={{
                        position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        zIndex: 20
                    }}>
                        <h2 style={{ color: '#ccc', fontSize: '1.5rem', fontWeight: '500' }}>Rendering Graph...</h2>
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
                                <polygon points="0 0, 10 3.5, 0 7" fill="#555" />
                            </marker>
                        </defs>

                        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
                            {/* Links */}
                            {links.map((link, i) => {
                                const source = nodes.find(n => n.id === link.source)
                                const target = nodes.find(n => n.id === link.target)
                                if (!source || !target) return null
                                return (
                                    <line
                                        key={i}
                                        x1={source.x} y1={source.y}
                                        x2={target.x} y2={target.y}
                                        stroke="#555"
                                        strokeWidth={1 / transform.k} // Keep stroke constant
                                        markerEnd="url(#arrowhead)"
                                    />
                                )
                            })}

                            {/* Nodes */}
                            {nodes.map((node, i) => (
                                <g key={node.id} transform={`translate(${node.x},${node.y})`}>
                                    <circle
                                        r={(node.group === 'domain' ? 10 : (node.group === 'risk' ? 4 : 6)) / transform.k} // Keep size somewhat constant or zoomable
                                        fill={getNodeColor(node.group)}
                                        stroke="#fff"
                                        strokeWidth={1 / transform.k}
                                    />
                                    <text
                                        dy={(node.group === 'domain' ? 25 : 15) / transform.k}
                                        textAnchor="middle"
                                        fill="#ccc"
                                        fontSize={`${10 / transform.k}px`} // Scale font invert to zoom
                                    >
                                        {node.label}
                                    </text>
                                    <title>{JSON.stringify(node.meta, null, 2)}</title>
                                </g>
                            ))}
                        </g>
                    </svg>
                )}
            </div>
        </div>
    )
}

export default AttackSurfaceGraph

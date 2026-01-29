import { useState } from 'react'

const SearchBar = ({ onSearch, loading }) => {
    const [input, setInput] = useState('')
    const [error, setError] = useState('')

    const handleSubmit = (e) => {
        e.preventDefault()
        if (!input.trim()) {
            setError('Please enter a domain')
            return
        }
        // Basic frontend validation
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/
        if (!domainRegex.test(input.replace('https://', '').replace('http://', '').split('/')[0])) {
            setError('Invalid domain format')
            return
        }

        setError('')
        onSearch(input.replace('https://', '').replace('http://', '').split('/')[0])
    }

    return (
        <div className="card" style={{ padding: '2rem' }}>
            <h2 style={{ marginBottom: '1.5rem', textAlign: 'center' }}>Target Acquisition</h2>
            <form onSubmit={handleSubmit}>
                <div style={{ marginBottom: '1rem' }}>
                    <input
                        type="text"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        placeholder="example.com"
                        style={{
                            width: '100%',
                            padding: '1rem',
                            backgroundColor: 'var(--bg-primary)',
                            border: '1px solid var(--border-color)',
                            color: 'var(--text-primary)',
                            borderRadius: '4px',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '1rem',
                            outline: 'none'
                        }}
                    />
                    {error && <p style={{ color: 'var(--secondary)', marginTop: '0.5rem', fontSize: '0.875rem' }}>{error}</p>}
                </div>
                <button
                    type="submit"
                    className="btn btn-primary"
                    style={{ width: '100%', opacity: loading ? 0.7 : 1 }}
                    disabled={loading}
                >
                    {loading ? 'Scanning...' : 'Initiate Scan'}
                </button>
            </form>
        </div>
    )
}

export default SearchBar

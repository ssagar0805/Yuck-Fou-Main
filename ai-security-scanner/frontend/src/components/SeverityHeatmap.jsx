import { motion } from 'framer-motion'

export default function SeverityHeatmap({ findings = [] }) {
    // Grid: Rows = Categories, Cols = Severities
    const categories = Array.from(new Set(findings.map(f => f.category))).sort()
    const severities = ['Critical', 'High', 'Medium', 'Low']

    // Build grid data
    const grid = {}
    categories.forEach(cat => {
        grid[cat] = { Critical: 0, High: 0, Medium: 0, Low: 0 }
    })

    findings.forEach(f => {
        if (grid[f.category] && grid[f.category][f.severity] !== undefined) {
            grid[f.category][f.severity]++
        }
    })

    const getColor = (count, severity) => {
        if (count === 0) return 'rgba(255,255,255,0.02)'
        const opacity = Math.min(0.2 + (count * 0.15), 0.9)
        switch (severity) {
            case 'Critical': return `rgba(255, 51, 102, ${opacity})`
            case 'High': return `rgba(255, 153, 51, ${opacity})`
            case 'Medium': return `rgba(255, 215, 0, ${opacity})`
            case 'Low': return `rgba(0, 245, 255, ${opacity})`
            default: return 'rgba(255,255,255,0.1)'
        }
    }

    if (categories.length === 0) {
        return (
            <div className="glass-card" style={{ padding: 24, display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', minHeight: 250 }}>
                <p style={{ color: '#6B7A90', fontSize: '0.9rem' }}>No data for heatmap</p>
            </div>
        )
    }

    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="glass-card"
            style={{ padding: '24px', height: '100%', minHeight: 300, overflow: 'auto' }}
        >
            <h3 style={{ fontSize: '0.75rem', fontWeight: 700, color: '#00F5FF', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 20 }}>
                Severity Heatmap
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(100px, 1fr) repeat(4, 1fr)', gap: 8 }}>
                {/* Header Row */}
                <div style={{ fontSize: '0.7rem', color: '#6B7A90', fontWeight: 600 }}>CATEGORY</div>
                {severities.map(s => (
                    <div key={s} style={{ fontSize: '0.7rem', color: '#6B7A90', fontWeight: 600, textAlign: 'center' }}>
                        {s.toUpperCase()}
                    </div>
                ))}

                {/* Data Rows */}
                {categories.map(cat => (
                    <>
                        <div key={`${cat}-label`} style={{ fontSize: '0.75rem', color: '#B8C5D6', display: 'flex', alignItems: 'center' }}>
                            {cat}
                        </div>
                        {severities.map(sev => {
                            const count = grid[cat][sev]
                            return (
                                <div
                                    key={`${cat}-${sev}`}
                                    style={{
                                        background: getColor(count, sev),
                                        borderRadius: 4,
                                        height: 32,
                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        fontSize: '0.8rem', fontWeight: 700, color: count > 0 ? '#fff' : 'transparent',
                                        border: count > 0 ? '1px solid rgba(255,255,255,0.1)' : '1px solid rgba(255,255,255,0.02)'
                                    }}
                                    title={`${cat} - ${sev}: ${count}`}
                                >
                                    {count}
                                </div>
                            )
                        })}
                    </>
                ))}
            </div>
        </motion.div>
    )
}

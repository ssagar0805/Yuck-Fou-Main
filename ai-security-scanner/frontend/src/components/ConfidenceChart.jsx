import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { motion } from 'framer-motion'

export default function ConfidenceChart({ findings = [] }) {
    // Bucket findings by confidence
    const buckets = [
        { name: 'Very High (90%+)', min: 0.9, count: 0, color: '#00F5FF' },
        { name: 'High (70-89%)', min: 0.7, count: 0, color: '#00D1FF' },
        { name: 'Medium (50-69%)', min: 0.5, count: 0, color: '#00A3FF' },
        { name: 'Low (<50%)', min: 0.0, count: 0, color: '#0075FF' },
    ]

    findings.forEach(f => {
        const conf = f.confidence || 0
        if (conf >= 0.9) buckets[0].count++
        else if (conf >= 0.7) buckets[1].count++
        else if (conf >= 0.5) buckets[2].count++
        else buckets[3].count++
    })

    const data = buckets.filter(b => b.count > 0)

    if (data.length === 0) {
        return (
            <div className="glass-card" style={{ padding: 24, display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', minHeight: 250 }}>
                <p style={{ color: '#6B7A90', fontSize: '0.9rem' }}>No confidence data available</p>
            </div>
        )
    }

    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5 }}
            className="glass-card"
            style={{ padding: '24px', height: '100%', minHeight: 300, display: 'flex', flexDirection: 'column' }}
        >
            <h3 style={{ fontSize: '0.75rem', fontWeight: 700, color: '#00F5FF', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 20 }}>
                AI Confidence Distribution
            </h3>
            <div style={{ flex: 1, minHeight: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                        <XAxis type="number" hide />
                        <YAxis
                            dataKey="name"
                            type="category"
                            width={100}
                            tick={{ fill: '#B8C5D6', fontSize: 10 }}
                            axisLine={false}
                            tickLine={false}
                        />
                        <Tooltip
                            contentStyle={{ backgroundColor: 'rgba(10, 25, 41, 0.95)', border: '1px solid rgba(0, 245, 255, 0.2)', borderRadius: 8 }}
                            itemStyle={{ color: '#fff' }}
                            cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                        />
                        <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20}>
                            {data.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                        </Bar>
                    </BarChart>
                </ResponsiveContainer>
            </div>
        </motion.div>
    )
}

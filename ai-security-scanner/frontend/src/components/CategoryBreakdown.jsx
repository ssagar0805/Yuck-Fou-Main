import { useState } from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { motion, AnimatePresence } from 'framer-motion'
import { OWASP_COLORS } from '../utils/formatters'
import { FiChevronDown, FiChevronUp, FiInfo } from 'react-icons/fi'

const OWASP_DESCRIPTIONS = {
    'LLM01:2025': 'Prompt Injection: Attackers manipulate LLM input to override instructions.',
    'LLM02:2025': 'Sensitive Information Disclosure: LLM reveals confidential data.',
    'LLM03:2025': 'Supply Chain Vulnerabilities: Risks from third-party models or data.',
    'LLM04:2025': 'Data and Model Poisoning: Malicious data corrupted the model behavior.',
    'LLM05:2025': 'Improper Output Handling: LLM output executed without validation.',
    'LLM06:2025': 'Excessive Agency: LLM has too much autonomy or dangerous tools.',
    'LLM07:2025': 'System Prompt Leakage: Attacker extracts the system instructions.',
    'LLM08:2025': 'Vector and Embedding Weaknesses: Attacks on RAG/embedding layer.',
    'LLM09:2025': 'Misinformation/Hallucination: Model generates false or misleading info.',
    'LLM10:2025': 'Unbounded Consumption: DoS attacks via expensive queries.'
}

const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null
    const d = payload[0]
    return (
        <div style={{
            background: 'rgba(19,24,41,0.95)', border: '1px solid rgba(0,245,255,0.2)',
            borderRadius: 10, padding: '10px 16px', backdropFilter: 'blur(16px)',
            boxShadow: '0 4px 20px rgba(0,0,0,0.5)'
        }}>
            <p style={{ color: d.payload.color, fontWeight: 700, fontSize: '0.85rem', marginBottom: 4 }}>{d.name.split(' ')[0]}</p>
            <p style={{ color: '#B8C5D6', fontSize: '0.8rem' }}>Score: <strong style={{ color: '#00F5FF' }}>{d.value.toFixed(1)}</strong></p>
        </div>
    )
}

function CategoryCard({ category, score, color, expanded, onClick }) {
    return (
        <motion.div
            layout
            onClick={onClick}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            style={{
                background: expanded ? 'rgba(255,255,255,0.05)' : 'rgba(255,255,255,0.02)',
                border: expanded ? `1px solid ${color}` : '1px solid rgba(255,255,255,0.05)',
                borderRadius: 8, marginBottom: 8, overflow: 'hidden', cursor: 'pointer',
                transition: 'all 0.2s'
            }}
        >
            <div style={{ padding: '10px 12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 8px ${color}` }} />
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#E0E6ED', fontFamily: 'JetBrains Mono, monospace' }}>
                        {category}
                    </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 700, color: color }}>{score.toFixed(1)}</span>
                    {expanded ? <FiChevronUp color="#6B7A90" size={14} /> : <FiChevronDown color="#6B7A90" size={14} />}
                </div>
            </div>

            <AnimatePresence>
                {expanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        style={{ overflow: 'hidden' }}
                    >
                        <div style={{ padding: '0 12px 12px 30px', borderTop: '1px solid rgba(255,255,255,0.03)' }}>
                            <p style={{ fontSize: '0.7rem', color: '#B8C5D6', marginTop: 8, lineHeight: 1.5 }}>
                                {OWASP_DESCRIPTIONS[category] || 'No description available.'}
                            </p>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    )
}

export default function CategoryBreakdown({ breakdown }) {
    const [expandedCat, setExpandedCat] = useState(null)

    const data = Object.entries(breakdown || {}).map(([cat, score]) => ({
        name: `${cat}`, // Short name for pie, full details in card
        value: parseFloat(score.toFixed(1)),
        color: OWASP_COLORS[cat] || '#6B7A90',
        id: cat
    })).sort((a, b) => b.value - a.value)

    if (!data.length) return null

    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="glass-card"
            style={{ padding: '0', display: 'flex', flexDirection: 'column', height: '100%', minHeight: 400, overflow: 'hidden' }}
        >
            <div style={{ padding: '24px 24px 0' }}>
                <h3 style={{ fontSize: '0.75rem', fontWeight: 700, color: '#00F5FF', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 4 }}>
                    Category Risk Breakdown
                </h3>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
                {/* Chart Area */}
                <div style={{ height: 200, position: 'relative' }}>
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie
                                data={data}
                                cx="50%"
                                cy="50%"
                                innerRadius={60}
                                outerRadius={80}
                                paddingAngle={4}
                                dataKey="value"
                                stroke="none"
                            >
                                {data.map((entry, i) => (
                                    <Cell key={i} fill={entry.color}
                                        style={{ filter: expandedCat === entry.id ? `drop-shadow(0 0 8px ${entry.color})` : 'none', transition: 'all 0.3s' }}
                                    />
                                ))}
                            </Pie>
                            <Tooltip content={<CustomTooltip />} />
                        </PieChart>
                    </ResponsiveContainer>

                    {/* Centered Total or Label */}
                    <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center', pointerEvents: 'none' }}>
                        <span style={{ fontSize: '1.5rem', fontWeight: 800, color: '#fff' }}>{data.length}</span>
                        <div style={{ fontSize: '0.6rem', color: '#6B7A90', textTransform: 'uppercase' }}>Categories</div>
                    </div>
                </div>

                {/* Cards Area - Scrollable */}
                <div style={{ flex: 1, overflowY: 'auto', padding: '0 20px 20px', scrollbarWidth: 'thin' }}>
                    {data.map((entry) => (
                        <CategoryCard
                            key={entry.id}
                            category={entry.id}
                            score={entry.value}
                            color={entry.color}
                            expanded={expandedCat === entry.id}
                            onClick={() => setExpandedCat(expandedCat === entry.id ? null : entry.id)}
                        />
                    ))}
                </div>
            </div>
        </motion.div>
    )
}

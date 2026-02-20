import { motion } from 'framer-motion'
import { FiShield, FiAlertTriangle, FiClock, FiActivity } from 'react-icons/fi'
import { formatDuration, getRiskColor } from '../utils/formatters'

function AnimatedNumber({ value, suffix = '' }) {
    return (
        <motion.span
            key={value}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
        >
            {value}{suffix}
        </motion.span>
    )
}

export default function MetricsCards({ results }) {
    const { total_findings, critical_severity_count, high_severity_count,
        scan_duration, risk_level, risk_score } = results

    const riskColor = getRiskColor(risk_level)

    const cards = [
        {
            icon: FiShield,
            value: total_findings,
            label: 'Total Vulnerabilities',
            sub: `${high_severity_count} High · ${critical_severity_count} Critical`,
            color: '#00F5FF',
            glow: 'rgba(0,245,255,0.15)',
        },
        {
            icon: FiAlertTriangle,
            value: critical_severity_count,
            label: 'Critical Issues',
            sub: critical_severity_count > 0 ? 'Immediate action required' : 'No critical issues',
            color: critical_severity_count > 0 ? '#FF0033' : '#00FF88',
            glow: critical_severity_count > 0 ? 'rgba(255,0,51,0.15)' : 'rgba(0,255,136,0.1)',
            pulse: critical_severity_count > 0,
        },
        {
            icon: FiClock,
            value: formatDuration(scan_duration),
            label: 'Scan Duration',
            sub: 'Hybrid detection time',
            color: '#00D9FF',
            glow: 'rgba(0,217,255,0.12)',
            isString: true,
        },
        {
            icon: FiActivity,
            value: risk_level,
            label: 'Risk Level',
            sub: `Score: ${risk_score}/100`,
            color: riskColor,
            glow: `${riskColor}25`,
            isString: true,
            pulse: risk_level === 'Critical',
        },
    ]

    return (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
            {cards.map((card, i) => {
                const Icon = card.icon
                return (
                    <motion.div
                        key={i}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.5, delay: i * 0.1 }}
                        whileHover={{ y: -4 }}
                        style={{
                            background: 'rgba(19,24,41,0.8)',
                            border: `1px solid ${card.color}30`,
                            borderRadius: 16,
                            padding: '24px 20px',
                            backdropFilter: 'blur(16px)',
                            boxShadow: `0 4px 20px rgba(0,0,0,0.3), 0 0 20px ${card.glow}`,
                            animation: card.pulse ? 'pulse-glow 2s infinite' : 'none',
                            cursor: 'default',
                        }}
                    >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                            <div style={{
                                width: 40, height: 40, borderRadius: 10,
                                background: `${card.color}15`,
                                border: `1px solid ${card.color}30`,
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                            }}>
                                <Icon size={20} color={card.color} />
                            </div>
                        </div>

                        <div style={{ fontSize: card.isString ? '1.5rem' : '2.2rem', fontWeight: 800, color: card.color, lineHeight: 1, marginBottom: 6, fontFamily: card.isString ? 'Inter, sans-serif' : 'JetBrains Mono, monospace' }}>
                            <AnimatedNumber value={card.value} />
                        </div>
                        <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#FFFFFF', marginBottom: 4 }}>{card.label}</div>
                        <div style={{ fontSize: '0.7rem', color: '#6B7A90' }}>{card.sub}</div>
                    </motion.div>
                )
            })}
        </div>
    )
}

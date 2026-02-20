import { motion } from 'framer-motion'
import { FiShield, FiCpu, FiLayers } from 'react-icons/fi'

const badges = [
    {
        icon: FiShield,
        topLabel: 'INDUSTRY STANDARD',
        mainLabel: 'OWASP ALIGNED',
        subLabel: 'Top 10 LLM 2025 Framework',
        gradient: 'from-cyan-500/10 to-blue-500/10',
        borderColor: 'rgba(0, 245, 255, 0.4)',
        glowColor: 'rgba(0, 245, 255, 0.15)',
        iconColor: '#00F5FF',
        delay: 0,
    },
    {
        icon: FiCpu,
        topLabel: 'ADVANCED INTELLIGENCE',
        mainLabel: 'AI-POWERED',
        subLabel: 'Google Gemini 2.0 Flash',
        gradient: 'from-purple-500/10 to-cyan-500/10',
        borderColor: 'rgba(168, 85, 247, 0.5)',
        glowColor: 'rgba(168, 85, 247, 0.15)',
        iconColor: '#A855F7',
        delay: 0.1,
    },
    {
        icon: FiLayers,
        topLabel: 'COMPREHENSIVE',
        mainLabel: 'HYBRID ENGINE',
        subLabel: 'Rule-Based + LLM Detection',
        gradient: 'from-orange-500/10 to-cyan-500/10',
        borderColor: 'rgba(255, 184, 0, 0.4)',
        glowColor: 'rgba(255, 184, 0, 0.12)',
        iconColor: '#FFB800',
        delay: 0.2,
    },
]

export default function CredibilityBadges() {
    return (
        <section className="flex flex-wrap justify-center gap-5 py-10 px-4">
            {badges.map((badge, i) => {
                const Icon = badge.icon
                return (
                    <motion.div
                        key={i}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.6, delay: badge.delay, ease: 'easeOut' }}
                        whileHover={{ y: -6, scale: 1.03 }}
                        style={{
                            width: 210,
                            minHeight: 130,
                            background: `linear-gradient(135deg, ${badge.gradient.replace('from-', '').replace(' to-', ', ')})`,
                            border: `1px solid ${badge.borderColor}`,
                            boxShadow: `0 0 20px ${badge.glowColor}, 0 4px 20px rgba(0,0,0,0.4)`,
                            borderRadius: 16,
                            backdropFilter: 'blur(16px)',
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 6,
                            padding: '20px 16px',
                            cursor: 'default',
                            animation: `border-pulse 2.5s ease-in-out infinite ${badge.delay}s`,
                        }}
                    >
                        <Icon size={28} color={badge.iconColor} style={{ filter: `drop-shadow(0 0 8px ${badge.iconColor})` }} />
                        <span style={{ fontSize: '0.6rem', color: '#00F5FF', fontWeight: 600, letterSpacing: '0.15em', textTransform: 'uppercase' }}>
                            {badge.topLabel}
                        </span>
                        <span style={{ fontSize: '1.05rem', color: '#FFFFFF', fontWeight: 800, letterSpacing: '-0.01em', textAlign: 'center', lineHeight: 1.2 }}>
                            {badge.mainLabel}
                        </span>
                        <span style={{ fontSize: '0.68rem', color: '#B8C5D6', textAlign: 'center', lineHeight: 1.4 }}>
                            {badge.subLabel}
                        </span>
                    </motion.div>
                )
            })}
        </section>
    )
}

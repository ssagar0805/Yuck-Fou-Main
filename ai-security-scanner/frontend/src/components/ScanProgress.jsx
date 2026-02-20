import { motion } from 'framer-motion'
import { FiCpu, FiCheckCircle } from 'react-icons/fi'

export default function ScanProgress({ isScanning, isComplete, progress }) {
    // If progress is provided, use it. Otherwise default to 0.
    const displayPct = isComplete ? 100 : (progress?.percent || 0)
    const currentMsg = isComplete ? 'Scan complete ✓' : (progress?.message || 'Initializing...')
    const currentSub = isComplete ? 'All checks finished' : (progress?.subMessage || 'Preparing environment...')

    // Calculate active step index for visual bar (0-5)
    // Approximate mapping based on percent
    const stepIdx = Math.floor((displayPct / 100) * 5)

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            style={{ maxWidth: 720, margin: '0 auto', padding: '0 24px 40px' }}
        >
            <div className="glass-card" style={{ padding: '36px 40px' }}>
                {/* Header row */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 28 }}>
                    <div style={{
                        width: 44, height: 44, borderRadius: 12,
                        background: isComplete ? 'rgba(0,255,136,0.15)' : 'rgba(0,245,255,0.1)',
                        border: `1px solid ${isComplete ? 'rgba(0,255,136,0.4)' : 'rgba(0,245,255,0.3)'}`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        animation: isComplete ? 'none' : 'pulse-glow 1.5s infinite',
                    }}>
                        {isComplete
                            ? <FiCheckCircle size={22} color="#00FF88" />
                            : <FiCpu size={22} color="#00F5FF" style={{ animation: 'spin-slow 2s linear infinite' }} />
                        }
                    </div>
                    <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                            <span style={{ fontWeight: 700, color: isComplete ? '#00FF88' : '#FFFFFF', fontSize: '0.95rem' }}>
                                {currentMsg}
                            </span>
                            <span style={{ fontWeight: 700, color: '#00F5FF', fontSize: '0.95rem', fontFamily: 'JetBrains Mono, monospace' }}>
                                {Math.round(displayPct)}%
                            </span>
                        </div>
                        <p style={{ fontSize: '0.78rem', color: '#6B7A90' }}>{currentSub}</p>
                    </div>
                </div>

                {/* Progress bar */}
                <div style={{ height: 8, background: '#1A1F3A', borderRadius: 4, overflow: 'hidden', marginBottom: 20 }}>
                    <motion.div
                        animate={{ width: `${displayPct}%` }}
                        transition={{ duration: 0.8, ease: 'easeOut' }}
                        className={displayPct < 100 ? 'shimmer-bar' : ''}
                        style={{
                            height: '100%',
                            background: isComplete
                                ? 'linear-gradient(90deg, #00FF88, #00D9FF)'
                                : 'linear-gradient(90deg, #00F5FF, #0080FF)',
                            borderRadius: 4,
                            boxShadow: isComplete ? '0 0 10px rgba(0,255,136,0.5)' : '0 0 10px rgba(0,245,255,0.5)',
                        }}
                    />
                </div>

                {/* Step indicators */}
                <div style={{ display: 'flex', gap: 6, justifyContent: 'center' }}>
                    {[0, 1, 2, 3, 4].map((i) => (
                        <div key={i} style={{
                            height: 3, flex: 1, borderRadius: 2,
                            background: i <= stepIdx ? 'rgba(0,245,255,0.7)' : 'rgba(0,245,255,0.1)',
                            transition: 'background 0.5s ease',
                        }} />
                    ))}
                </div>

                {/* AI mention */}
                {!isComplete && (
                    <p style={{ textAlign: 'center', marginTop: 16, fontSize: '0.72rem', color: '#6B7A90' }}>
                        🤖 AI-Powered Analysis · OWASP Top 10 LLM 2025 · Hybrid Detection Engine
                    </p>
                )}
            </div>
        </motion.div>
    )
}

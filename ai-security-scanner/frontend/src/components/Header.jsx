import { motion } from 'framer-motion'
import { FiShield, FiActivity } from 'react-icons/fi'

export default function Header() {
    return (
        <motion.header
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            style={{
                position: 'sticky',
                top: 0,
                zIndex: 100,
                background: 'rgba(10, 14, 39, 0.92)',
                backdropFilter: 'blur(20px)',
                borderBottom: '1px solid rgba(0, 245, 255, 0.12)',
                boxShadow: '0 4px 30px rgba(0, 0, 0, 0.5)',
            }}
        >
            <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', height: 72, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                {/* Left: Logo + Title */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                    <div style={{
                        width: 42, height: 42, borderRadius: 10,
                        background: 'linear-gradient(135deg, rgba(0,245,255,0.2), rgba(0,128,255,0.2))',
                        border: '1px solid rgba(0,245,255,0.3)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        boxShadow: '0 0 15px rgba(0,245,255,0.2)',
                    }}>
                        <FiShield size={22} color="#00F5FF" />
                    </div>
                    <div>
                        <h1 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#FFFFFF', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
                            AI Security Scanner
                        </h1>
                        <p style={{ fontSize: '0.7rem', color: '#6B7A90', letterSpacing: '0.08em', textTransform: 'uppercase', marginTop: 2 }}>
                            OWASP Top 10 LLM Vulnerability Assessment
                        </p>
                    </div>
                </div>

                {/* Right: Status + Version */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#00FF88', boxShadow: '0 0 8px #00FF88', animation: 'pulse-glow 2s infinite' }} />
                        <span style={{ fontSize: '0.7rem', color: '#00FF88', fontWeight: 600, letterSpacing: '0.1em' }}>SYSTEM ONLINE</span>
                    </div>
                    <div style={{
                        padding: '4px 12px', borderRadius: 20,
                        background: 'rgba(0,245,255,0.1)',
                        border: '1px solid rgba(0,245,255,0.25)',
                        fontSize: '0.7rem', color: '#00F5FF', fontWeight: 700, letterSpacing: '0.1em',
                    }}>
                        v1.0
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 8, background: 'rgba(0,245,255,0.05)', border: '1px solid rgba(0,245,255,0.1)' }}>
                        <FiActivity size={13} color="#00F5FF" />
                        <span style={{ fontSize: '0.65rem', color: '#B8C5D6', fontWeight: 500 }}>Gemini 2.0 Flash</span>
                    </div>
                </div>
            </div>
        </motion.header>
    )
}

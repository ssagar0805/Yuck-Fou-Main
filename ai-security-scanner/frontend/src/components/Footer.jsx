export default function Footer() {
    return (
        <footer style={{
            borderTop: '1px solid rgba(0,245,255,0.08)',
            padding: '24px',
            textAlign: 'center',
            background: 'rgba(10,14,39,0.8)',
        }}>
            <p style={{ fontSize: '0.72rem', color: '#6B7A90', letterSpacing: '0.06em' }}>
                Powered by{' '}
                <span style={{ color: '#A855F7', fontWeight: 600 }}>Google Gemini 2.0 Flash</span>
                {' '}·{' '}
                <span style={{ color: '#00F5FF', fontWeight: 600 }}>OWASP Top 10 LLM 2025</span>
                {' '}·{' '}
                <span style={{ color: '#B8C5D6' }}>Hybrid Detection Engine</span>
                {' '}·{' '}
                <span style={{ color: '#6B7A90' }}>AI Security Scanner v1.0</span>
            </p>
        </footer>
    )
}

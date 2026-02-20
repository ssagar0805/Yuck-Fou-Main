/**
 * Utility formatters
 */

export const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, None: 4 }

export const OWASP_LABELS = {
    'LLM01:2025': 'Prompt Injection',
    'LLM02:2025': 'Sensitive Info Disclosure',
    'LLM03:2025': 'Supply Chain',
    'LLM04:2025': 'Data & Model Poisoning',
    'LLM05:2025': 'Improper Output Handling',
    'LLM06:2025': 'Excessive Agency',
    'LLM07:2025': 'System Prompt Leakage',
    'LLM08:2025': 'Vector/Embedding Weakness',
    'LLM09:2025': 'Misinformation',
    'LLM10:2025': 'Unbounded Consumption',
}

export const OWASP_COLORS = {
    'LLM01:2025': '#FF3366', // Red-pink
    'LLM02:2025': '#FFB800', // Orange
    'LLM03:2025': '#34D399', // Emerald
    'LLM04:2025': '#F87171', // Red
    'LLM05:2025': '#00F5FF', // Cyan
    'LLM06:2025': '#A855F7', // Purple
    'LLM07:2025': '#FB7185', // Rose
    'LLM08:2025': '#60A5FA', // Blue
    'LLM09:2025': '#F472B6', // Pink
    'LLM10:2025': '#94A3B8', // Slate
}

export function formatDuration(seconds) {
    if (seconds < 1) return `${Math.round(seconds * 1000)}ms`
    return `${seconds.toFixed(2)}s`
}

export function formatFileSize(bytes) {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function getRiskColor(level) {
    const map = {
        Critical: '#FF0033',
        High: '#FF3366',
        Medium: '#FFB800',
        Low: '#00FF88',
    }
    return map[level] || '#6B7A90'
}

export function getRiskGradient(score) {
    if (score >= 76) return 'from-red-600 to-red-900'
    if (score >= 51) return 'from-orange-500 to-red-600'
    if (score >= 26) return 'from-yellow-500 to-orange-500'
    return 'from-green-500 to-cyan-500'
}

export function getSeverityClass(severity) {
    const map = {
        Critical: 'badge-critical',
        High: 'badge-high',
        Medium: 'badge-medium',
        Low: 'badge-low',
    }
    return `badge ${map[severity] || 'badge-low'}`
}

export function truncate(str, n = 80) {
    if (!str) return ''
    return str.length > n ? str.slice(0, n) + '…' : str
}

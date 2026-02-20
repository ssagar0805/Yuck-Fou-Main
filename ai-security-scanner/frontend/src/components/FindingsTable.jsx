import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FiChevronDown, FiChevronUp, FiSearch, FiChevronLeft, FiChevronRight } from 'react-icons/fi'
import { getSeverityClass, OWASP_LABELS, SEVERITY_ORDER, truncate } from '../utils/formatters'

const FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low']
const PAGE_SIZE = 8

function SortIcon({ col, sortCol, sortDir }) {
    if (sortCol !== col) return <span style={{ color: '#6B7A90', marginLeft: 4 }}>⇅</span>
    return <span style={{ color: '#00F5FF', marginLeft: 4 }}>{sortDir === 'asc' ? '↑' : '↓'}</span>
}

function ExpandedRow({ finding }) {
    return (
        <motion.tr
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
        >
            <td colSpan={6} style={{ padding: '0 16px 20px', background: 'rgba(0,245,255,0.02)' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, paddingTop: 16 }}>
                    {/* Evidence */}
                    <div>
                        <p style={{ fontSize: '0.65rem', color: '#00F5FF', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8 }}>Evidence</p>
                        <div style={{ background: 'rgba(0,0,0,0.3)', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)' }}>
                            {finding.evidence?.length ? (
                                <ul style={{ margin: 0, paddingLeft: 16, color: '#E0E6ED', fontSize: '0.85rem' }}>
                                    {finding.evidence.map((e, i) => (
                                        <li key={i} style={{ marginBottom: 4 }}>
                                            {e}
                                            {finding.line_number && <span style={{ color: '#00F5FF', marginLeft: 8, fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace' }}>(Line {finding.line_number})</span>}
                                        </li>
                                    ))}
                                </ul>
                            ) : <span style={{ color: '#64748b', fontSize: '0.85rem' }}>No specific evidence provided.</span>}
                        </div>

                        {finding.owasp_reference && (
                            <div style={{ marginTop: 12 }}>
                                <p style={{ fontSize: '0.65rem', color: '#94A3B8', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4 }}>OWASP Reference</p>
                                <p style={{ color: '#00F5FF', fontSize: '0.85rem', fontFamily: 'monospace' }}>{finding.owasp_reference}</p>
                            </div>
                        )}
                    </div>
                    {/* Remediation */}
                    <div>
                        <p style={{ fontSize: '0.65rem', color: '#00FF88', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8 }}>Remediation</p>
                        <p style={{ fontSize: '0.8rem', color: '#B8C5D6', lineHeight: 1.6 }}>{finding.remediation}</p>
                        {finding.attack_scenario && (
                            <>
                                <p style={{ fontSize: '0.65rem', color: '#FFB800', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', marginTop: 12, marginBottom: 8 }}>Attack Scenario</p>
                                <p style={{ fontSize: '0.78rem', color: '#B8C5D6', lineHeight: 1.6 }}>{finding.attack_scenario}</p>
                            </>
                        )}
                    </div>
                </div>
            </td>
        </motion.tr>
    )
}

export default function FindingsTable({ findings = [] }) {
    const [filter, setFilter] = useState('All')
    const [search, setSearch] = useState('')
    const [sortCol, setSortCol] = useState('severity')
    const [sortDir, setSortDir] = useState('asc')
    const [expanded, setExpanded] = useState(null)
    const [page, setPage] = useState(1)

    const handleSort = (col) => {
        if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
        else { setSortCol(col); setSortDir('asc') }
        setPage(1)
    }

    const filtered = useMemo(() => {
        let data = findings
        if (filter !== 'All') data = data.filter(f => f.severity === filter)
        if (search) data = data.filter(f =>
            f.description?.toLowerCase().includes(search.toLowerCase()) ||
            f.category?.toLowerCase().includes(search.toLowerCase())
        )
        data = [...data].sort((a, b) => {
            let av, bv
            if (sortCol === 'severity') { av = SEVERITY_ORDER[a.severity] ?? 9; bv = SEVERITY_ORDER[b.severity] ?? 9 }
            else if (sortCol === 'confidence') { av = a.confidence; bv = b.confidence }
            else if (sortCol === 'category') { av = a.category; bv = b.category }
            else { av = a.description; bv = b.description }
            const cmp = typeof av === 'string' ? av.localeCompare(bv) : av - bv
            return sortDir === 'asc' ? cmp : -cmp
        })
        return data
    }, [findings, filter, search, sortCol, sortDir])

    const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
    const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.5 }}
            className="glass-card"
            style={{ overflow: 'hidden' }}
        >
            {/* Table header bar */}
            <div style={{ padding: '20px 20px 16px', borderBottom: '1px solid rgba(0,245,255,0.08)', display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center', justifyContent: 'space-between' }}>
                <h3 style={{ fontSize: '0.75rem', fontWeight: 700, color: '#00F5FF', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
                    Vulnerability Findings ({filtered.length})
                </h3>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                    {/* Search */}
                    <div style={{ position: 'relative' }}>
                        <FiSearch size={13} color="#6B7A90" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }} />
                        <input
                            value={search}
                            onChange={e => { setSearch(e.target.value); setPage(1) }}
                            placeholder="Search findings..."
                            style={{
                                background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(0,245,255,0.15)',
                                borderRadius: 8, padding: '7px 12px 7px 30px', color: '#B8C5D6',
                                fontSize: '0.8rem', outline: 'none', width: 180,
                            }}
                        />
                    </div>
                    {/* Severity filters */}
                    <div style={{ display: 'flex', gap: 6 }}>
                        {FILTERS.map(f => (
                            <button key={f} onClick={() => { setFilter(f); setPage(1) }} style={{
                                padding: '5px 12px', borderRadius: 20, fontSize: '0.7rem', fontWeight: 600,
                                cursor: 'pointer', border: '1px solid',
                                background: filter === f ? 'rgba(0,245,255,0.15)' : 'transparent',
                                borderColor: filter === f ? 'rgba(0,245,255,0.4)' : 'rgba(0,245,255,0.1)',
                                color: filter === f ? '#00F5FF' : '#6B7A90',
                                transition: 'all 0.2s',
                            }}>{f}</button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Table */}
            <div style={{ overflowX: 'auto' }}>
                <table className="findings-table">
                    <thead>
                        <tr>
                            {[
                                { key: 'category', label: 'Category' },
                                { key: 'severity', label: 'Severity' },
                                { key: 'confidence', label: 'Confidence' },
                                { key: 'description', label: 'Description' },
                                { key: 'method', label: 'Method' },
                                { key: 'expand', label: '' },
                            ].map(col => (
                                <th key={col.key}
                                    onClick={() => col.key !== 'expand' && col.key !== 'method' && handleSort(col.key)}
                                    style={{ cursor: col.key !== 'expand' && col.key !== 'method' ? 'pointer' : 'default' }}
                                >
                                    {col.label}
                                    {col.key !== 'expand' && col.key !== 'method' && <SortIcon col={col.key} sortCol={sortCol} sortDir={sortDir} />}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        <AnimatePresence>
                            {paginated.length === 0 ? (
                                <tr><td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: '#6B7A90' }}>No findings match your filter.</td></tr>
                            ) : paginated.map((finding, i) => (
                                <>
                                    <motion.tr
                                        key={`${finding.category}-${i}`}
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1 }}
                                        transition={{ delay: i * 0.04 }}
                                        onClick={() => setExpanded(expanded === i ? null : i)}
                                        style={{ cursor: 'pointer' }}
                                    >
                                        {/* Category */}
                                        <td>
                                            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', color: '#00F5FF', fontWeight: 600 }}>{finding.category}</div>
                                            <div style={{ fontSize: '0.65rem', color: '#6B7A90', marginTop: 2 }}>{OWASP_LABELS[finding.category]}</div>
                                        </td>
                                        {/* Severity */}
                                        <td><span className={getSeverityClass(finding.severity)}>{finding.severity}</span></td>
                                        {/* Confidence */}
                                        <td>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                <div style={{ flex: 1, height: 4, background: '#1A1F3A', borderRadius: 2, overflow: 'hidden', minWidth: 50 }}>
                                                    <div style={{ height: '100%', width: `${finding.confidence * 100}%`, background: '#00F5FF', borderRadius: 2 }} />
                                                </div>
                                                <span style={{ fontSize: '0.72rem', color: '#B8C5D6', fontFamily: 'JetBrains Mono, monospace', minWidth: 32 }}>
                                                    {Math.round(finding.confidence * 100)}%
                                                </span>
                                            </div>
                                        </td>
                                        {/* Description */}
                                        <td style={{ maxWidth: 300 }}>
                                            <span style={{ fontSize: '0.82rem', color: '#B8C5D6', lineHeight: 1.5 }}>
                                                {truncate(finding.description, 100)}
                                            </span>
                                        </td>
                                        {/* Detection method */}
                                        <td>
                                            <span style={{
                                                fontSize: '0.65rem', padding: '3px 8px', borderRadius: 10, fontWeight: 600,
                                                background: finding.detection_method === 'llm_powered' ? 'rgba(168,85,247,0.15)' : 'rgba(0,245,255,0.1)',
                                                color: finding.detection_method === 'llm_powered' ? '#A855F7' : '#00F5FF',
                                                border: `1px solid ${finding.detection_method === 'llm_powered' ? 'rgba(168,85,247,0.3)' : 'rgba(0,245,255,0.2)'}`,
                                            }}>
                                                {finding.detection_method === 'llm_powered' ? '🤖 AI' : '⚡ Rule'}
                                            </span>
                                        </td>
                                        {/* Expand */}
                                        <td style={{ textAlign: 'center' }}>
                                            {expanded === i ? <FiChevronUp color="#00F5FF" /> : <FiChevronDown color="#6B7A90" />}
                                        </td>
                                    </motion.tr>
                                    {expanded === i && <ExpandedRow key={`exp-${i}`} finding={finding} />}
                                </>
                            ))}
                        </AnimatePresence>
                    </tbody>
                </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div style={{ padding: '16px 20px', borderTop: '1px solid rgba(0,245,255,0.08)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.75rem', color: '#6B7A90' }}>
                        Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, filtered.length)} of {filtered.length}
                    </span>
                    <div style={{ display: 'flex', gap: 8 }}>
                        <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                            style={{ background: 'rgba(0,245,255,0.08)', border: '1px solid rgba(0,245,255,0.15)', borderRadius: 8, padding: '6px 10px', cursor: page === 1 ? 'not-allowed' : 'pointer', color: page === 1 ? '#6B7A90' : '#00F5FF', opacity: page === 1 ? 0.5 : 1 }}>
                            <FiChevronLeft size={14} />
                        </button>
                        {Array.from({ length: totalPages }, (_, i) => (
                            <button key={i} onClick={() => setPage(i + 1)}
                                style={{ background: page === i + 1 ? 'rgba(0,245,255,0.2)' : 'rgba(0,245,255,0.05)', border: `1px solid ${page === i + 1 ? 'rgba(0,245,255,0.4)' : 'rgba(0,245,255,0.1)'}`, borderRadius: 8, padding: '6px 12px', cursor: 'pointer', color: page === i + 1 ? '#00F5FF' : '#6B7A90', fontSize: '0.8rem', fontWeight: page === i + 1 ? 700 : 400 }}>
                                {i + 1}
                            </button>
                        ))}
                        <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                            style={{ background: 'rgba(0,245,255,0.08)', border: '1px solid rgba(0,245,255,0.15)', borderRadius: 8, padding: '6px 10px', cursor: page === totalPages ? 'not-allowed' : 'pointer', color: page === totalPages ? '#6B7A90' : '#00F5FF', opacity: page === totalPages ? 0.5 : 1 }}>
                            <FiChevronRight size={14} />
                        </button>
                    </div>
                </div>
            )}
        </motion.div>
    )
}

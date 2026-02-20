import { useState } from 'react'
import { motion } from 'framer-motion'
import RiskGauge from './RiskGauge'
import MetricsCards from './MetricsCards'
import CategoryBreakdown from './CategoryBreakdown'
import ConfidenceChart from './ConfidenceChart'
import SeverityHeatmap from './SeverityHeatmap'
import FindingsTable from './FindingsTable'
import { FiRefreshCw, FiFile, FiCheckCircle, FiDownload } from 'react-icons/fi'

export default function ResultsDashboard({ results, onReset }) {
    const [activeIndex, setActiveIndex] = useState(0)

    // Safety check in case results structure is unexpected (e.g. legacy single file)
    // But we updated backend/frontend to always return { files: [], overall: {} }
    // We can fallback if needed.
    const isMultiFile = results.files && Array.isArray(results.files)

    const activeResult = isMultiFile ? results.files[activeIndex] : results
    const overall = isMultiFile ? results.overall : { risk_score: results.risk_score, risk_level: results.risk_level }

    const files = isMultiFile ? results.files : [results]

    return (
        <motion.section
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            style={{ maxWidth: 1400, margin: '0 auto', padding: '0 24px 80px' }}
        >
            {/* Results header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
                <div>
                    <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#FFFFFF', marginBottom: 6 }}>
                        Security Assessment Complete
                    </h2>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        {isMultiFile && (
                            <span style={{
                                padding: '4px 10px', borderRadius: 6, fontSize: '0.75rem', fontWeight: 700,
                                background: overall.risk_level === 'Critical' ? 'rgba(255, 51, 102, 0.2)' : 'rgba(0, 245, 255, 0.1)',
                                color: overall.risk_level === 'Critical' ? '#FF3366' : '#00F5FF',
                                border: overall.risk_level === 'Critical' ? '1px solid rgba(255, 51, 102, 0.3)' : '1px solid rgba(0, 245, 255, 0.3)'
                            }}>
                                Batch Risk: {overall.risk_level} ({overall.risk_score})
                            </span>
                        )}
                        <p style={{ fontSize: '0.8rem', color: '#6B7A90' }}>
                            Processed {overall.total_files || 1} {overall.total_files === 1 ? 'file' : 'files'}
                        </p>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: 12 }}>
                    {results.pdf_url && (
                        <a
                            href={`http://localhost:8000${results.pdf_url}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                                display: 'flex', alignItems: 'center', gap: 8,
                                padding: '10px 20px', borderRadius: 10, cursor: 'pointer',
                                background: 'rgba(52, 211, 153, 0.1)', border: '1px solid rgba(52, 211, 153, 0.3)',
                                color: '#34D399', fontSize: '0.82rem', fontWeight: 600, transition: 'all 0.2s',
                                textDecoration: 'none'
                            }}
                        >
                            <FiDownload size={16} /> Download Report
                        </a>
                    )}
                    <button
                        onClick={onReset}
                        style={{
                            display: 'flex', alignItems: 'center', gap: 8,
                            padding: '10px 20px', borderRadius: 10, cursor: 'pointer',
                            background: 'rgba(0,245,255,0.08)', border: '1px solid rgba(0,245,255,0.2)',
                            color: '#00F5FF', fontSize: '0.82rem', fontWeight: 600, transition: 'all 0.2s',
                        }}
                    >
                        <FiRefreshCw size={14} /> New Scan
                    </button>
                </div>
            </div>

            {/* File Tabs */}
            {isMultiFile && files.length > 1 && (
                <div style={{ display: 'flex', gap: 8, marginBottom: 24, overflowX: 'auto', paddingBottom: 4 }}>
                    {files.map((file, idx) => (
                        <button
                            key={idx}
                            onClick={() => setActiveIndex(idx)}
                            style={{
                                display: 'flex', alignItems: 'center', gap: 8,
                                padding: '10px 16px', borderRadius: 8, cursor: 'pointer',
                                background: activeIndex === idx ? 'rgba(0, 245, 255, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                                border: activeIndex === idx ? '1px solid rgba(0, 245, 255, 0.4)' : '1px solid rgba(255, 255, 255, 0.1)',
                                color: activeIndex === idx ? '#FFFFFF' : '#B8C5D6',
                                transition: 'all 0.2s', minWidth: 140
                            }}
                        >
                            <FiFile size={14} color={activeIndex === idx ? '#00F5FF' : '#6B7A90'} />
                            <div style={{ textAlign: 'left', overflow: 'hidden' }}>
                                <div style={{ fontSize: '0.8rem', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 120 }}>
                                    {file.file_name}
                                </div>
                                <div style={{ fontSize: '0.65rem', color: activeIndex === idx ? '#00F5FF' : '#6B7A90' }}>
                                    Risk: {file.risk_score}
                                </div>
                            </div>
                        </button>
                    ))}
                </div>
            )}

            {/* Top row: Gauge + Metrics + Breakdown */}
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(250px, 0.8fr) 1fr minmax(250px, 1fr)', gap: 24, marginBottom: 24, alignItems: 'start' }}>
                {/* Gauge */}
                <motion.div
                    key={`gauge-${activeIndex}`}
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.6, delay: 0.2 }}
                    className="glass-card"
                    style={{ padding: '32px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, height: '100%' }}
                >
                    <h3 style={{ fontSize: '0.7rem', fontWeight: 700, color: '#00F5FF', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
                        File Risk Score
                    </h3>
                    <RiskGauge score={activeResult.risk_score} level={activeResult.risk_level} />
                    {activeResult.summary && (
                        <p style={{ fontSize: '0.75rem', color: '#B8C5D6', textAlign: 'center', lineHeight: 1.6, marginTop: 8 }}>
                            {activeResult.summary.slice(0, 150)}...
                        </p>
                    )}
                </motion.div>

                {/* Metrics */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <p style={{ fontSize: '0.9rem', fontWeight: 600, color: '#fff', marginBottom: -8 }}>Findings Overview</p>
                    <MetricsCards results={activeResult} />
                </div>

                {/* Breakdown chart */}
                <CategoryBreakdown breakdown={activeResult.breakdown_by_category} />
            </div>

            {/* Second Row: Heatmap + Confidence */}
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 24, marginBottom: 32 }}>
                <SeverityHeatmap findings={activeResult.findings} />
                <ConfidenceChart findings={activeResult.findings} />
            </div>

            {/* Findings table */}
            <FindingsTable findings={activeResult.findings} />
        </motion.section>
    )
}

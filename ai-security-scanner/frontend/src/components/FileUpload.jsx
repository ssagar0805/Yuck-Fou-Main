import { useCallback, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { motion, AnimatePresence } from 'framer-motion'
import { FiUploadCloud, FiFile, FiX, FiAlertCircle, FiPlus, FiType, FiArrowLeft } from 'react-icons/fi'
import { formatFileSize } from '../utils/formatters'

const ACCEPTED = {
    'application/json': ['.json'],
    'application/x-yaml': ['.yaml', '.yml'],
    'text/plain': ['.txt'],
    'text/x-python': ['.py'],
}

export default function FileUpload({ onFilesSelect, selectedFiles = [], onClear, isScanning, onScan, onTextScan }) {
    const [error, setError] = useState('')
    const [activeTab, setActiveTab] = useState('upload') // 'upload' | 'text'
    const [textContent, setTextContent] = useState('')

    const onDrop = useCallback((accepted, rejected) => {
        setError('')
        if (rejected.length > 0) {
            setError('Some files were rejected. Please upload .json, .yaml, .txt, .js, or .py files.')
        }

        if (accepted.length > 0) {
            onFilesSelect([...selectedFiles, ...accepted])
        }
    }, [onFilesSelect, selectedFiles])

    const { getRootProps, getInputProps, isDragActive, open } = useDropzone({
        onDrop,
        accept: ACCEPTED,
        maxSize: 10 * 1024 * 1024,
        disabled: isScanning,
        noClick: true, // We have a custom open button
    })

    const handleRemoveFile = (index) => {
        const newFiles = [...selectedFiles]
        newFiles.splice(index, 1)
        onFilesSelect(newFiles)
        if (newFiles.length === 0) {
            setError('')
        }
    }

    const handleTextSubmit = () => {
        if (!textContent.trim()) {
            setError('Please enter some text to analyze.')
            return
        }
        // Call parent handler for text scan
        if (onTextScan) {
            onTextScan(textContent)
        }
    }

    const showInputView = selectedFiles.length === 0

    return (
        <motion.section
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.3 }}
            style={{ maxWidth: 720, margin: '0 auto', padding: '0 24px 60px' }}
        >
            <AnimatePresence mode="wait">
                {showInputView ? (
                    /* ── Input State: Tabs + Drop Zone / Text ── */
                    <motion.div
                        key="input-zone"
                        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                        className="glass-card"
                        style={{ padding: '30px', overflow: 'hidden' }}
                    >
                        {/* Tabs */}
                        <div style={{ display: 'flex', gap: 12, marginBottom: 24, justifyContent: 'center' }}>
                            <button
                                onClick={() => setActiveTab('upload')}
                                style={{
                                    display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px', borderRadius: 8,
                                    background: activeTab === 'upload' ? 'rgba(0,245,255,0.15)' : 'transparent',
                                    border: activeTab === 'upload' ? '1px solid rgba(0,245,255,0.3)' : '1px solid transparent',
                                    color: activeTab === 'upload' ? '#00F5FF' : '#6B7A90', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
                                }}
                            >
                                <FiUploadCloud /> Upload Files
                            </button>
                            <button
                                onClick={() => setActiveTab('text')}
                                style={{
                                    display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px', borderRadius: 8,
                                    background: activeTab === 'text' ? 'rgba(0,245,255,0.15)' : 'transparent',
                                    border: activeTab === 'text' ? '1px solid rgba(0,245,255,0.3)' : '1px solid transparent',
                                    color: activeTab === 'text' ? '#00F5FF' : '#6B7A90', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
                                }}
                            >
                                <FiType /> Paste Text
                            </button>
                        </div>

                        {activeTab === 'upload' ? (
                            <div
                                {...getRootProps()}
                                className={`upload-zone ${isDragActive ? 'drag-active' : ''}`}
                                onClick={open}
                                style={{
                                    padding: '50px 20px',
                                    textAlign: 'center',
                                    background: isDragActive ? 'rgba(0,245,255,0.07)' : 'rgba(0,0,0,0.2)',
                                    borderRadius: 12, border: '2px dashed rgba(255,255,255,0.1)',
                                    cursor: 'pointer', transition: 'all 0.2s'
                                }}
                            >
                                <input {...getInputProps()} />
                                <FiUploadCloud
                                    size={48}
                                    color={isDragActive ? '#00F5FF' : '#6B7A90'}
                                    style={{ marginBottom: 16, transition: 'all 0.3s' }}
                                />
                                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#FFFFFF', marginBottom: 8 }}>
                                    {isDragActive ? 'Release to upload' : 'Drop agent config files or click'}
                                </h3>
                                <p style={{ color: '#6B7A90', marginBottom: 16, fontSize: '0.9rem' }}>
                                    .json, .yaml, .txt, .js, .py (max 10MB)
                                </p>
                            </div>
                        ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                <textarea
                                    value={textContent}
                                    onChange={(e) => { setTextContent(e.target.value); setError('') }}
                                    placeholder="Paste your agent configuration, system prompt, or workflow definition here..."
                                    style={{
                                        width: '100%', minHeight: 200, padding: 16,
                                        background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)',
                                        borderRadius: 12, color: '#E0E6ED', fontFamily: 'monospace', fontSize: '0.9rem',
                                        resize: 'vertical'
                                    }}
                                />
                                <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
                                    <button
                                        onClick={handleTextSubmit}
                                        disabled={isScanning}
                                        style={{
                                            padding: '12px 32px', borderRadius: 8, cursor: 'pointer',
                                            background: 'linear-gradient(135deg, #00F5FF 0%, #00DBE5 100%)',
                                            border: 'none', color: '#0A1A2F', fontWeight: 700,
                                            boxShadow: '0 4px 12px rgba(0, 245, 255, 0.2)',
                                            display: 'flex', alignItems: 'center', gap: 8
                                        }}
                                    >
                                        {isScanning ? (
                                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ animation: 'spin-slow 1s linear infinite' }}>
                                                <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
                                            </svg>
                                        ) : <FiArrowLeft style={{ transform: 'rotate(180deg)' }} />}
                                        Analyze Text
                                    </button>
                                </div>
                            </div>
                        )}

                        {error && (
                            <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center', color: '#FF3366' }}>
                                <FiAlertCircle size={16} />
                                <span style={{ fontSize: '0.85rem' }}>{error}</span>
                            </div>
                        )}
                    </motion.div>
                ) : (
                    /* ── Files Selected State ── */
                    <motion.div
                        key="selected"
                        initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }}
                        className="glass-card"
                        style={{ padding: '32px 40px', textAlign: 'center' }}
                        {...getRootProps({ onClick: e => e.stopPropagation() })}
                    >
                        <input {...getInputProps()} />

                        {/* Header */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                            <h3 style={{ color: '#fff', fontSize: '1.1rem', fontWeight: 600 }}>
                                {selectedFiles.length} {selectedFiles.length === 1 ? 'file' : 'files'} selected
                            </h3>
                            <button
                                onClick={open}
                                disabled={isScanning}
                                style={{
                                    background: 'rgba(0,245,255,0.1)', border: '1px solid rgba(0,245,255,0.3)',
                                    borderRadius: 8, padding: '8px 16px', cursor: 'pointer', color: '#00F5FF',
                                    fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: 6,
                                }}
                            >
                                <FiPlus size={16} /> Add Files
                            </button>
                        </div>

                        {/* File List */}
                        <div style={{ maxHeight: 300, overflowY: 'auto', marginBottom: 28, display: 'flex', flexDirection: 'column', gap: 12 }}>
                            {selectedFiles.map((file, idx) => {
                                const fileExt = file.name?.split('.').pop()?.toUpperCase() || ''
                                return (
                                    <motion.div
                                        key={`${file.name}-${idx}`}
                                        initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                                        style={{
                                            display: 'flex', alignItems: 'center', gap: 16, padding: '12px',
                                            background: 'rgba(255,255,255,0.03)', borderRadius: 12, border: '1px solid rgba(255,255,255,0.05)'
                                        }}
                                    >
                                        <div style={{
                                            width: 40, height: 40, borderRadius: 8,
                                            background: 'rgba(0,245,255,0.1)', border: '1px solid rgba(0,245,255,0.3)',
                                            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
                                        }}>
                                            <FiFile size={20} color="#00F5FF" />
                                        </div>
                                        <div style={{ textAlign: 'left', flex: 1, overflow: 'hidden' }}>
                                            <p style={{ fontWeight: 600, fontSize: '0.9rem', color: '#E0E6ED', marginBottom: 2, textOverflow: 'ellipsis', whiteSpace: 'nowrap', overflow: 'hidden' }}>{file.name}</p>
                                            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                                <span style={{ fontSize: '0.7rem', color: '#6B7A90' }}>{formatFileSize(file.size)}</span>
                                                <span style={{
                                                    padding: '1px 6px', borderRadius: 4, fontSize: '0.55rem', fontWeight: 700,
                                                    background: 'rgba(0,245,255,0.1)', color: '#00F5FF', border: '1px solid rgba(0,245,255,0.2)',
                                                }}>{fileExt}</span>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => handleRemoveFile(idx)}
                                            disabled={isScanning}
                                            style={{
                                                background: 'transparent', border: 'none',
                                                padding: '8px', cursor: 'pointer', color: '#6B7A90',
                                                transition: 'color 0.2s',
                                            }}
                                            title="Remove file"
                                        >
                                            <FiX size={18} />
                                        </button>
                                    </motion.div>
                                )
                            })}
                        </div>

                        {/* Error Message */}
                        {error && (
                            <div style={{ marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center', color: '#FF3366' }}>
                                <FiAlertCircle size={16} />
                                <span style={{ fontSize: '0.85rem' }}>{error}</span>
                            </div>
                        )}

                        {/* Scan button */}
                        <div style={{ display: 'flex', gap: 12 }}>
                            <button
                                onClick={onClear}
                                disabled={isScanning}
                                style={{
                                    flex: 1, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
                                    borderRadius: 12, padding: '16px', cursor: 'pointer', color: '#B8C5D6', fontSize: '1rem',
                                    fontWeight: 600, transition: 'all 0.2s', maxWidth: 120
                                }}
                            >
                                Clear
                            </button>
                            <button
                                className="btn-primary"
                                onClick={onScan}
                                disabled={isScanning}
                                style={{ flex: 1, fontSize: '1rem', padding: '16px', borderRadius: 12 }}
                            >
                                {isScanning ? (
                                    <span style={{ display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'center' }}>
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ animation: 'spin-slow 1s linear infinite' }}>
                                            <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
                                        </svg>
                                        Scanning {selectedFiles.length} files...
                                    </span>
                                ) : `🔍 Scan ${selectedFiles.length} Files`}
                            </button>
                        </div>

                        <p style={{ marginTop: 14, fontSize: '0.72rem', color: '#6B7A90' }}>
                            Powered by OWASP Top 10 LLM 2025 · Gemini 2.0 Flash · Hybrid Detection
                        </p>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.section>
    )
}

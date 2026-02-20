import { useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import { getRiskColor } from '../utils/formatters'

const SIZE = 280
const CX = SIZE / 2
const CY = SIZE / 2
const R = 110
const STROKE = 22
const START_ANGLE = -220  // degrees (bottom-left)
const END_ANGLE = 40    // degrees (bottom-right)
const TOTAL_ARC = END_ANGLE - START_ANGLE  // 260 degrees

function polarToXY(cx, cy, r, angleDeg) {
    const rad = (angleDeg - 90) * (Math.PI / 180)
    return {
        x: cx + r * Math.cos(rad),
        y: cy + r * Math.sin(rad),
    }
}

function describeArc(cx, cy, r, startDeg, endDeg) {
    const s = polarToXY(cx, cy, r, startDeg)
    const e = polarToXY(cx, cy, r, endDeg)
    const large = endDeg - startDeg > 180 ? 1 : 0
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`
}

// Color zones: 0-39 green, 40-59 orange, 60-79 red, 80-100 deep red
const ZONES = [
    { from: 0, to: 39, color: '#00FF88' },
    { from: 40, to: 59, color: '#FFB800' },
    { from: 60, to: 79, color: '#FF3366' },
    { from: 80, to: 100, color: '#FF0033' },
]

function scoreToAngle(score) {
    return START_ANGLE + (score / 100) * TOTAL_ARC
}

export default function RiskGauge({ score = 0, level = 'Low' }) {
    const needleRef = useRef(null)
    const targetAngle = scoreToAngle(score)
    const riskColor = getRiskColor(level)

    // Needle tip position
    const needleLength = R - STROKE / 2 - 8
    const needleTip = polarToXY(CX, CY, needleLength, targetAngle)

    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
            <svg
                viewBox={`0 0 ${SIZE} ${SIZE}`}
                width={SIZE}
                height={SIZE}
                style={{ filter: `drop-shadow(0 0 20px ${riskColor}40)`, overflow: 'visible' }}
            >
                {/* Background track */}
                <path
                    d={describeArc(CX, CY, R, START_ANGLE, END_ANGLE)}
                    fill="none"
                    stroke="#1A1F3A"
                    strokeWidth={STROKE}
                    strokeLinecap="round"
                />

                {/* Color zone arcs */}
                {ZONES.map((zone, i) => {
                    const zoneStart = scoreToAngle(zone.from)
                    const zoneEnd = scoreToAngle(zone.to)
                    return (
                        <path
                            key={i}
                            d={describeArc(CX, CY, R, zoneStart, zoneEnd)}
                            fill="none"
                            stroke={zone.color}
                            strokeWidth={STROKE}
                            strokeLinecap="butt"
                            opacity={0.35}
                        />
                    )
                })}

                {/* Filled arc up to score */}
                {score > 0 && (
                    <motion.path
                        d={describeArc(CX, CY, R, START_ANGLE, targetAngle)}
                        fill="none"
                        stroke={riskColor}
                        strokeWidth={STROKE}
                        strokeLinecap="round"
                        initial={{ pathLength: 0 }}
                        animate={{ pathLength: 1 }}
                        transition={{ duration: 2, ease: 'easeOut', delay: 0.3 }}
                        style={{ filter: `drop-shadow(0 0 8px ${riskColor})` }}
                    />
                )}

                {/* Tick marks */}
                {[0, 25, 50, 75, 100].map(tick => {
                    const angle = scoreToAngle(tick)
                    const inner = polarToXY(CX, CY, R - STROKE / 2 - 4, angle)
                    const outer = polarToXY(CX, CY, R + STROKE / 2 + 4, angle)
                    const label = polarToXY(CX, CY, R + STROKE / 2 + 18, angle)
                    return (
                        <g key={tick}>
                            <line x1={inner.x} y1={inner.y} x2={outer.x} y2={outer.y}
                                stroke="rgba(255,255,255,0.2)" strokeWidth={1.5} />
                            <text x={label.x} y={label.y} textAnchor="middle" dominantBaseline="middle"
                                fontSize={9} fill="rgba(255,255,255,0.4)" fontFamily="JetBrains Mono, monospace">
                                {tick}
                            </text>
                        </g>
                    )
                })}

                {/* Needle */}
                <motion.line
                    x1={CX} y1={CY}
                    x2={CX} y2={CY - needleLength}
                    stroke="#00F5FF"
                    strokeWidth={3}
                    strokeLinecap="round"
                    style={{ transformOrigin: `${CX}px ${CY}px`, filter: 'drop-shadow(0 0 6px #00F5FF)' }}
                    initial={{ rotate: START_ANGLE }}
                    animate={{ rotate: targetAngle }}
                    transition={{ duration: 2, ease: 'easeOut', delay: 0.3 }}
                />

                {/* Needle center dot */}
                <circle cx={CX} cy={CY} r={8} fill="#00F5FF" style={{ filter: 'drop-shadow(0 0 8px #00F5FF)' }} />
                <circle cx={CX} cy={CY} r={4} fill="#0A0E27" />

                {/* Center score text */}
                <text x={CX} y={CY - 20} textAnchor="middle" fontSize={52} fontWeight={800}
                    fill={riskColor} fontFamily="Inter, sans-serif"
                    style={{ filter: `drop-shadow(0 0 12px ${riskColor})` }}>
                    {score}
                </text>
                <text x={CX} y={CY + 20} textAnchor="middle" fontSize={16} fontWeight={700}
                    fill={riskColor} fontFamily="Inter, sans-serif" letterSpacing="0.05em">
                    {level.toUpperCase()}
                </text>
                <text x={CX} y={CY + 40} textAnchor="middle" fontSize={9}
                    fill="rgba(255,255,255,0.35)" fontFamily="Inter, sans-serif" letterSpacing="0.1em">
                    OWASP RISK ASSESSMENT
                </text>
            </svg>

            {/* Label below */}
            <p style={{ fontSize: '0.72rem', color: '#6B7A90', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                Risk Score / 100
            </p>
        </div>
    )
}

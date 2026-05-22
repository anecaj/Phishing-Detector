import { useEffect, useState } from "react";

export default function RiskGauge({ score, label, color }) {
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    setAnimated(0);
    const timer = setTimeout(() => setAnimated(score), 100);
    return () => clearTimeout(timer);
  }, [score]);

  const radius = 80;
  const cx = 110;
  const cy = 110;
  const circumference = Math.PI * radius; // half circle
  const progress = (animated / 100) * circumference;

  // Arc path: left to right semicircle
  const startX = cx - radius;
  const startY = cy;
  const endX = cx + radius;
  const endY = cy;

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
      <svg width="220" height="130" viewBox="0 0 220 130">
        {/* Background track */}
        <path
          d={`M ${startX} ${startY} A ${radius} ${radius} 0 0 1 ${endX} ${endY}`}
          fill="none"
          stroke="#1e2530"
          strokeWidth="16"
          strokeLinecap="round"
        />
        {/* Colored progress arc */}
        <path
          d={`M ${startX} ${startY} A ${radius} ${radius} 0 0 1 ${endX} ${endY}`}
          fill="none"
          stroke={color || "#4ade80"}
          strokeWidth="16"
          strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          style={{ transition: "stroke-dasharray 0.8s cubic-bezier(0.4,0,0.2,1), stroke 0.4s" }}
        />
        {/* Zone markers */}
        {[0, 45, 75, 100].map((pct, i) => {
          const angle = Math.PI - (pct / 100) * Math.PI;
          const mx = cx + (radius + 12) * Math.cos(angle);
          const my = cy - (radius + 12) * Math.sin(angle);
          return (
            <text key={i} x={mx} y={my} textAnchor="middle" fontSize="9" fill="#4a5568" fontFamily="Space Mono">
              {pct}
            </text>
          );
        })}
        {/* Score */}
        <text x={cx} y={cy - 10} textAnchor="middle" fontSize="36" fontWeight="700" fill={color || "#4ade80"} fontFamily="Space Mono">
          {Math.round(animated)}
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" fontSize="11" fill="#6b7280" fontFamily="DM Sans">
          risk score
        </text>
      </svg>
      <div style={{
        fontSize: 15, fontWeight: 700, letterSpacing: "0.12em",
        color: color || "#4ade80", fontFamily: "Space Mono",
        marginTop: -8,
      }}>
        {label}
      </div>
    </div>
  );
}

export default function HistoryLog({ history, onSelect }) {
  if (history.length === 0) return null;

  const labelColor = (label) => {
    if (label === "PHISHING")   return "#ff4d4d";
    if (label === "SUSPICIOUS") return "#fbbf24";
    return "#4ade80";
  };

  return (
    <div>
      <div style={{ fontSize: 11, color: "#6b7280", fontFamily: "Space Mono", marginBottom: 12, letterSpacing: "0.08em" }}>
        RECENT SCANS
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {history.map((item, i) => (
          <div
            key={i}
            onClick={() => onSelect(item)}
            style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "8px 12px", borderRadius: 8,
              background: "#0d1117", border: "1px solid #1e2530",
              cursor: "pointer", transition: "border-color 0.15s",
            }}
            onMouseEnter={(e) => e.currentTarget.style.borderColor = "#2d3748"}
            onMouseLeave={(e) => e.currentTarget.style.borderColor = "#1e2530"}
          >
            <div style={{
              width: 8, height: 8, borderRadius: "50%",
              background: labelColor(item.label), flexShrink: 0,
            }} />
            <div style={{
              fontSize: 12, color: "#9ca3af", fontFamily: "DM Sans",
              flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>
              {item.url}
            </div>
            <div style={{ fontSize: 11, color: labelColor(item.label), fontFamily: "Space Mono", flexShrink: 0 }}>
              {item.risk_score}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

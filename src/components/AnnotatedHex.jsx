/** Interactive hex byte viewer with TLV-aware colored segments and tooltips. */
import { useState } from "react";
import { h, hexStr } from "../decode.js";
import { SPECS } from "../knowledge.js";
import { C } from "../theme.js";

const styles = {
  container: { fontFamily: "monospace", fontSize: 12, lineHeight: 1.8, padding: "8px 10px" },
  label: { fontSize: 10, color: C.muted, marginBottom: 4, display: "block" },
  byte: (color, hovered) => ({
    display: "inline-block", padding: "1px 3px", borderRadius: 2, cursor: "pointer",
    background: hovered ? (color ?? C.muted) + "33" : "transparent",
    color: color ?? C.muted,
    transition: "background 0.15s",
  }),
  tooltip: {
    position: "absolute", bottom: "100%", left: 0, marginBottom: 6,
    background: "#1a2030", border: `1px solid ${C.teal}55`, borderRadius: 5,
    padding: "6px 10px", fontSize: 10, color: C.text, zIndex: 50,
    minWidth: 180, maxWidth: 340, boxShadow: "0 4px 16px #00000066",
    lineHeight: 1.6, whiteSpace: "pre-wrap",
  },
};

function AnnotatedHex({ segs, label }) {
  const [hover, setHover] = useState(null);

  return (
    <div style={styles.container}>
      {label && <span style={styles.label}>{label}</span>}
      <div style={{ position: "relative" }}>
        {segs.map((seg, si) => (
          <span key={si} style={{ position: "relative", display: "inline" }}
            onMouseEnter={() => setHover(si)} onMouseLeave={() => setHover(null)}>
            {seg.bytes.map((b, bi) => (
              <span key={bi} style={styles.byte(seg.color, hover === si)}>{h(b)} </span>
            ))}
            {hover === si && (
              <div style={styles.tooltip}>
                <div style={{ fontWeight: 700, color: seg.color ?? C.teal, marginBottom: 2 }}>{seg.label}</div>
                {seg.detail && <div style={{ color: C.muted }}>{seg.detail}</div>}
                {seg.field && <div style={{ color: C.dim, fontSize: 9, marginTop: 2 }}>Field: {seg.field}</div>}
              </div>
            )}
          </span>
        ))}
      </div>
    </div>
  );
}

export default AnnotatedHex;

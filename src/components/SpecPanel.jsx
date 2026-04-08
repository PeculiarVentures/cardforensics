/** Specification reference browser for ISO 7816-4, GP, and PIV. */
import { useState, useEffect } from "react";
import { SPEC_DB } from "../knowledge.js";
import { C } from "../theme.js";

const styles = {
  container: { fontSize: 11, borderTop: `1px solid ${C.border}` },
  header: {
    padding: "6px 10px", display: "flex", alignItems: "center", gap: 8,
    cursor: "pointer", userSelect: "none", background: C.surface,
  },
  specCard: {
    padding: "6px 10px 6px 20px", borderBottom: `1px solid ${C.border}`,
    lineHeight: 1.6,
  },
  specName: { color: C.teal, fontWeight: 600 },
  specDesc: { color: C.muted, fontSize: 10, marginTop: 2 },
  link: { color: C.blue, fontSize: 10, textDecoration: "none" },
};

function SpecPanel({ relevantSpecs }) {
  const [collapsed, setCollapsed] = useState(true);
  const [specs, setSpecs] = useState([]);

  useEffect(() => {
    if (!relevantSpecs?.length) return;
    const resolved = relevantSpecs
      .map(entry => {
        const spec = SPEC_DB[entry.key] ?? Object.values(SPEC_DB).find(s => s.key === entry.key);
        return spec ? { ...spec, ref: entry.ref } : null;
      })
      .filter(Boolean);
    setSpecs(resolved);
  }, [relevantSpecs]);

  if (!specs.length) return null;

  return (
    <div style={styles.container}>
      <div style={styles.header} onClick={() => setCollapsed(c => !c)}>
        <span style={{ color: C.teal, fontWeight: 700 }}>📚 Specifications</span>
        <span style={{ color: C.muted }}>{specs.length} relevant</span>
        <span style={{ marginLeft: "auto", color: C.dim }}>{collapsed ? "▶" : "▼"}</span>
      </div>
      {!collapsed && specs.map((spec, i) => (
        <div key={i} style={styles.specCard}>
          <div style={styles.specName}>{spec.name}</div>
          <div style={styles.specDesc}>{spec.description}</div>
          {spec.url && <a href={spec.url} target="_blank" rel="noopener" style={styles.link}>{spec.url}</a>}
        </div>
      ))}
    </div>
  );
}

export default SpecPanel;

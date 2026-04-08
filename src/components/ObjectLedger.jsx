/** Data object access summary: reads, writes, mutations per object. */
import { useState } from "react";
import { C, BG } from "../theme.js";

const CLASS_COLORS = {
  mutated: C.amber,
  present: C.green,
  "access-error": C.red,
  "expected-absent": C.dim,
  probed: C.muted,
};

const styles = {
  container: { fontSize: 11, borderTop: `1px solid ${C.border}` },
  header: {
    padding: "6px 10px", display: "flex", alignItems: "center", gap: 8,
    cursor: "pointer", userSelect: "none", background: C.surface,
  },
  row: (cls) => ({
    display: "flex", alignItems: "center", gap: 8,
    padding: "3px 10px 3px 20px", borderBottom: `1px solid ${C.border}`,
    borderLeft: `2px solid ${CLASS_COLORS[cls] ?? C.dim}`,
  }),
  label: { flex: 1, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  badge: (color) => ({
    fontSize: 9, fontFamily: "monospace", color,
    background: color + "18", border: `1px solid ${color}33`,
    borderRadius: 3, padding: "0 4px", flexShrink: 0,
  }),
};

function ObjectLedger({ ledger }) {
  const [collapsed, setCollapsed] = useState(false);
  if (!ledger?.length) return null;

  const mutated = ledger.filter(e => e.classification === "mutated").length;
  const errors = ledger.filter(e => e.classification === "access-error").length;

  return (
    <div style={styles.container}>
      <div style={styles.header} onClick={() => setCollapsed(c => !c)}>
        <span style={{ color: C.teal, fontWeight: 700 }}>📦 Object Ledger</span>
        <span style={{ color: C.muted }}>{ledger.length} objects</span>
        {mutated > 0 && <span style={styles.badge(C.amber)}>{mutated} mutated</span>}
        {errors > 0 && <span style={styles.badge(C.red)}>{errors} errors</span>}
        <span style={{ marginLeft: "auto", color: C.dim }}>{collapsed ? "▶" : "▼"}</span>
      </div>
      {!collapsed && ledger.map((entry, i) => (
        <div key={i} style={styles.row(entry.classification)}>
          <span style={{ color: C.muted, fontFamily: "monospace", fontSize: 10, width: 70, flexShrink: 0 }}>{entry.id}</span>
          <span style={styles.label}>{entry.label}</span>
          {entry.reads.ok > 0 && <span style={styles.badge(C.green)}>R:{entry.reads.ok}</span>}
          {entry.reads.fail > 0 && <span style={styles.badge(C.red)}>R✗:{entry.reads.fail}</span>}
          {entry.writes.ok > 0 && <span style={styles.badge(C.amber)}>W:{entry.writes.ok}</span>}
          {entry.size && <span style={{ color: C.dim, fontSize: 9 }}>{entry.size}B</span>}
        </div>
      ))}
    </div>
  );
}

export default ObjectLedger;

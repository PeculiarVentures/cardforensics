/** Collapsible session group with time range, error count, and API operations. */
import { decodeCmd, decodeRsp, INS_MAP, h } from "../decode.js";
import { autoAnnotate, translateToAPI } from "../analysis/index.js";
import { C, BTN, BG } from "../theme.js";
import ExchangeRow from "./ExchangeRow.jsx";

const styles = {
  header: {
    position: "sticky", top: 0, zIndex: 9,
    background: "#131a28",
    borderBottom: `1px solid ${C.borderHi}`,
    cursor: "pointer", userSelect: "none",
  },
  headerRow: {
    padding: "6px 12px", display: "flex", alignItems: "center", gap: 10,
  },
  colorBar: (color) => ({ width: 3, alignSelf: "stretch", background: color, borderRadius: "2px 0 0 2px", flexShrink: 0 }),
  sessionLabel: (color) => ({ color, fontWeight: 700, fontSize: 12, fontFamily: "monospace" }),
  summary: {
    padding: "4px 16px 6px",
    color: C.text, fontSize: 11, lineHeight: 1.6,
    background: "#131a28",
  },
  summaryWarn: {
    padding: "4px 16px 6px",
    color: "#8899bb", fontSize: 11, fontStyle: "italic",
    background: "#131a28",
  },
  opsRow: {
    padding: "4px 16px 6px",
    background: "#131a28",
    display: "flex", flexWrap: "wrap", gap: 4, alignItems: "center",
    borderBottom: `1px solid ${C.border}`,
  },
  opsLabel: { fontSize: 9, color: C.muted, marginRight: 4, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.3px" },
  opBadge: {
    fontSize: 9, fontFamily: "monospace", color: C.teal,
    background: C.teal + "11", border: `1px solid ${C.teal}33`,
    borderRadius: 3, padding: "1px 5px", whiteSpace: "nowrap",
  },
};

function SessionBlock({ session, si, color, label, meta, isCollapsed, onToggle, filters, annotations, selected, onSelect, protocolStates, integrity, groupLabel }) {
  const t0 = session[0]?.cmd.ts.split(" ")[1].substring(0, 8);
  const t1 = session[session.length - 1]?.cmd.ts.split(" ")[1].substring(0, 8);
  const errCount = session.filter(ex => {
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    return rsp && rsp.sw !== 0x9000 && rsp.sw >= 0x6000;
  }).length;

  const filtered = session.filter(ex => {
    try {
      const cmd = decodeCmd(ex.cmd.bytes);
      const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
      if (filters.errorsOnly) { const sw = rsp?.sw ?? 0; if (sw === 0x9000 || (sw >> 8) === 0x61) return false; }
      if (filters.hideGetData && (cmd?.ins === 0xCB || cmd?.ins === 0xCA)) return false;
      if (filters.search) {
        const q = filters.search.toLowerCase();
        const ins = cmd ? (INS_MAP[cmd.ins] ?? h(cmd.ins)) : "";
        const ann = autoAnnotate(ex, protocolStates?.[ex.id]);
        if (!ins.toLowerCase().includes(q) && !ann?.note?.toLowerCase().includes(q) && !ex.cmd.hex.includes(q)) return false;
      }
      return true;
    } catch { return true; }
  });

  return (
    <div>
      {/* Sticky session header — minimal, just title and stats */}
      <div onClick={onToggle} style={styles.header}>
        <div style={styles.headerRow}>
          <div style={styles.colorBar(color)} />
          <span style={styles.sessionLabel(color)}>{groupLabel} {si + 1}</span>
          {meta && <span style={{ color: C.muted, fontSize: 11 }}>{meta.label}</span>}
          <span style={{ color: "#8899bb", fontSize: 11 }}>{t0}–{t1}</span>
          <span style={{ color: "#8899bb", fontSize: 11 }}>
            {filtered.length < session.length
              ? <><span style={{ color: C.amber }}>{filtered.length}</span>/{session.length} exchanges</>
              : <>{session.length} exchanges</>}
          </span>
          {errCount > 0 && <span style={{ color: C.red, fontSize: 10, fontFamily: "monospace" }}>{errCount} errors</span>}
          <span style={{ marginLeft: "auto", color: "#8899bb", fontSize: 11 }}>{isCollapsed ? "\u25B6" : "\u25BC"}</span>
        </div>
      </div>

      {/* Expanded: summary + ops card, then exchange rows */}
      {!isCollapsed && (
        <div>
          <div style={{ background: "#131a28", borderBottom: `1px solid ${C.border}` }}>
            {meta
              ? <div style={styles.summary}>{meta.summary}</div>
              : integrity?.confidence !== "high" && <div style={styles.summaryWarn}>Partial context — per-exchange annotations are accurate, session intent cannot be fully determined</div>
            }
            {(() => {
              const ops = translateToAPI(session, protocolStates);
              if (!ops.length) return null;
              return (
                <div style={styles.opsRow}>
                  <span style={styles.opsLabel}>Operations:</span>
                  {ops.map((op, i) => <span key={i} title={op.detail} style={styles.opBadge}>{op.icon} {op.label}</span>)}
                </div>
              );
            })()}
          </div>
          {filtered.length === 0 && <div style={{ padding: "8px 12px", color: "#8899bb", fontSize: 11, fontStyle: "italic" }}>No exchanges match current filters</div>}
          {filtered.map(ex => (
            <ExchangeRow key={ex.id} ex={ex} annotation={annotations[ex.id]} selected={selected?.id === ex.id} onSelect={onSelect} protocolState={protocolStates[ex.id]} />
          ))}
        </div>
      )}
    </div>
  );
}

export default SessionBlock;

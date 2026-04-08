/** Single APDU exchange row: timestamp, CLA, INS, status word, annotation. */
import { useRef, useEffect } from "react";
import { decodeCmd, decodeRsp, INS_MAP, lookupSW, descCLA, h, execDeltaMs } from "../decode.js";
import { C, swColor, BG } from "../theme.js";

const styles = {
  row: (selected, isErr) => ({
    borderBottom: `1px solid ${C.border}`,
    background: selected ? BG.selected : isErr ? BG.errorRow : "transparent",
    transition: "background 0.15s",
    cursor: "pointer",
  }),
  cmdLine: {
    display: "flex", alignItems: "center", gap: 8,
    padding: "5px 12px", fontFamily: "monospace", fontSize: 12,
  },
  rspLine: {
    display: "flex", alignItems: "center", gap: 8,
    padding: "3px 12px 4px", fontFamily: "monospace", fontSize: 12,
  },
  timestamp: { color: C.muted, width: 78, flexShrink: 0, fontSize: 11 },
  deltaMs: { fontSize: 8, color: C.dim, opacity: 0.6 },
  cmdTag: { color: C.blue, flexShrink: 0, fontSize: 11 },
  rspTag: { color: C.green, flexShrink: 0, fontSize: 11 },
  claBadge: {
    fontSize: 9, padding: "1px 5px", borderRadius: 3,
    background: C.purple + "22", color: C.purple,
    border: `1px solid ${C.purple}44`,
    fontFamily: "monospace", whiteSpace: "nowrap", flexShrink: 0,
  },
  insName: { color: "#fff", fontWeight: 600, flexShrink: 0 },
  params: { color: C.muted, flexShrink: 0 },
  hex: { color: C.dim, fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  chainBadge: {
    fontSize: 9, color: C.teal, border: `1px solid ${C.teal}44`,
    borderRadius: 3, padding: "1px 5px", flexShrink: 0,
  },
  annotation: (flag) => ({
    padding: "3px 12px 3px 100px",
    background: flag === "bug" ? BG.error : flag === "key" ? BG.key : flag === "expected" ? "#111114" : BG.warn,
    borderLeft: `2px solid ${flag === "bug" ? C.red : flag === "key" ? C.green : flag === "expected" ? C.dim : C.amber}`,
    color: flag === "bug" ? C.red : flag === "key" ? C.green : flag === "expected" ? C.dim : C.amber,
    fontSize: 11, fontFamily: "sans-serif",
  }),
};

function ExchangeRow({ ex, annotation, selected, onSelect, protocolState }) {
  const rowRef = useRef(null);
  const cmd = decodeCmd(ex.cmd.bytes);
  const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
  const swInfo = rsp ? lookupSW(rsp.sw) : null;
  const statusColor = swInfo ? swColor(swInfo.s) : C.muted;
  const isErr = swInfo?.s === "err";

  useEffect(() => {
    if (selected && rowRef.current) rowRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [selected]);

  return (
    <div id={`exch-row-${ex.id}`} ref={rowRef} onClick={() => onSelect(ex)} style={styles.row(selected, isErr)}>
      {/* Command line */}
      <div style={styles.cmdLine}>
        <span style={styles.timestamp}>
          {ex.cmd.ts.split(" ")[1].substring(0, 12)}
          {(() => { const dt = execDeltaMs(ex); return dt !== null ? <span style={styles.deltaMs}>{dt}ms</span> : null; })()}
        </span>
        {protocolState?.authenticated && <span title={`${protocolState.scp ?? "SCP"} session active (inferred)`} style={{ fontSize: 9, color: C.green, flexShrink: 0 }}>🔒</span>}
        {protocolState?.phase && <span style={{ fontSize: 9, color: C.dim, flexShrink: 0, border: `1px solid ${C.border}`, borderRadius: 3, padding: "0 4px" }} title={protocolState.phase}>{protocolState.phase.split(" ").map(w => w[0]).join("").toUpperCase()}</span>}
        <span style={styles.cmdTag}>▶ CMD</span>
        <span style={styles.claBadge}>{cmd ? descCLA(cmd.cla) : "?"}</span>
        <span style={styles.insName}>{cmd ? (INS_MAP[cmd.ins] || `${h(cmd.ins)}`) : ""}</span>
        {cmd && <span style={styles.params}>P1={h(cmd.p1)} P2={h(cmd.p2)}</span>}
        {cmd?.lc != null && <span style={{ color: C.dim, flexShrink: 0 }}>Lc={cmd.lc}</span>}
        <span style={styles.hex}>{ex.cmd.hex}</span>
      </div>

      {/* Response line */}
      {rsp && (
        <div style={styles.rspLine}>
          <span style={{ width: 78, flexShrink: 0 }} />
          <span style={styles.rspTag}>◀ RSP</span>
          <span style={{ color: statusColor, fontWeight: 700, flexShrink: 0 }}>{h(rsp.sw1)}{h(rsp.sw2)}</span>
          <span style={{ color: statusColor, fontSize: 11, flexShrink: 0 }}>{swInfo?.msg}</span>
          {rsp.data.length > 0 && <span style={{ color: C.muted, fontSize: 11, flexShrink: 0 }}>{rsp.data.length}B</span>}
          {ex.continuations > 0 && <span title={`Assembled from ${ex.continuations + 1} chunks via GET RESPONSE`} style={styles.chainBadge}>⛓ {ex.continuations + 1} chunks</span>}
        </div>
      )}

      {/* Annotation */}
      {annotation && <div style={styles.annotation(annotation.flag)}>✦ {annotation.note}</div>}
    </div>
  );
}

export default ExchangeRow;

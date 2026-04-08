/** Full exchange inspector with annotated hex, AI analysis, and SCP03 decryption. */
import { useState, useMemo, useEffect } from "react";
import { decodeCmd, decodeRsp, INS_MAP, h, hexStr, lookupSW, execDeltaMs } from "../decode.js";
import { autoAnnotate } from "../analysis/index.js";
import { buildCmdSegs, buildRspSegs } from "../tlv.js";
import { unwrapSCP03 } from "../crypto.js";
import { callClaude, buildExchangePrompt } from "../ai.js";
import { C, BG } from "../theme.js";
import AnnotatedHex from "./AnnotatedHex.jsx";
import ExchangeDecoders from "./ExchangeDecoders.jsx";
import CertViewer from "./CertViewer.jsx";

const styles = {
  container: { overflowY: "auto", flex: 1, background: C.bg },
  header: { padding: "8px 12px", borderBottom: `1px solid ${C.border}`, background: C.surface },
  headerTitle: { fontWeight: 700, color: C.text, fontSize: 13, fontFamily: "monospace" },
  meta: { display: "flex", gap: 12, marginTop: 4, fontSize: 10, color: C.muted, fontFamily: "monospace" },
  annotation: (flag) => ({
    padding: "6px 12px", fontSize: 11,
    borderLeft: `3px solid ${flag === "bug" ? C.red : flag === "key" ? C.green : C.amber}`,
    background: flag === "bug" ? BG.error : flag === "key" ? BG.key : BG.warn,
    color: flag === "bug" ? C.red : flag === "key" ? C.green : C.amber,
  }),
  aiSection: { padding: "8px 12px", background: BG.aiSection, borderBottom: `1px solid ${C.border}` },
  aiLabel: { color: C.purple, fontWeight: 700, fontSize: 10, marginBottom: 4 },
  aiText: { color: C.text, fontSize: 11, lineHeight: 1.6, whiteSpace: "pre-wrap" },
  decryptSection: { padding: "8px 12px", background: BG.key, borderBottom: `1px solid ${C.border}` },
};

function ExchangeDetail({ ex, onClose, protocolState, exchanges, aiCache, lazyDone, keyCheck }) {
  const cmd = decodeCmd(ex.cmd.bytes);
  const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
  const ann = autoAnnotate(ex, protocolState);
  const swInfo = rsp ? lookupSW(rsp.sw) : null;
  const cmdSegs = useMemo(() => buildCmdSegs(ex.cmd.bytes), [ex]);
  const rspSegs = useMemo(() => rsp ? buildRspSegs(ex.rsp.bytes) : [], [ex]);
  const dt = execDeltaMs(ex);

  // AI per-exchange analysis
  const [aiNote, setAiNote] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  useEffect(() => {
    const cached = aiCache?.current?.get(ex.id);
    if (cached) { setAiNote(cached); return; }
    setAiNote(null);
  }, [ex.id, lazyDone]);

  const requestAI = async () => {
    setAiLoading(true);
    try {
      const prompt = buildExchangePrompt(ex, protocolState, exchanges);
      const result = await callClaude(prompt, "You are a smart card forensics expert.");
      setAiNote(result);
      aiCache?.current?.set(ex.id, result);
    } catch (e) { setAiNote(`Error: ${e.message}`); }
    setAiLoading(false);
  };

  // SCP03 decryption attempt
  const [decrypted, setDecrypted] = useState(null);
  useEffect(() => {
    setDecrypted(null);
    if (!protocolState?.authenticated || !rsp?.data?.length || !keyCheck?.sessionKeys) return;
    (async () => {
      try {
        const plain = await unwrapSCP03(rsp.data, keyCheck.sessionKeys.sEnc);
        if (plain) setDecrypted(hexStr(plain));
      } catch { /* decryption failed, expected for non-encrypted data */ }
    })();
  }, [ex.id]);

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <span style={styles.headerTitle}>Exchange #{ex.id}</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 16 }}>✕</button>
        </div>
        <div style={styles.meta}>
          <span>{ex.cmd.ts}</span>
          {cmd && <span>{INS_MAP[cmd.ins] ?? `INS ${h(cmd.ins)}`}</span>}
          {swInfo && <span style={{ color: swInfo.s === "ok" ? C.green : C.red }}>{h(rsp.sw1)}{h(rsp.sw2)} {swInfo.msg}</span>}
          {dt !== null && <span>{dt}ms</span>}
          {protocolState?.authenticated && <span style={{ color: C.green }}>🔒 {protocolState.scp}</span>}
        </div>
      </div>

      {/* Annotation */}
      {ann && <div style={styles.annotation(ann.flag)}>✦ {ann.note}</div>}

      {/* AI analysis — top of detail to explain what we're looking at */}
      <div style={styles.aiSection}>
        <div style={styles.aiLabel}>✦ AI Analysis</div>
        {aiNote
          ? <div style={styles.aiText}>{aiNote}</div>
          : aiLoading
            ? <div style={{ color: C.dim }}>Analyzing…</div>
            : <button onClick={requestAI} style={{ fontSize: 10, color: C.purple, background: "transparent", border: `1px solid ${C.purple}44`, borderRadius: 3, padding: "2px 8px", cursor: "pointer" }}>Analyze this exchange</button>
        }
      </div>

      {/* Decoders (CPLC, key set, CCC, CHUID, X.509 cert) */}
      <ExchangeDecoders ex={ex} />
      <CertViewer ex={ex} />

      {/* Annotated hex */}
      <AnnotatedHex segs={cmdSegs} label="Command" />
      {rspSegs.length > 0 && <AnnotatedHex segs={rspSegs} label="Response" />}

      {/* SCP03 decryption */}
      {decrypted && (
        <div style={styles.decryptSection}>
          <div style={{ color: C.green, fontWeight: 700, fontSize: 10, marginBottom: 4 }}>SCP03 Decrypted</div>
          <div style={{ color: C.text, fontFamily: "monospace", fontSize: 11, wordBreak: "break-all" }}>{decrypted}</div>
        </div>
      )}
    </div>
  );
}

export default ExchangeDetail;

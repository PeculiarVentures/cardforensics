/**
 * Animated APDU sequence diagram with playback controls.
 * Shows HOST to CARD message flow with CSS arrow animations.
 * Waits for AI annotation before advancing in play mode.
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { decodeCmd, decodeRsp, INS_MAP, lookupSW, descCLA, h } from "../decode.js";
import { autoAnnotate } from "../analysis/index.js";
import { C, BTN, ACTOR } from "../theme.js";

const styles = {
  container: { background: "#080b11", borderBottom: `1px solid ${C.border}`, flexShrink: 0, overflow: "hidden" },
  toolbar: { display: "flex", alignItems: "center", gap: 5, padding: "5px 10px" },
  counter: { color: C.muted, fontSize: 10, minWidth: 50 },
  sessionBadge: (color) => ({ fontSize: 9, padding: "1px 5px", border: `1px solid ${color}44`, borderRadius: 8, color }),
  cmdSummary: { fontSize: 9, color: C.dim, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 },
  speedBtn: (active) => ({
    ...BTN, fontSize: 9, padding: "2px 5px",
    background: active ? C.purple + "33" : "transparent",
    border: `1px solid ${active ? C.purple : C.border}`,
    color: active ? C.purple : C.muted,
  }),
  diagramArea: { display: "flex", alignItems: "center", height: 90, cursor: "pointer", padding: "0 10px" },
  lane: { flex: 1, position: "relative", height: "100%", display: "flex", flexDirection: "column", justifyContent: "center", gap: 10, padding: "0 4px" },
  clickToStart: {
    position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center",
    color: C.dim, fontSize: 11, fontFamily: "monospace", letterSpacing: 1, pointerEvents: "none",
  },
  scrubber: { margin: "0 10px 8px", position: "relative", height: 18, cursor: "pointer" },
  scrubTrack: { position: "absolute", top: 4, left: 0, right: 0, height: 8, background: C.border, borderRadius: 4 },
  scrubThumb: (pct, playing) => ({
    position: "absolute", top: 2, width: 3, height: 12, background: C.text,
    borderRadius: 2, transform: "translateX(-50%)",
    left: `${pct}%`, transition: playing ? "left 0.1s linear" : "none",
  }),
};

function SequenceReplay({ exchanges, sessions, sessionAnalysis, onSelect, aiCache }) {
  const [idx, setIdx]         = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed]     = useState(1);
  const [showDiagram, setShowDiagram] = useState(true);
  const [animKey, setAnimKey] = useState(0);
  const [hasStarted, setHasStarted] = useState(false);
  const [waitingForAI, setWaitingForAI] = useState(false);
  const timerRef = useRef(null);

  const CMD_MS = Math.round(650 / speed);
  const RSP_MS = Math.round(500 / speed);
  const ANIM_MS = CMD_MS + RSP_MS + 150;

  // Current exchange decoding
  const ex = exchanges[idx] ?? null;
  const cmd = ex ? decodeCmd(ex.cmd.bytes) : null;
  const rsp = ex?.rsp ? decodeRsp(ex.rsp.bytes) : null;
  const sw = rsp?.sw ?? 0;
  const ann = ex ? autoAnnotate(ex) : null;
  const swInfo = rsp ? lookupSW(sw) : null;
  const sessionIdx = sessions.findIndex(s => s.some(e => e.id === ex?.id));
  const sessionColor = [C.teal, C.amber, C.red, C.green][sessionIdx] ?? C.teal;
  const sessionLabel = sessionAnalysis?.[sessionIdx]?.label ?? `Session ${sessionIdx + 1}`;

  // Arrow colors
  const cmdColor = ann?.flag === "bug" ? C.red : C.blue;
  const rspColor = sw === 0x9000 ? C.green : sw >= 0x6000 ? C.red : C.amber;

  // Labels
  const cmdLabel = ann?.note
    ? ann.note.replace(/ [→].*$/, "").substring(0, 54)
    : `${cmd ? (INS_MAP[cmd.ins] || `INS ${h(cmd.ins)}`) : "?"}${cmd?.lc ? ` · ${cmd.lc}B` : ""}`;
  const rspLabel = (() => {
    if (!rsp) return "";
    const swStr = `${h(rsp.sw1)}${h(rsp.sw2)}`;
    if (sw === 0x9000) {
      if (!rsp.data.length) return `${swStr} · Acknowledged`;
      if (cmd?.ins === 0x87) return `${swStr} · Cryptogram accepted`;
      if (cmd?.ins === 0xDB) return `${swStr} · Written`;
      if (cmd?.ins === 0xA4) return `${swStr} · App selected`;
      return `${swStr} · ${rsp.data.length}B`;
    }
    if (sw === 0x6A82) return `${swStr} · Not found`;
    if (sw === 0x6881) return `${swStr} · Channel required`;
    return `${swStr} · ${swInfo?.msg ?? ""}`;
  })();

  // Playback engine
  useEffect(() => {
    clearTimeout(timerRef.current);
    if (!playing) { setWaitingForAI(false); return; }
    const advance = () => {
      setWaitingForAI(false);
      const next = idx + 1;
      if (next < exchanges.length) { setIdx(next); setAnimKey(k => k + 1); }
      else setPlaying(false);
    };
    const waitForAI = () => {
      const exId = exchanges[idx]?.id;
      if (!aiCache || aiCache.current.has(exId)) {
        setWaitingForAI(false);
        timerRef.current = setTimeout(advance, 1800);
      } else {
        setWaitingForAI(true);
        timerRef.current = setTimeout(waitForAI, 150);
      }
    };
    timerRef.current = setTimeout(waitForAI, ANIM_MS);
    return () => clearTimeout(timerRef.current);
  }, [playing, idx, ANIM_MS, exchanges.length]);

  useEffect(() => { if (hasStarted) onSelect?.(exchanges[idx] ?? null); }, [idx, hasStarted]);

  const goTo = useCallback((i) => {
    clearTimeout(timerRef.current);
    setIdx(Math.max(0, Math.min(i, exchanges.length - 1)));
    setAnimKey(k => k + 1);
    setHasStarted(true);
  }, [exchanges.length]);

  const togglePlay = useCallback(() => { setHasStarted(true); setPlaying(p => !p); }, []);

  // Session bands for scrubber
  const totalEx = exchanges.length;
  let cum = 0;
  const bands = sessions.map((s, si) => {
    const start = cum / totalEx, width = s.length / totalEx;
    cum += s.length;
    return { start, width, color: [C.teal, C.amber, C.red, C.green][si] ?? C.teal };
  });

  const animVars = { "--cmd-ms": `${CMD_MS}ms`, "--rsp-ms": `${RSP_MS}ms`, "--rsp-delay": `${CMD_MS}ms` };
  const thumbPct = (idx / Math.max(1, exchanges.length - 1)) * 100;

  return (
    <div style={styles.container}>
      {/* Toolbar */}
      <div style={styles.toolbar}>
        <button onClick={() => goTo(0)} style={BTN} title="Reset">⏮</button>
        <button onClick={() => goTo(idx - 1)} style={BTN}>◀</button>
        <button onClick={togglePlay} style={{ ...BTN, minWidth: 26, color: playing ? C.amber : C.green }}>{playing ? "⏸" : "▶"}</button>
        <button onClick={() => goTo(idx + 1)} style={BTN}>▶</button>
        <span style={styles.counter}>{idx + 1}/{exchanges.length}</span>
        {sessionIdx >= 0 && <span style={styles.sessionBadge(sessionColor)}>{sessionLabel}</span>}
        <span style={styles.cmdSummary}>
          {waitingForAI ? <span style={{ color: C.purple }}>✦ waiting for analysis…</span> : cmdLabel}
        </span>
        <div style={{ display: "flex", gap: 2, marginLeft: "auto" }}>
          {[0.5, 1, 2, 4].map(s => <button key={s} onClick={() => setSpeed(s)} style={styles.speedBtn(speed === s)}>{s}×</button>)}
          <button onClick={() => setShowDiagram(d => !d)} style={{ ...BTN, fontSize: 9, padding: "2px 5px", marginLeft: 4, color: C.dim }} title="Toggle diagram">{showDiagram ? "▲" : "▼"}</button>
        </div>
      </div>

      {/* Diagram */}
      {showDiagram && (
        <>
          <div onClick={togglePlay} style={styles.diagramArea}>
            <div style={{ ...ACTOR, borderColor: cmdColor + "55" }}><div style={{ fontSize: 18 }}>🖥</div><div style={{ color: cmdColor, fontWeight: 700, fontSize: 9, fontFamily: "monospace" }}>HOST</div><div style={{ color: C.dim, fontSize: 7 }}>CryptoTokenKit</div></div>
            <div key={animKey} className={hasStarted ? "apdu-lane" : ""} style={{ ...styles.lane, ...animVars }}>
              {!hasStarted && <div style={styles.clickToStart}>▶ click to start</div>}
              <div style={{ position: "relative", height: 22, opacity: hasStarted ? 1 : 0 }}>
                <div className="apdu-cmd-line" style={{ position: "absolute", top: 10, left: 0, right: 8, height: 2, background: cmdColor, transformOrigin: "left", transform: "scaleX(0)" }} />
                <div className="apdu-cmd-head" style={{ position: "absolute", top: 5, right: 0, borderTop: "6px solid transparent", borderBottom: "6px solid transparent", borderLeft: `9px solid ${cmdColor}`, opacity: 0 }} />
                <div className="apdu-cmd-label" style={{ position: "absolute", top: -10, left: 0, right: 0, textAlign: "center", color: cmdColor, fontSize: 10, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", opacity: 0 }}>{cmdLabel}</div>
              </div>
              <div style={{ position: "relative", height: 22, opacity: hasStarted ? 1 : 0 }}>
                <div className="apdu-rsp-line" style={{ position: "absolute", top: 10, left: 8, right: 0, height: 2, background: rspColor, transformOrigin: "right", transform: "scaleX(0)" }} />
                <div className="apdu-rsp-head" style={{ position: "absolute", top: 5, left: 0, borderTop: "6px solid transparent", borderBottom: "6px solid transparent", borderRight: `9px solid ${rspColor}`, opacity: 0 }} />
                <div className="apdu-rsp-label" style={{ position: "absolute", bottom: -12, left: 0, right: 0, textAlign: "center", color: rspColor, fontSize: 10, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", opacity: 0 }}>{rspLabel}</div>
              </div>
            </div>
            <div style={{ ...ACTOR, borderColor: rspColor + "55" }}><div style={{ fontSize: 18 }}>💳</div><div style={{ color: rspColor, fontWeight: 700, fontSize: 9, fontFamily: "monospace" }}>CARD</div><div style={{ color: C.dim, fontSize: 7 }}>smart card</div></div>
          </div>

          {/* Scrubber */}
          <div style={styles.scrubber} onClick={(e) => { const rect = e.currentTarget.getBoundingClientRect(); goTo(Math.round(((e.clientX - rect.left) / rect.width) * (exchanges.length - 1))); }}>
            <div style={styles.scrubTrack} />
            {bands.map((b, i) => <div key={i} style={{ position: "absolute", top: 4, height: 8, left: `${b.start * 100}%`, width: `${b.width * 100}%`, background: b.color + "44", borderRadius: 2 }} />)}
            <div style={styles.scrubThumb(thumbPct, playing)} />
          </div>
        </>
      )}
    </div>
  );
}

export default SequenceReplay;

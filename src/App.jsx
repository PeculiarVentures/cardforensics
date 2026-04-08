/**
 * CardForensics root component.
 *
 * Responsibilities:
 *   - Drag-and-drop file loading with APDU format validation
 *   - Memoized synchronous analysis pipeline (parse → decode → annotate)
 *   - Async AI pipeline: batch annotation → session summary (in that order)
 *   - Hybrid storage caching (artifact sandbox or localStorage fallback)
 *   - Three-screen flow: drop page → analysis loading → split-pane viewer
 *   - Export modal with copy-to-clipboard
 */
import { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { storage, isSandbox } from "./storage.js";
import { getApiConfig } from "./components/ApiConfig.jsx";
import { traceHash, parseEntries, buildExchanges, decodeCmd, decodeRsp, h, hexStr, INS_MAP, extractATR } from "./decode.js";
import { groupSessions, buildProtocolStates } from "./protocol.js";
import {
  analyzeIntegrity, classifyErrors, checkCertProvisioning, identifyCard,
  computeComplianceProfile, computeSecurityScore, buildObjectLedger,
  analyzeThreats, autoAnnotate,
} from "./analysis/index.js";
import { checkKnownKeys } from "./crypto.js";
import { buildSessionPrompt, callClaude, extractJSON, analyzeBatch, MODEL, SESSION_MODEL } from "./ai.js";
import { buildForensicExport } from "./export.js";
import { INS_SPECS } from "./knowledge.js";
import { C, BTN, SESSION_COLORS } from "./theme.js";
import {
  SequenceReplay, AISessionSummary, FindingsPanel,
  FilterBar, SessionBlock, ExchangeDetail, ObjectLedger, SpecPanel, ApiConfig,
} from "./components/index.js";

export default function APDUViewer() {
  // Single trace state: { name, log } or null.
  // Replaces traceId + customTrace from the original.
  const [trace, setTrace]       = useState(null);
  const [selected, setSelected] = useState(null);
  const [collapsed, setCollapsed] = useState({});
  const [filters, setFilters]   = useState({ errorsOnly: false, hideGetData: false, search: "" });
  const [keyCheck, setKeyCheck] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [rightTab, setRightTab] = useState("detail");
  const [cardTip, setCardTip] = useState(false);
  const [splitPct, setSplitPct] = useState(42);
  const [splitDragging, setSplitDragging] = useState(false);
  const splitRef = useRef(null);
  const fileInputRef = useRef(null);
  const [exportModal, setExportModal] = useState(null);
  const [exportCopied, setExportCopied] = useState(false);
  const aiCache = useRef(new Map());
  const [aiSessions, setAiSessions]             = useState(null);
  const [aiSessionsLoading, setAiSessionsLoading] = useState(false);
  const [aiSessionsError, setAiSessionsError]   = useState(null);
  const [aiSessionsWarning, setAiSessionsWarning] = useState(null);
  const [aiTraceMeta, setAiTraceMeta]           = useState(null);
  const [lazyDone, setLazyDone]                 = useState(0);
  const [batchComplete, setBatchComplete]       = useState(false);
  const [viewResults, setViewResults]           = useState(false);
  const lazyRef = useRef({ running: false, aborted: false });

  // Hash-based stable cache keys — survives re-drops of same file.
  const cacheKey      = trace ? traceHash(trace.log) : null;
  const STORAGE_CACHE = cacheKey ? `apdu-cache-${cacheKey}` : null;
  const STORAGE_META  = cacheKey ? `apdu-meta-${cacheKey}`  : null;

  const entries         = useMemo(() => trace ? parseEntries(trace.log) : [], [trace]);
  const traceATR        = useMemo(() => trace ? extractATR(trace.log) : null, [trace]);
  const exchanges       = useMemo(() => buildExchanges(entries), [entries]);
  const sessions        = useMemo(() => groupSessions(exchanges), [exchanges]);
  const integrity       = useMemo(() => analyzeIntegrity(exchanges, sessions), [exchanges, sessions]);
  const errorProfile    = useMemo(() => classifyErrors(exchanges), [exchanges]);
  const cardId          = useMemo(() => identifyCard(exchanges, traceATR), [exchanges, traceATR]);
  const complianceProfile = useMemo(() => computeComplianceProfile(exchanges), [exchanges]);
  const protocolStates  = useMemo(() => buildProtocolStates(exchanges), [exchanges]);
  const objectLedger    = useMemo(() => buildObjectLedger(exchanges, protocolStates), [exchanges, protocolStates]);
  const certProvision   = useMemo(() => checkCertProvisioning(exchanges, objectLedger), [exchanges, objectLedger]);
  const protocolStatesRef = useRef(protocolStates);
  useEffect(() => { protocolStatesRef.current = protocolStates; }, [protocolStates]);

  const annotations = useMemo(() => {
    const out = {};
    for (const ex of exchanges) { const a = autoAnnotate(ex, protocolStates[ex.id]); if (a) out[ex.id] = a; }
    return out;
  }, [exchanges, protocolStates]);

  const securityScore = useMemo(
    () => computeSecurityScore(keyCheck, integrity, errorProfile, certProvision, exchanges, protocolStates),
    [keyCheck, integrity, errorProfile, certProvision, exchanges, protocolStates]
  );
  const activeThreats = useMemo(
    () => analyzeThreats(exchanges, protocolStates, integrity),
    [exchanges, protocolStates, integrity]
  );

  // Reset all derived state when trace changes.
  useEffect(() => {
    setSelected(null);
    setCollapsed({});
    aiCache.current.clear();
    setAiSessions(null);
    setAiSessionsWarning(null);
    setAiTraceMeta(null);
    setAiSessionsError(null);
    lazyRef.current.aborted = true;
    setBatchComplete(false);
    setViewResults(false);
    setKeyCheck(null);
    setLazyDone(0);

    if (!trace || !STORAGE_CACHE || !STORAGE_META) return;
    (async () => {
      try {
        const cached = await storage.get(STORAGE_CACHE).catch(() => null);
        if (cached?.value) {
          const data = JSON.parse(cached.value);
          for (const [id, text] of Object.entries(data)) aiCache.current.set(Number(id), text);
        }
        const meta = await storage.get(STORAGE_META).catch(() => null);
        if (meta?.value) {
          const { sessions: s, traceMeta } = JSON.parse(meta.value);
          if (s) setAiSessions(s);
          if (traceMeta) setAiTraceMeta(traceMeta);
        }
      } catch (e) {}
    })();
  }, [trace]);

  // File drop handler.
  const handleDrop = useCallback((e) => {
    e.preventDefault(); setDragOver(false);
    const file = e.dataTransfer.files[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target.result;
      if (!text.includes("APDU ->") && !text.includes("APDU <-")) {
        alert("No APDU lines found. Expected macOS CryptoTokenKit log format."); return;
      }
      setTrace({ name: file.name, log: text });
    };
    reader.readAsText(file);
  }, []);

  // File browse handler (hidden input).
  const handleBrowse = useCallback((e) => {
    const file = e.target.files?.[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target.result;
      if (!text.includes("APDU ->") && !text.includes("APDU <-")) {
        alert("No APDU lines found. Expected macOS CryptoTokenKit log format."); return;
      }
      setTrace({ name: file.name, log: text });
    };
    reader.readAsText(file);
    e.target.value = "";
  }, []);

  // Check if AI is available (sandbox with proxy, or standalone with API key)
  const aiAvailable = isSandbox() || (getApiConfig()?.apiKey?.length > 0);

  // Batch AI analysis loop — runs after trace loads (only if AI is available).
  useEffect(() => {
    if (!exchanges.length || !sessions.length) return;
    lazyRef.current = { running: true, aborted: false };
    setLazyDone(0); setBatchComplete(false);

    if (!aiAvailable) {
      // No AI access — skip batch, mark complete immediately
      setBatchComplete(true);
      setAiSessionsError(!isSandbox() ? "AI disabled — add an API key on the drop page to enable" : null);
      return;
    }
    const CHUNK = 20;
    const chunks = sessions.flatMap(session => {
      const c = [];
      for (let i = 0; i < session.length; i += CHUNK) c.push(session.slice(i, i + CHUNK));
      return c;
    });
    let chunkIdx = 0;
    const processNext = async () => {
      while (chunkIdx < chunks.length) {
        if (lazyRef.current.aborted) return;
        const chunk = chunks[chunkIdx++];
        const uncached = chunk.filter(ex => !aiCache.current.has(ex.id));
        if (uncached.length) {
          try {
            await analyzeBatch(uncached, protocolStatesRef.current, aiCache);
            if (STORAGE_CACHE) {
              const snap = Object.fromEntries(aiCache.current);
              storage.set(STORAGE_CACHE, JSON.stringify(snap)).catch(() => {});
            }
          } catch (err) { console.warn("Batch analysis failed:", err); }
        }
        setLazyDone(d => d + chunk.length);
        if (chunkIdx < chunks.length) await new Promise(res => setTimeout(res, 800));
      }
    };
    Promise.all([processNext()]).then(() => {
      if (!lazyRef.current.aborted) { setBatchComplete(true); triggerSessionAnalysis(); }
    });
  }, [exchanges, sessions]);

  const triggerSessionAnalysis = useCallback(() => {
    if (!sessions.length || !aiAvailable) return;
    setAiSessionsLoading(true); setAiSessionsError(null); setAiSessionsWarning(null);
    const hasCached = (aiSessions?.length ?? 0) > 0;
    const slowTimer = hasCached ? null : setTimeout(() => setAiSessionsWarning("Taking longer than usual — API may be busy…"), 30000);
    let prompt;
    try { prompt = buildSessionPrompt(sessions, exchanges, aiCache, keyCheck); }
    catch (e) {
      setAiSessionsError("Failed to build prompt: " + e.message);
      setAiSessionsLoading(false); if (slowTimer) clearTimeout(slowTimer); return;
    }
    callClaude(prompt, null, 4096, SESSION_MODEL, 2)
      .then(text => {
        if (!text) { setAiSessionsError("No response from AI"); return; }
        try {
          const raw = extractJSON(text);
          if (!raw) { setAiSessionsError("No JSON in response. Check browser console for raw text."); console.warn("Full AI response (no JSON found):", text); return; }
          const parsed = JSON.parse(raw);
          const sessionData = parsed?.sessions && Array.isArray(parsed.sessions) ? parsed.sessions : Array.isArray(parsed) ? parsed : null;
          if (!sessionData) { setAiSessionsError("Unexpected response format"); return; }
          setAiSessions(sessionData);
          const meta = { card: parsed.card ?? null, protocol: parsed.protocol ?? null, finding: parsed.finding ?? null };
          setAiTraceMeta(meta);
          if (STORAGE_META)
            storage.set(STORAGE_META, JSON.stringify({ sessions: sessionData, traceMeta: meta })).catch(() => {});
        } catch (e) { setAiSessionsError("Parse error: " + e.message); }
      })
      .catch(e => { setAiSessionsError(e.message ?? "Request failed"); })
      .finally(() => { if (slowTimer) clearTimeout(slowTimer); setAiSessionsWarning(null); setAiSessionsLoading(false); });
  }, [sessions, exchanges, keyCheck, STORAGE_META]);

  // Trigger initial session analysis when sessions are ready (if no cached content).
  useEffect(() => {
    if (!sessions.length || aiSessionsLoading) return;
    if (aiSessions?.length) return; // Already have cached content — don't re-run.
    triggerSessionAnalysis();
  }, [sessions]);

  // Key check — runs once per trace.
  useEffect(() => {
    if (!exchanges.length) return;
    checkKnownKeys(exchanges).then(setKeyCheck).catch(() => {});
  }, [exchanges]);

  const handleSelect   = useCallback((ex) => setSelected(prev => prev?.id === ex.id ? null : ex), []);
  const toggleCollapse = useCallback((si) => {
    setCollapsed(prev => {
      const nowCollapsing = !prev[si];
      if (nowCollapsing) setSelected(sel => (sel && sessions[si]?.some(e => e.id === sel.id)) ? null : sel);
      return { ...prev, [si]: nowCollapsing };
    });
  }, [sessions]);

  const groupLabel = integrity.sessionKind === "sessions" ? "SESSION" : integrity.sessionKind === "chunks" ? "CHUNK" : "SEGMENT";
  const errCount = exchanges.filter(ex => { const rd = ex.rsp ? decodeRsp(ex.rsp.bytes) : null; return rd && rd.sw !== 0x9000 && rd.sw >= 0x6000; }).length;

  // Auto-advance from loading screen after 4s (AI continues in background)
  useEffect(() => {
    if (!trace || viewResults || batchComplete) return;
    const timer = setTimeout(() => setViewResults(true), 4000);
    return () => clearTimeout(timer);
  }, [trace, viewResults, batchComplete]);

  // Keyboard navigation: arrow keys move through exchanges
  useEffect(() => {
    if (!exchanges.length) return;
    const handler = (e) => {
      if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "j" && e.key !== "k") return;
      e.preventDefault();
      const dir = (e.key === "ArrowDown" || e.key === "j") ? 1 : -1;
      setSelected(prev => {
        const curIdx = prev ? exchanges.findIndex(ex => ex.id === prev.id) : -1;
        const nextIdx = Math.max(0, Math.min(exchanges.length - 1, curIdx + dir));
        const next = exchanges[nextIdx];
        // Scroll the row into view
        setTimeout(() => {
          const el = document.getElementById(`exch-row-${next.id}`);
          if (el) el.scrollIntoView({ block: "nearest", behavior: "smooth" });
        }, 0);
        return next;
      });
      setRightTab("detail");
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [exchanges]);

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100dvh", background:C.bg, color:C.text, fontFamily:"system-ui, sans-serif" }}
      onDragOver={e => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}>

      {/* Drop overlay */}
      {dragOver && <div style={{ position:"fixed", inset:0, zIndex:100, background:C.purple+"22", border:`2px dashed ${C.purple}`, display:"flex", alignItems:"center", justifyContent:"center", pointerEvents:"none" }}>
        <div style={{ color:C.purple, fontSize:18, fontFamily:"monospace", fontWeight:700 }}>Drop CryptoTokenKit log file to analyze</div>
      </div>}

      {/* Hidden file input for browse button */}
      <input ref={fileInputRef} type="file" accept=".txt,.log" onChange={handleBrowse} style={{ display:"none" }} />

      {/* Header */}
      <div style={{ borderBottom:`1px solid ${C.border}`, background:C.surface, flexShrink:0 }}>
        <div style={{ padding:"6px 12px", display:"flex", alignItems:"center", gap:10, minHeight:34 }}>
          <span style={{ fontSize:12, fontWeight:700, color:"#fff", fontFamily:"monospace", letterSpacing:1, flexShrink:0, lineHeight:"20px" }}>CardForensics</span>
          {cardId && <span style={{ position:"relative", flexShrink:0, lineHeight:"20px" }}>
            <span onMouseEnter={() => setCardTip(true)} onMouseLeave={() => setCardTip(false)} onClick={() => setCardTip(t=>!t)}
              style={{ fontSize:9, color:C.teal, border:`1px solid ${C.teal}33`, borderRadius:3, padding:"2px 6px", cursor:"pointer", verticalAlign:"middle" }}>{cardId.profile.name}</span>
            {cardTip && <div style={{ position:"absolute", top:"100%", left:0, marginTop:6, zIndex:999, background:"#141825", border:`1px solid ${C.teal}44`, borderRadius:5, padding:"10px 12px", fontSize:11, width:300, boxShadow:"0 4px 20px #00000088", lineHeight:1.7 }}
              onMouseEnter={() => setCardTip(true)} onMouseLeave={() => setCardTip(false)}>
              <div style={{ fontWeight:700, color:C.teal, marginBottom:6 }}>{cardId.profile.name}</div>
              <div style={{ color:C.text, marginBottom:4 }}>{cardId.profile.vendor} · {Math.round(cardId.confidence*100)}% confidence</div>
              <div style={{ color:"#8899bb", fontSize:10, marginBottom:6 }}>{cardId.signals.map((s,i)=><div key={i}>· {s}</div>)}</div>
              {complianceProfile && <div style={{ color:C.text, fontSize:10, paddingTop:4, borderTop:`1px solid ${C.border}` }}>
                Compliance: {complianceProfile.standardPct}% standard, {complianceProfile.proprietaryPct}% proprietary
                {complianceProfile.proprietaryInsCodes.length > 0 && <span style={{ color:"#8899bb" }}> (INS: {complianceProfile.proprietaryInsCodes.join(", ")})</span>}
              </div>}
            </div>}
          </span>}
          {trace && <span style={{ fontSize:11, color:C.teal, flexShrink:0, lineHeight:"20px" }}>{trace.name}</span>}
          <span style={{ flex:1 }} />
          {trace && <>
            <div style={{ display:"flex", gap:8, fontSize:10, color:C.muted, alignItems:"center", flexShrink:0, flexWrap:"wrap" }}>
              <span><span style={{ color:C.text }}>{exchanges.length}</span> exchanges</span>
              <span><span style={{ color:C.red }}>{errCount}</span> errors</span>
              <span><span style={{ color:C.text }}>{sessions.length}</span> {groupLabel.toLowerCase()}s</span>
              {securityScore && <span style={{ color:securityScore.color }}>{securityScore.score}</span>}
            </div>
            <button onClick={() => {
              const pkg = buildForensicExport({ exchanges, sessions, protocolStates, annotations, objectLedger, keyCheck, integrity, errorProfile, aiSessions, aiTraceMeta, aiCache: aiCache.current, certProvision, securityScore, complianceProfile, cardId });
              const json = JSON.stringify(pkg, null, 2);
              const filename = `apdu-forensic-${exchanges[0]?.cmd.ts.split(" ")[0] ?? "export"}.json`;
              setExportModal({ json, filename });
            }} style={{ ...BTN, fontSize:9, color:C.teal, border:`1px solid ${C.teal}44`, padding:"3px 8px", flexShrink:0 }}>↓ export JSON</button>
            <button onClick={() => fileInputRef.current?.click()} style={{ ...BTN, fontSize:9, padding:"3px 8px", flexShrink:0 }}>📂 open</button>
            <button onClick={() => setTrace(null)} style={{ ...BTN, fontSize:9, color:C.red, border:`1px solid ${C.red}44`, padding:"3px 8px", flexShrink:0 }}>✕ reset</button>
          </>}
        </div>
        {/* Analysis progress bar — only when trace loaded */}
        {trace && (() => {
          const pct = exchanges.length ? Math.min(lazyDone / exchanges.length, 1) : 0;
          const barColor = batchComplete ? C.teal : C.purple;
          return <div style={{ height:3, background:C.border, position:"relative" }}>
            <div style={{ position:"absolute", top:0, left:0, height:"100%", width:`${pct*100}%`, background:barColor, transition:"width 0.4s ease, background 0.6s ease", borderRadius:"0 2px 2px 0", animation:(batchComplete&&aiSessionsLoading&&!aiSessions?.length)?"apdu-bar-pulse 1.6s ease-in-out infinite":"none" }} />
            {batchComplete && aiSessionsLoading && !aiSessions?.length && <div style={{ position:"absolute", right:8, top:4, fontSize:9, color:C.amber, fontFamily:"monospace", background:C.surface, padding:"1px 5px", borderRadius:3, border:`1px solid ${C.amber}44`, pointerEvents:"none", zIndex:20 }}>summarizing sessions…</div>}
          </div>;
        })()}
      </div>

      {/* Empty state */}
      {!trace ? (
        <div style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", gap:20, padding:"40px 20px", textAlign:"center" }}>
          <div style={{ fontSize:48, opacity:0.15 }}>📡</div>
          <div style={{ fontSize:18, color:C.text, fontWeight:700, fontFamily:"monospace" }}>Drop a CryptoTokenKit log file to analyze</div>
          <div style={{ fontSize:12, color:C.dim, lineHeight:1.6, maxWidth:440 }}>
            Enable APDU logging on macOS, perform your smart card operation, then export the log.
          </div>
          <div style={{ width:"100%", maxWidth:620, textAlign:"left", display:"flex", flexDirection:"column", gap:10 }}>
            {[
              { label: "1. Enable APDU logging", cmd: "sudo defaults write /Library/Preferences/com.apple.security.smartcard Logging -bool true" },
              { label: "2. Export recent traces to file", cmd: "log show --predicate 'eventMessage CONTAINS[c] \"APDU\"' --last 5m > trace.txt" },
              { label: "3. Disable logging when done", cmd: "sudo defaults delete /Library/Preferences/com.apple.security.smartcard Logging" },
            ].map((step, i) => (
              <div key={i}>
                <div style={{ fontSize:10, color:C.muted, marginBottom:3, fontFamily:"monospace", paddingLeft:2 }}>{step.label}</div>
                <div style={{ display:"flex", background:"#0d1117", borderRadius:5, border:`1px solid ${C.border}` }}>
                  <pre style={{ flex:1, margin:0, padding:"8px 12px", fontSize:11, color:C.teal, fontFamily:"'SF Mono',Menlo,Monaco,monospace", overflowX:"hidden", whiteSpace:"pre-wrap", wordBreak:"break-word", lineHeight:1.5 }}>{step.cmd}</pre>
                  <button onClick={(e) => { navigator.clipboard?.writeText(step.cmd); const b=e.currentTarget; b.textContent="✓"; setTimeout(()=>b.textContent="⎘",1500); }}
                    style={{ padding:"0 12px", background:C.surface, border:"none", borderLeft:`1px solid ${C.border}`, color:C.muted, cursor:"pointer", fontSize:14, flexShrink:0, borderRadius:"0 4px 4px 0" }}
                    title="Copy to clipboard">⎘</button>
                </div>
              </div>
            ))}
          </div>
          <ApiConfig />
          <button onClick={() => fileInputRef.current?.click()} style={{ ...BTN, fontSize:13, padding:"10px 24px", color:C.teal, border:`1px solid ${C.teal}66`, marginTop:8 }}>Browse for log file</button>
        </div>

      ) : !viewResults && !batchComplete ? (
        /* Analysis loading screen */
        <div style={{ flex:1, display:"flex", alignItems:"center", justifyContent:"center", padding:40 }}>
          <div style={{ width:"100%", maxWidth:480 }}>
            <div style={{ textAlign:"center", marginBottom:28 }}>
              <div style={{ fontSize:14, fontWeight:700, color:C.text, fontFamily:"monospace", marginBottom:4 }}>Analyzing {trace.name}</div>
              <div style={{ fontSize:11, color:C.dim }}>{exchanges.length} exchanges · {sessions.length} session{sessions.length!==1?"s":""}</div>
            </div>

            <div style={{ display:"flex", flexDirection:"column", gap:12, marginBottom:24 }}>
              {/* Parse */}
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ color:C.green, fontSize:13, width:18, textAlign:"center" }}>✓</span>
                <span style={{ fontSize:12, color:C.text, flex:1 }}>Parsed {exchanges.length} APDU exchanges</span>
              </div>

              {/* Card ID */}
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ color:cardId?C.green:C.dim, fontSize:13, width:18, textAlign:"center" }}>{cardId?"✓":"·"}</span>
                <span style={{ fontSize:12, color:cardId?C.text:C.dim, flex:1 }}>{cardId?`Identified: ${cardId.profile.name} (${Math.round(cardId.confidence*100)}%)`:"Card identification"}</span>
              </div>

              {/* Integrity */}
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ color:integrity.kind==="complete"?C.green:C.amber, fontSize:13, width:18, textAlign:"center" }}>✓</span>
                <span style={{ fontSize:12, color:C.text, flex:1 }}>Trace integrity: {integrity.kind}{integrity.warnings?.length?` (${integrity.warnings.length} warning${integrity.warnings.length>1?"s":""})`:""}
                </span>
              </div>

              {/* Threats */}
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ color:C.green, fontSize:13, width:18, textAlign:"center" }}>✓</span>
                <span style={{ fontSize:12, color:C.text, flex:1 }}>
                  {activeThreats.length} threat{activeThreats.length!==1?"s":""} detected
                  {activeThreats.filter(t=>t.severity==="critical").length>0&&<span style={{ color:C.red, marginLeft:6, fontWeight:700 }}>{activeThreats.filter(t=>t.severity==="critical").length} critical</span>}
                </span>
              </div>

              {/* Key check */}
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ color:keyCheck?C.green:C.purple, fontSize:13, width:18, textAlign:"center" }}>{keyCheck?"✓":"⟳"}</span>
                <span style={{ fontSize:12, color:keyCheck?C.text:C.dim, flex:1 }}>{
                  keyCheck
                    ? keyCheck.matches.length > 0
                      ? <span style={{ color:C.red, fontWeight:700 }}>Default key matched ({keyCheck.matches.length}×)</span>
                      : `No default keys (${keyCheck.testedPairs.length} pair${keyCheck.testedPairs.length!==1?"s":""} tested)`
                    : "Checking known keys…"
                }</span>
              </div>

              {/* AI annotation */}
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ color:batchComplete?C.green:C.purple, fontSize:13, width:18, textAlign:"center" }}>{batchComplete?"✓":"✦"}</span>
                <span style={{ fontSize:12, color:C.text, flex:1 }}>AI annotation: {lazyDone}/{exchanges.length}</span>
              </div>
            </div>

            {/* Progress bar */}
            <div style={{ height:4, background:C.border, borderRadius:2, marginBottom:20, overflow:"hidden" }}>
              <div style={{ height:"100%", borderRadius:2, background:`linear-gradient(90deg, ${C.purple}, ${C.teal})`, width:`${exchanges.length?Math.round(lazyDone/exchanges.length*100):0}%`, transition:"width 0.5s ease" }} />
            </div>

            {/* View Results button — always enabled, AI runs in background */}
            <div style={{ textAlign:"center" }}>
              <button onClick={() => setViewResults(true)}
                style={{ padding:"10px 32px", borderRadius:6, cursor:"pointer", fontSize:13, fontWeight:600, fontFamily:"monospace",
                  background: C.purple+"22",
                  border:`1px solid ${C.purple}`,
                  color: C.purple,
                  transition:"all 0.3s" }}>
                View Results →
              </button>
              <div style={{ fontSize:10, color:C.dim, marginTop:8 }}>
                {lazyDone > 0 ? "AI annotation continues in background" : "Deterministic analysis complete. AI annotation runs in background."}
              </div>
            </div>
          </div>
        </div>

      ) : (
        /* Main split layout */
        <div ref={splitRef}
          style={{ display:"flex", flex:1, overflow:"hidden", position:"relative", userSelect:splitDragging?"none":"auto" }}
          onMouseMove={e => {
            if (!splitDragging) return;
            const rect = splitRef.current?.getBoundingClientRect();
            if (!rect) return;
            setSplitPct(Math.max(20, Math.min(75, ((e.clientX - rect.left) / rect.width) * 100)));
          }}
          onMouseUp={() => { setSplitDragging(false); document.body.style.cursor = ""; }}
          onMouseLeave={() => { setSplitDragging(false); document.body.style.cursor = ""; }}>

          {/* Left panel: AI summary + findings */}
          <div style={{ width:`${splitPct}%`, flexShrink:0, display:"flex", flexDirection:"column", overflow:"hidden", borderRight:`1px solid ${C.border}` }}>
            <div style={{ flex:1, overflowY:"auto", WebkitOverflowScrolling:"touch" }}>
              <AISessionSummary aiSessions={aiSessions} aiSessionsLoading={aiSessionsLoading} aiSessionsError={aiSessionsError} aiSessionsWarning={aiSessionsWarning} aiTraceMeta={aiTraceMeta} onRetry={triggerSessionAnalysis} batchProgress={lazyDone > 0 ? { done: lazyDone, total: exchanges.length } : null} securityScore={securityScore} complianceProfile={complianceProfile} onSelectSession={(si) => {
                setCollapsed(prev => ({ ...prev, [si]: false }));
                const firstEx = sessions[si]?.[0];
                if (firstEx) { setSelected(firstEx); setTimeout(() => { const el = document.getElementById(`exch-row-${firstEx.id}`); if (el) el.scrollIntoView({ block: "start", behavior: "smooth" }); }, 100); }
              }} />
              <FindingsPanel integrity={integrity} keyCheck={keyCheck} aiSessions={aiSessions} aiTraceMeta={aiTraceMeta} aiSessionsLoading={aiSessionsLoading} aiSessionsError={aiSessionsError} lazyDone={lazyDone} exchangeCount={exchanges.length} exchanges={exchanges} protocolStates={protocolStates} certProvision={certProvision} securityScore={securityScore} complianceProfile={complianceProfile} activeThreats={activeThreats} onSelectExchange={(ex) => { if (ex) { setSelected(ex); setRightTab("detail"); }}} />
            </div>
          </div>

          {/* Divider */}
          <div
            onMouseDown={e => { e.preventDefault(); setSplitDragging(true); document.body.style.cursor = "col-resize"; }}
            style={{ width:6, flexShrink:0, cursor:"col-resize", background:splitDragging?C.purple:C.border, transition:"background 0.15s", position:"relative", zIndex:10 }}
            onMouseEnter={e => e.currentTarget.style.background = C.purple+"bb"}
            onMouseLeave={e => { if (!splitDragging) e.currentTarget.style.background = C.border; }}
          />

          {/* Right panel: Sequence replay + exchange list + detail */}
          <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden", minWidth:0 }}>
            <SequenceReplay
              key={cacheKey ?? "empty"}
              exchanges={exchanges} sessions={sessions} sessionAnalysis={aiSessions}
              onSelect={handleSelect} aiCache={aiCache} />

            <FilterBar filters={filters} onFilters={setFilters} />

            <div style={{ display:"flex", flex:1, overflow:"hidden" }}>
              {/* Exchange list */}
              <div style={{ flex:1, overflowY:"auto", minWidth:0, display:"flex", flexDirection:"column", WebkitOverflowScrolling:"touch" }}>
                {sessions.map((session, si) => (
                  <SessionBlock key={si} session={session} si={si} color={SESSION_COLORS[si]||C.teal}
                    label={aiSessions?.[si]?.label} meta={integrity.confidence==="high"?aiSessions?.[si]:null}
                    isCollapsed={!!collapsed[si]} onToggle={() => toggleCollapse(si)}
                    filters={filters} annotations={annotations} selected={selected} onSelect={handleSelect}
                    protocolStates={protocolStates} integrity={integrity} groupLabel={groupLabel} />
                ))}
              </div>

              {/* Detail panel */}
              <div style={{ width:(selected||rightTab!=="detail")?"min(400px, 45%)":0, overflow:"hidden", borderLeft:`1px solid ${C.border}`, display:"flex", flexDirection:"column", background:C.surface, transition:"width 0.2s ease", flexShrink:0 }}>
                <div style={{ display:"flex", borderBottom:`1px solid ${C.border}`, background:C.surface, flexShrink:0 }}>
                  {[["detail","Detail"],["objects",`Objects (${objectLedger?.length??0})`],["specs","Specs"]].map(([tab,label]) => (
                    <button key={tab} onClick={() => setRightTab(tab)} style={{ padding:"6px 10px", background:"transparent", border:"none", borderBottom:`2px solid ${rightTab===tab?C.purple:"transparent"}`, color:rightTab===tab?C.purple:C.muted, cursor:"pointer", fontSize:10, fontFamily:"monospace", textTransform:"uppercase", letterSpacing:0.5, whiteSpace:"nowrap" }}>{label}</button>
                  ))}
                  {selected && rightTab==="detail" && <button onClick={() => setSelected(null)} style={{ marginLeft:"auto", background:"none", border:"none", color:C.muted, cursor:"pointer", fontSize:13, padding:"0 10px" }}>✕</button>}
                </div>
                {rightTab==="objects" && <ObjectLedger ledger={objectLedger} />}
                {rightTab==="specs" && <SpecPanel relevantSpecs={selected ? (INS_SPECS[decodeCmd(selected.cmd.bytes)?.ins] ?? []) : []} />}
                {rightTab==="detail" && selected && <ExchangeDetail ex={selected} onClose={() => setSelected(null)} protocolState={protocolStates[selected.id]} exchanges={exchanges} aiCache={aiCache} lazyDone={lazyDone} keyCheck={keyCheck} />}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Export modal */}
      {exportModal && (
        <div style={{ position:"fixed", inset:0, zIndex:200, background:"rgba(0,0,0,0.88)", display:"flex", flexDirection:"column" }}>
          <div style={{ background:C.surface, borderBottom:`1px solid ${C.border}`, padding:"10px 14px", display:"flex", alignItems:"center", gap:10, flexShrink:0 }}>
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ fontFamily:"monospace", fontSize:11, color:C.teal, fontWeight:700, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{exportModal.filename}</div>
              <div style={{ fontSize:10, color:C.dim, marginTop:2 }}>{(exportModal.json.length/1024).toFixed(0)} KB · copy to clipboard then paste into a .json file</div>
            </div>
            <button onClick={() => {
              const ta = document.querySelector("#export-ta");
              if (!ta) return; ta.select(); ta.setSelectionRange(0, 99999999);
              try { setExportCopied(document.execCommand("copy") ? "copied" : "selected"); }
              catch { setExportCopied("selected"); }
              setTimeout(() => setExportCopied(false), 3000);
            }} style={{ padding:"8px 18px", borderRadius:6, cursor:"pointer", flexShrink:0, background:exportCopied?C.green+"33":C.teal+"22", border:`1px solid ${exportCopied?C.green:C.teal}`, color:exportCopied?C.green:C.teal, fontSize:13, fontWeight:700, transition:"all 0.2s", minWidth:120 }}>
              {exportCopied==="copied"?"✓ Copied!":exportCopied==="selected"?"✓ Selected":"⎘ Copy all"}
            </button>
            <button onClick={() => { setExportModal(null); setExportCopied(false); }} style={{ background:"none", border:`1px solid ${C.border}`, color:C.muted, cursor:"pointer", fontSize:18, padding:"6px 10px", borderRadius:5, flexShrink:0 }}>✕</button>
          </div>
          {exportCopied && <div style={{ background:C.green+"22", borderBottom:`1px solid ${C.green}44`, padding:"8px 16px", fontSize:12, color:C.green, fontWeight:600, display:"flex", alignItems:"center", gap:8, flexShrink:0 }}>
            ✓ {exportCopied==="copied"?"JSON copied to clipboard — paste into a .json file":"All text selected — press Ctrl+C / Cmd+C to copy"}
          </div>}
          <textarea id="export-ta" readOnly value={exportModal.json} onClick={e => e.target.select()}
            style={{ flex:1, background:"#050810", color:"#7a9ab5", fontFamily:"monospace", fontSize:11, lineHeight:1.6, padding:16, border:"none", outline:"none", resize:"none", overflowY:"auto" }} />
        </div>
      )}

      <style>{`
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        .apdu-lane .apdu-cmd-line  { animation: apdu-grow-right var(--cmd-ms, 650ms) cubic-bezier(.4,0,.2,1) forwards; }
        .apdu-lane .apdu-cmd-head  { animation: apdu-fade var(--cmd-ms, 650ms) ease-out forwards; animation-delay: calc(var(--cmd-ms, 650ms) * 0.7); }
        .apdu-lane .apdu-cmd-label { animation: apdu-fade 200ms ease-out forwards; animation-delay: calc(var(--cmd-ms, 650ms) * 0.5); }
        .apdu-lane .apdu-rsp-line  { animation: apdu-grow-left var(--rsp-ms, 500ms) cubic-bezier(.4,0,.2,1) forwards; animation-delay: var(--rsp-delay, 650ms); }
        .apdu-lane .apdu-rsp-head  { animation: apdu-fade var(--rsp-ms, 500ms) ease-out forwards; animation-delay: calc(var(--rsp-delay, 650ms) + var(--rsp-ms, 500ms) * 0.7); }
        .apdu-lane .apdu-rsp-label { animation: apdu-fade 200ms ease-out forwards; animation-delay: calc(var(--rsp-delay, 650ms) + var(--rsp-ms, 500ms) * 0.5); }
        @keyframes apdu-grow-right { from { transform: scaleX(0); } to { transform: scaleX(1); } }
        @keyframes apdu-grow-left  { from { transform: scaleX(0); } to { transform: scaleX(1); } }
        @keyframes apdu-fade       { from { opacity: 0; } to { opacity: 1; } }
        @keyframes apdu-bar-pulse  { 0% { opacity: 1; } 50% { opacity: 0.45; } 100% { opacity: 1; } }
      `}</style>
    </div>
  );
}

/**
 * useTraceAnalysis — synchronous analysis pipeline.
 *
 * Accepts a trace object ({ name, log }) and returns all derived
 * analysis data via useMemo chains. Also runs the async key check
 * once per trace.
 *
 * This hook contains NO UI state — only analysis outputs.
 */
import { useState, useMemo, useRef, useEffect } from "react";
import { parseEntries, buildExchanges, extractATR } from "../decode.js";
import { groupSessions, buildProtocolStates } from "../protocol.js";
import {
  analyzeIntegrity, classifyErrors, checkCertProvisioning, identifyCard,
  computeComplianceProfile, computeSecurityScore, buildObjectLedger,
  analyzeThreats, autoAnnotate, extractTokenMetadata,
} from "../analysis/index.js";
import { checkKnownKeys } from "../crypto.js";

export default function useTraceAnalysis(trace) {
  const [keyCheck, setKeyCheck] = useState(null);

  // ── Synchronous memo chain ──
  const entries         = useMemo(() => trace ? parseEntries(trace.log) : [], [trace]);
  const traceATR        = useMemo(() => trace ? extractATR(trace.log) : null, [trace]);
  const exchanges       = useMemo(() => buildExchanges(entries), [entries]);
  const sessions        = useMemo(() => groupSessions(exchanges), [exchanges]);
  const integrity       = useMemo(() => analyzeIntegrity(exchanges, sessions), [exchanges, sessions]);
  const errorProfile    = useMemo(() => classifyErrors(exchanges), [exchanges]);
  const cardId          = useMemo(() => identifyCard(exchanges, traceATR), [exchanges, traceATR]);
  const tokenMeta       = useMemo(() => extractTokenMetadata(exchanges), [exchanges]);
  const complianceProfile = useMemo(() => computeComplianceProfile(exchanges), [exchanges]);
  const protocolStates  = useMemo(() => buildProtocolStates(exchanges), [exchanges]);
  const objectLedger    = useMemo(() => buildObjectLedger(exchanges, protocolStates), [exchanges, protocolStates]);
  const certProvision   = useMemo(() => checkCertProvisioning(exchanges, objectLedger), [exchanges, objectLedger]);

  // Mutable ref so async code (AI batching) can read the latest states
  const protocolStatesRef = useRef(protocolStates);
  useEffect(() => { protocolStatesRef.current = protocolStates; }, [protocolStates]);

  const annotations = useMemo(() => {
    const out = {};
    for (const ex of exchanges) {
      const a = autoAnnotate(ex, protocolStates[ex.id]);
      if (a) out[ex.id] = a;
    }
    return out;
  }, [exchanges, protocolStates]);

  const activeThreats = useMemo(
    () => analyzeThreats(exchanges, protocolStates, integrity),
    [exchanges, protocolStates, integrity]
  );

  // Security score depends on keyCheck (async) + everything else (sync)
  const securityScore = useMemo(
    () => computeSecurityScore(keyCheck, integrity, errorProfile, certProvision, exchanges, protocolStates, activeThreats),
    [keyCheck, integrity, errorProfile, certProvision, exchanges, protocolStates, activeThreats]
  );

  // ── Async: key check runs once per trace ──
  useEffect(() => {
    setKeyCheck(null);
    if (!exchanges.length) return;
    checkKnownKeys(exchanges)
      .then(setKeyCheck)
      .catch(e => console.warn("Key check failed:", e));
  }, [exchanges]);

  return {
    entries, exchanges, sessions,
    integrity, errorProfile, cardId, complianceProfile, tokenMeta,
    protocolStates, protocolStatesRef,
    objectLedger, certProvision, annotations,
    activeThreats, securityScore, keyCheck,
  };
}

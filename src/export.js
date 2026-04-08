/**
 * Forensic evidence package builder (JSON export).
 *
 * Three-layer structure:
 *   "trace"  — raw APDU bytes from the log
 *   "rules"  — deterministic analysis (annotations, threats, scoring)
 *   "ai"     — LLM-generated hypotheses (require human verification)
 */
// ── EXPORT ────────────────────────────────────────────────────────────────
// Forensic evidence package builder. Three-layer structure:
// "trace" = raw bytes, "rules" = deterministic analysis, "ai" = LLM hypothesis.
import { h, hexStr, decodeCmd, decodeRsp, INS_MAP } from "./decode.js";
import { analyzeThreats, translateToAPI } from "./analysis/index.js";
import { KNOWN_KEYS } from "./crypto.js";

function buildForensicExport({ exchanges, sessions, protocolStates, annotations, objectLedger, keyCheck, integrity, errorProfile, aiSessions, aiTraceMeta, aiCache, certProvision, securityScore, complianceProfile, cardId }) {
  const ref = { ex:(id)=>`ex:${id}`, sess:(i)=>`sess:${i}` };
  const sessionOf = (ex) => sessions.findIndex(s => s.some(e => e.id === ex.id));
  const testedPairs = keyCheck?.testedPairs ?? [], keyMatches = keyCheck?.matches ?? [];
  const activeThreats = analyzeThreats(exchanges, protocolStates, integrity);
  const uniqueDefaultKeyIds = [...new Set(keyMatches.map(m => m.id))];
  return {
    schema_version: "2.1",
    schema_note: "Three-layer forensic evidence package. source: trace=raw bytes, rules=deterministic analysis, ai=LLM hypothesis requiring verification.",
    provenance: { exported_at: new Date().toISOString(), log_source: "macOS CryptoTokenKit APDU log", log_date: exchanges[0]?.cmd.ts.split(" ")[0] ?? null, exchange_count: exchanges.length, ai_coverage: `${aiCache?.size ?? 0}/${exchanges.length} exchanges AI-analyzed` },
    card_identification: cardId ? { source: "rules", name: cardId.profile.name, vendor: cardId.profile.vendor, confidence: cardId.confidence, signals: cardId.signals, atr: cardId.atrMatch?.atr ?? null, read_only: cardId.atrMatch?.readOnly ?? cardId.profile.readOnly ?? null } : { source: "rules", name: null, note: "Card family could not be identified." },
    security_score: securityScore ?? null,
    compliance_profile: complianceProfile ? { source: "rules", standard_pct: complianceProfile.standardPct, proprietary_pct: complianceProfile.proprietaryPct, proprietary_ins_codes: complianceProfile.proprietaryInsCodes } : null,
    cert_provisioning: certProvision?.probed.length > 0 ? { source: "rules", probed_slots: certProvision.probed, populated_slots: certProvision.populated, absent_slots: certProvision.absent, all_empty: certProvision.allEmpty, fully_provisioned: certProvision.full } : null,
    active_threats: activeThreats,
    key_check: { source: "rules", pairs_tested: testedPairs.length, known_keys_tested: KNOWN_KEYS.length, unique_default_keys_matched: uniqueDefaultKeyIds.length, matches: keyMatches },
    sessions: sessions.map((sess, si) => ({ ref: ref.sess(si), index: si, exchange_count: sess.length, start_time: sess[0]?.cmd.ts ?? null, ai_label: aiSessions?.[si]?.label ?? null, ai_summary: { source: "ai", text: aiSessions?.[si]?.summary ?? null }, api_operations: translateToAPI(sess, protocolStates).map(op => ({ source: "rules", label: op.label, detail: op.detail })) })),
    object_ledger: objectLedger ?? [],
    exchanges: exchanges.map(ex => {
      const cd = decodeCmd(ex.cmd.bytes), rd = ex.rsp ? decodeRsp(ex.rsp.bytes) : null, ps = protocolStates[ex.id], ann = annotations[ex.id];
      return { ref: ref.ex(ex.id), id: ex.id, session: ref.sess(sessionOf(ex)), command: { source:"trace", timestamp:ex.cmd.ts, hex:ex.cmd.hex, ins:cd?h(cd.ins):null, ins_name:cd?(INS_MAP[cd.ins]??null):null, p1:cd?h(cd.p1):null, p2:cd?h(cd.p2):null, lc:cd?.lc??null, data_hex:cd?.data?.length?hexStr(cd.data):null }, response: ex.rsp ? { source:"trace", timestamp:ex.rsp.ts, sw:rd?h(rd.sw1)+h(rd.sw2):null, sw_ok:rd?.sw===0x9000, data_hex:rd?.data?.length?hexStr(rd.data):null, data_length:rd?.data?.length??0 } : null, protocol_state: ps ? { source:"rules", channel:ps.chNum, phase:ps.phase??null, selected_app:ps.selected, authenticated:ps.authenticated, authenticated_note:ps.authenticated?"inferred — not proven by CLA alone":null, scp_variant:ps.scp } : null, annotation: ann?{source:"rules",note:ann.note,flag:ann.flag}:null, ai_analysis:{source:"ai",text:aiCache?.get(ex.id)??null} };
    }),
  };
}


export { buildForensicExport };

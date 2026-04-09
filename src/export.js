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
import { analyzeThreats, translateToAPI, lookupAID, ATR_DB_STATS } from "./analysis/index.js";
import { KNOWN_KEYS } from "./crypto.js";
import { parseATR, formatATRSummary } from "./atr-parser.js";

function buildForensicExport({ exchanges, sessions, protocolStates, annotations, objectLedger, keyCheck, integrity, errorProfile, aiSessions, aiTraceMeta, aiCache, certProvision, securityScore, complianceProfile, cardId }) {
  const ref = { ex:(id)=>`ex:${id}`, sess:(i)=>`sess:${i}` };
  const sessionOf = (ex) => sessions.findIndex(s => s.some(e => e.id === ex.id));
  const testedPairs = keyCheck?.testedPairs ?? [], keyMatches = keyCheck?.matches ?? [];
  const activeThreats = analyzeThreats(exchanges, protocolStates, integrity);
  const uniqueDefaultKeyIds = [...new Set(keyMatches.map(m => m.id))];

  // ATR structural parse (if ATR is available from card identification)
  const atrHex = cardId?.atrMatch?.atr ?? null;
  let atrParse = null;
  if (atrHex) {
    try {
      const parsed = parseATR(atrHex);
      atrParse = {
        source: "rules",
        convention: parsed.convention,
        protocols: parsed.protocols,
        historical_bytes_ascii: parsed.historicalAscii,
        check_byte_valid: parsed.checkByte !== null ? parsed.checkValid : null,
        summary: formatATRSummary(parsed),
      };
    } catch { /* ATR parse failure is non-fatal */ }
  }

  // Resolve AID names for SELECT commands in exchanges
  const aidLookupCache = new Map();
  function resolveAID(dataBytes) {
    if (!dataBytes?.length) return null;
    const hex = hexStr(dataBytes).replace(/ /g, "").toUpperCase();
    if (aidLookupCache.has(hex)) return aidLookupCache.get(hex);
    const result = lookupAID(hex);
    aidLookupCache.set(hex, result);
    return result;
  }

  return {
    schema_version: "2.3",
    schema_note: "Three-layer forensic evidence package. source: trace=raw bytes, rules=deterministic analysis, ai=LLM hypothesis requiring verification. v2.3: cert_provisioning split into required/all, key_check renamed scp03_key_check with scope, PIV reset chronology correction, vendor-specific probe tagging.",
    provenance: {
      exported_at: new Date().toISOString(),
      log_source: "macOS CryptoTokenKit APDU log",
      log_date: exchanges[0]?.cmd.ts.split(" ")[0] ?? null,
      exchange_count: exchanges.length,
      ai_coverage: `${aiCache?.size ?? 0}/${exchanges.length} exchanges AI-analyzed`,
      database_coverage: {
        atr_entries: ATR_DB_STATS.total,
        atr_pv: ATR_DB_STATS.pvEntries,
        atr_pcsc_exact: ATR_DB_STATS.pcscExact,
        atr_pcsc_wildcards: ATR_DB_STATS.pcscWildcards,
      },
    },
    card_identification: cardId ? {
      source: "rules",
      name: cardId.profile.name,
      vendor: cardId.profile.vendor,
      confidence: cardId.confidence,
      signals: cardId.signals,
      card_type: cardId.profile.cardType ?? null,
      atr: atrHex,
      atr_database_source: cardId.atrMatch?.source ?? null,
      read_only: cardId.atrMatch?.readOnly ?? cardId.profile.readOnly ?? null,
      atr_parse: atrParse,
    } : { source: "rules", name: null, note: "Card family could not be identified." },
    security_score: securityScore ?? null,
    compliance_profile: complianceProfile ? { source: "rules", standard_pct: complianceProfile.standardPct, proprietary_pct: complianceProfile.proprietaryPct, proprietary_ins_codes: complianceProfile.proprietaryInsCodes } : null,
    cert_provisioning: certProvision?.probed.length > 0 ? { source: "rules", probed_slots: certProvision.probed, populated_slots: certProvision.populated, absent_slots: certProvision.absent, all_empty: certProvision.allEmpty, required_slots_populated: certProvision.requiredPopulated, all_slots_populated: certProvision.allPopulated } : null,
    active_threats: activeThreats,
    scp03_key_check: { source: "rules", scope: "SCP03 management key brute-force (not PIN verification — see active_threats for PIN findings)", pairs_tested: testedPairs.length, known_keys_tested: KNOWN_KEYS.length, unique_default_keys_matched: uniqueDefaultKeyIds.length, matches: keyMatches },
    sessions: sessions.map((sess, si) => ({ ref: ref.sess(si), index: si, exchange_count: sess.length, start_time: sess[0]?.cmd.ts ?? null, ai_label: aiSessions?.[si]?.label ?? null, ai_summary: { source: "ai", text: aiSessions?.[si]?.summary ?? null }, api_operations: translateToAPI(sess, protocolStates).map(op => ({ source: "rules", label: op.label, detail: op.detail })) })),
    object_ledger: objectLedger ?? [],
    exchanges: exchanges.map(ex => {
      const cd = decodeCmd(ex.cmd.bytes), rd = ex.rsp ? decodeRsp(ex.rsp.bytes) : null, ps = protocolStates[ex.id], ann = annotations[ex.id];
      // Resolve AID for SELECT commands
      const aidInfo = (cd?.ins === 0xA4 && cd?.data?.length) ? resolveAID(cd.data) : null;
      return { ref: ref.ex(ex.id), id: ex.id, session: ref.sess(sessionOf(ex)), command: { source:"trace", timestamp:ex.cmd.ts, hex:ex.cmd.hex, ins:cd?h(cd.ins):null, ins_name:cd?(INS_MAP[cd.ins]??null):null, p1:cd?h(cd.p1):null, p2:cd?h(cd.p2):null, lc:cd?.lc??null, data_hex:cd?.data?.length?hexStr(cd.data):null, aid_name:aidInfo?.name??null, aid_category:aidInfo?.category??null }, response: ex.rsp ? { source:"trace", timestamp:ex.rsp.ts, sw:rd?h(rd.sw1)+h(rd.sw2):null, sw_ok:rd?.sw===0x9000, data_hex:rd?.data?.length?hexStr(rd.data):null, data_length:rd?.data?.length??0 } : null, protocol_state: ps ? { source:"rules", channel:ps.chNum, phase:ps.phase??null, selected_app:ps.selected, authenticated:ps.authenticated, authenticated_note:ps.authenticated?"inferred — not proven by CLA alone":null, scp_variant:ps.scp } : null, annotation: ann?{source:"rules",note:ann.note,flag:ann.flag}:null, ai_analysis:{source:"ai",text:aiCache?.get(ex.id)??null} };
    }),
  };
}


export { buildForensicExport };

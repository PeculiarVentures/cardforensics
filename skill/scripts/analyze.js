#!/usr/bin/env node
/**
 * CardForensics CLI — full analysis pipeline.
 *
 * Modes:
 *   npx vite-node skill/scripts/analyze.js <log-file> [--atr <hex>]
 *     → Full trace analysis (card ID, token metadata, threats, keys,
 *       certs, scoring, protocol states, annotations, object ledger)
 *
 *   npx vite-node skill/scripts/analyze.js --atr-only <hex>
 *     → Standalone ATR lookup (card identification + ATR parse only)
 *
 * Output: structured JSON to stdout.
 */
import "reflect-metadata";
import { readFileSync } from "fs";
import { parseEntries, buildExchanges, extractATR, decodeCmd, decodeRsp, hexStr, h, INS_MAP, lookupSW, descCLA, execDeltaMs } from "../../src/decode.js";
import { groupSessions, buildProtocolStates, aidLabel } from "../../src/protocol.js";
import {
  identifyCard, ATR_DB_STATS, analyzeIntegrity, classifyErrors,
  checkCertProvisioning, computeSecurityScore, computeComplianceProfile,
  buildObjectLedger, analyzeThreats, autoAnnotate, extractTokenMetadata,
  lookupAID, getAllAIDs, unwrapPIVCert, analyzeCertificate,
  decodeExchange,
} from "../../src/analysis/index.js";
import { checkKnownKeys, KNOWN_KEYS } from "../../src/crypto.js";
import { parseATR, formatATRSummary } from "../../src/atr-parser.js";
import { decodeCPLC, decodeKeySetResponse } from "../../src/tlv.js";
import { translateToAPI } from "../../src/analysis/translate.js";

// ── Args ──
const args = process.argv.slice(2);
const atrOnlyIdx = args.indexOf("--atr-only");
const atrFlagIdx = args.indexOf("--atr");
const verboseFlag = args.includes("--verbose");

// ── Mode: ATR-only lookup ──
if (atrOnlyIdx >= 0) {
  const atrHex = args[atrOnlyIdx + 1];
  if (!atrHex) { console.error("Usage: --atr-only <ATR hex>"); process.exit(1); }
  const cardId = identifyCard([], atrHex);
  let atrParse = null;
  try {
    const parsed = parseATR(atrHex);
    atrParse = {
      convention: parsed.convention,
      protocols: parsed.protocols,
      historicalAscii: parsed.historicalAscii,
      checkValid: parsed.checkByte !== null ? parsed.checkValid : null,
      summary: formatATRSummary(parsed),
    };
  } catch { /* non-fatal */ }
  console.log(JSON.stringify({
    mode: "atr-lookup",
    atr: { hex: atrHex, parse: atrParse },
    card_identification: cardId ? {
      name: cardId.profile.name,
      vendor: cardId.profile.vendor,
      confidence: Math.round(cardId.confidence * 100),
      signals: cardId.signals,
      card_type: cardId.profile.cardType ?? null,
      read_only: cardId.profile.readOnly ?? null,
      atr_source: cardId.atrMatch?.source ?? null,
    } : null,
    database: { atr_entries: ATR_DB_STATS.total, aid_entries: getAllAIDs().length },
  }, null, 2));
  process.exit(0);
}

// ── Mode: Full trace analysis ──
const logPath = args.find(a => !a.startsWith("--"));
const atrOverride = atrFlagIdx >= 0 ? args[atrFlagIdx + 1] : null;

if (!logPath) {
  console.error("Usage:");
  console.error("  npx vite-node skill/scripts/analyze.js <log-file> [--atr <hex>] [--verbose]");
  console.error("  npx vite-node skill/scripts/analyze.js --atr-only <hex>");
  process.exit(1);
}

// ── Pipeline ──
const raw = readFileSync(logPath, "utf-8");
const entries = parseEntries(raw);
const traceATR = atrOverride || extractATR(raw);
const exchanges = buildExchanges(entries);
const sessions = groupSessions(exchanges);
const integrity = analyzeIntegrity(exchanges, sessions);
const errorProfile = classifyErrors(exchanges);
const cardId = identifyCard(exchanges, traceATR);
const tokenMeta = extractTokenMetadata(exchanges);
const complianceProfile = computeComplianceProfile(exchanges);
const protocolStates = buildProtocolStates(exchanges);
const objectLedger = buildObjectLedger(exchanges, protocolStates);
const certProvision = checkCertProvisioning(exchanges, objectLedger);
const activeThreats = analyzeThreats(exchanges, protocolStates, integrity);

// Annotations
const annotations = {};
let annotatedCount = 0;
const flagCounts = {};
for (const ex of exchanges) {
  const a = autoAnnotate(ex, protocolStates[ex.id]);
  if (a) {
    annotations[ex.id] = a;
    annotatedCount++;
    if (a.flag) flagCounts[a.flag] = (flagCounts[a.flag] || 0) + 1;
  }
}

// Async: key check
const keyCheck = await checkKnownKeys(exchanges);
const securityScore = computeSecurityScore(
  keyCheck, integrity, errorProfile, certProvision, exchanges, protocolStates, activeThreats
);

// ATR parse
let atrParse = null;
if (traceATR) {
  try {
    const parsed = parseATR(traceATR);
    atrParse = {
      convention: parsed.convention,
      protocols: parsed.protocols,
      historicalAscii: parsed.historicalAscii,
      checkValid: parsed.checkByte !== null ? parsed.checkValid : null,
      summary: formatATRSummary(parsed),
    };
  } catch { /* non-fatal */ }
}

// Session summaries
const sessionSummaries = sessions.map((sess, si) => {
  const ops = translateToAPI(sess, protocolStates);
  const firstTs = sess[0]?.cmd?.ts ?? null;
  const lastTs = sess[sess.length - 1]?.rsp?.ts ?? sess[sess.length - 1]?.cmd?.ts ?? null;
  return {
    index: si,
    exchange_count: sess.length,
    start_time: firstTs,
    end_time: lastTs,
    operations: ops.map(op => ({ label: op.label, detail: op.detail })),
  };
});

// ── Output ──
const result = {
  mode: "trace-analysis",
  file: logPath,

  // Top-level summary
  exchange_count: exchanges.length,
  session_count: sessions.length,
  annotation_stats: { annotated: annotatedCount, total: exchanges.length, flags: flagCounts },

  // Card identification
  card_identification: cardId ? {
    name: cardId.profile.name,
    vendor: cardId.profile.vendor,
    confidence: Math.round(cardId.confidence * 100),
    signals: cardId.signals,
    card_type: cardId.profile.cardType ?? null,
    read_only: cardId.profile.readOnly ?? null,
  } : null,

  // Token identity (serial, version, CHUID)
  token_identity: tokenMeta ? {
    serial: tokenMeta.serial,
    version: tokenMeta.version,
    vendor: tokenMeta.vendor,
    chuid: tokenMeta.chuid ?? null,
  } : null,

  // ATR
  atr: traceATR ? { hex: traceATR, parse: atrParse } : null,

  // Integrity
  integrity: { kind: integrity.kind, warnings: integrity.warnings ?? [] },

  // Security score
  security_score: securityScore ? {
    score: securityScore.score,
    label: securityScore.label,
    breakdown: securityScore.deductions ?? [],
  } : null,

  // Compliance
  compliance: complianceProfile ? {
    standard_pct: complianceProfile.standardPct,
    proprietary_pct: complianceProfile.proprietaryPct,
    proprietary_ins: complianceProfile.proprietaryInsCodes,
  } : null,

  // Certificate provisioning
  cert_provisioning: certProvision ? {
    probed: certProvision.probed,
    populated: certProvision.populated,
    absent: certProvision.absent,
    all_empty: certProvision.allEmpty,
    required_populated: certProvision.requiredPopulated,
    all_populated: certProvision.allPopulated,
  } : null,

  // Threats
  threats: activeThreats.map(t => ({
    id: t.id, severity: t.severity, title: t.title, detail: t.detail,
    exchange_ids: t.exchangeIds ?? [],
  })),

  // Key check
  key_check: {
    keys_tested: KNOWN_KEYS.length,
    pairs_tested: keyCheck?.testedPairs?.length ?? 0,
    matches: (keyCheck?.matches ?? []).map(m => ({
      id: m.id, name: m.name, exchange: m.exchangeId,
    })),
  },

  // Sessions
  sessions: sessionSummaries,

  // Object ledger
  object_ledger: (objectLedger ?? []).map(obj => ({
    tag: obj.id, name: obj.label, size: obj.size,
    status: obj.classification, reads: obj.reads?.ok||0,
    writes: obj.writes?.ok||0, mutated: obj.mutated,
  })),

  // All annotations (notable first, then informational if --verbose)
  notable_annotations: Object.entries(annotations)
    .filter(([, a]) => a.flag && a.flag !== "expected")
    .map(([id, a]) => ({ exchange: Number(id), note: a.note, flag: a.flag })),
};

// In verbose mode, include every annotation + full timeline for replay
if (verboseFlag) {
  result.all_annotations = Object.entries(annotations)
    .map(([id, a]) => ({ exchange: Number(id), note: a.note, flag: a.flag }));

  // Session membership map
  const sessionOf = (exId) => sessions.findIndex(s => s.some(e => e.id === exId));

  // Full timeline for sequence replay
  const PIV_CERT_TAGS = new Set(["5FC105", "5FC10A", "5FC10B", "5FC101"]);
  result.timeline = exchanges.map(ex => {
    const cmd = decodeCmd(ex.cmd.bytes);
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    const ps = protocolStates[ex.id];
    const ann = annotations[ex.id];
    const ins = cmd ? (INS_MAP[cmd.ins] ?? `INS_${h(cmd.ins)}`) : "?";
    const sw = rsp ? (rsp.sw === 0x9000 ? "9000" : `${h(rsp.sw1)}${h(rsp.sw2)}`) : null;
    const swOk = rsp?.sw === 0x9000;
    const sw61 = rsp && ((rsp.sw >> 8) === 0x61);
    const swInfo = rsp ? lookupSW(rsp.sw) : null;
    const dt = execDeltaMs(ex);

    // Cert extraction for PIV cert slots
    let cert = null;
    if (swOk && cmd && (cmd.ins === 0xCB || cmd.ins === 0xCA) && cmd.data?.[0] === 0x5C && rsp?.data?.length >= 50) {
      const tagHex = hexStr(cmd.data.slice(2, 2 + (cmd.data[1] ?? 0))).replace(/ /g, "").toUpperCase();
      if (PIV_CERT_TAGS.has(tagHex)) {
        try {
          const der = unwrapPIVCert(Array.from(rsp.data));
          if (der) {
            const info = analyzeCertificate(der);
            cert = { slot: tagHex, subject: info.subject, issuer: info.issuer, serial: info.serial, notBefore: info.notBefore, notAfter: info.notAfter, algorithm: info.signatureAlgorithm, keyAlgorithm: info.keyAlgorithm, keySize: info.keySize, b64: btoa(String.fromCharCode(...der)) };
          }
        } catch { /* cert parse failure is non-fatal */ }
      }
    }

    return {
      id: ex.id,
      session: sessionOf(ex.id),
      ins,
      cla: cmd ? h(cmd.cla) : null,
      claDesc: cmd ? descCLA(cmd.cla) : null,
      p1: cmd ? h(cmd.p1) : null,
      p2: cmd ? h(cmd.p2) : null,
      lc: cmd?.lc ?? null,
      sw, swMsg: swInfo?.msg ?? null, swSev: swInfo?.s ?? null,
      ok: swOk || sw61,
      phase: ps?.phase ?? null,
      auth: ps?.authenticated ?? false,
      selected: ps?.selected ?? null,
      note: ann?.note ?? null,
      flag: ann?.flag ?? null,
      cmdHex: ex.cmd.hex,
      rspHex: ex.rsp?.hex ?? null,
      cmdLen: ex.cmd.bytes?.length ?? 0,
      rspLen: ex.rsp?.bytes?.length ?? 0,
      dataLen: rsp?.data?.length ?? 0,
      ts: ex.cmd.ts ?? null,
      dt,
      continuations: ex.continuations ?? 0,
      cert,
      decoded: decodeExchange(ex),
    };
  });
}

console.log(JSON.stringify(result, null, 2));

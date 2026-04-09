/**
 * CardForensics CLI analyzer.
 *
 * Runs the full analysis pipeline on a CryptoTokenKit APDU log file
 * and outputs structured JSON to stdout.
 *
 * Usage:
 *   npx vite-node skill/scripts/analyze.js <path-to-log> [--atr <hex>]
 *
 * The script reuses the same analysis modules as the web app.
 */
import "reflect-metadata";
import { readFileSync } from "fs";
import { parseEntries, buildExchanges, extractATR } from "../../src/decode.js";
import { groupSessions, buildProtocolStates } from "../../src/protocol.js";
import {
  identifyCard, analyzeIntegrity, classifyErrors,
  checkCertProvisioning, computeSecurityScore, computeComplianceProfile,
  buildObjectLedger, analyzeThreats, autoAnnotate, extractTokenMetadata,
} from "../../src/analysis/index.js";
import { checkKnownKeys } from "../../src/crypto.js";
import { parseATR, formatATRSummary } from "../../src/atr-parser.js";

// ── Args ──
const args = process.argv.slice(2);
const logPath = args.find(a => !a.startsWith("--"));
const atrFlag = args.indexOf("--atr");
const atrOverride = atrFlag >= 0 ? args[atrFlag + 1] : null;

if (!logPath) {
  console.error("Usage: npx vite-node skill/scripts/analyze.js <log-file> [--atr <hex>]");
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
  keyCheck, integrity, errorProfile, certProvision, exchanges, protocolStates
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
      summary: formatATRSummary(parsed),
    };
  } catch { /* non-fatal */ }
}

// ── Output ──
const result = {
  file: logPath,
  exchange_count: exchanges.length,
  session_count: sessions.length,
  annotation_stats: { annotated: annotatedCount, total: exchanges.length, flags: flagCounts },

  card_identification: cardId ? {
    name: cardId.profile.name,
    vendor: cardId.profile.vendor,
    confidence: Math.round(cardId.confidence * 100),
    signals: cardId.signals,
    card_type: cardId.profile.cardType ?? null,
  } : null,

  token_identity: tokenMeta ? {
    serial: tokenMeta.serial,
    version: tokenMeta.version,
    vendor: tokenMeta.vendor,
    chuid: tokenMeta.chuid ?? null,
  } : null,

  atr: traceATR ? { hex: traceATR, parse: atrParse } : null,

  integrity: { kind: integrity.kind, warnings: integrity.warnings ?? [] },

  security_score: securityScore ? {
    score: securityScore.score,
    label: securityScore.label,
    breakdown: securityScore.breakdown ?? [],
  } : null,

  compliance: complianceProfile ? {
    standard_pct: complianceProfile.standardPct,
    proprietary_pct: complianceProfile.proprietaryPct,
    proprietary_ins: complianceProfile.proprietaryInsCodes,
  } : null,

  cert_provisioning: certProvision ? {
    probed: certProvision.probed,
    populated: certProvision.populated,
    absent: certProvision.absent,
    required_populated: certProvision.requiredPopulated,
  } : null,

  threats: activeThreats.map(t => ({
    id: t.id, severity: t.severity, title: t.title, detail: t.detail,
  })),

  key_check: {
    pairs_tested: keyCheck?.testedPairs?.length ?? 0,
    matches: keyCheck?.matches ?? [],
  },

  object_ledger_count: objectLedger?.length ?? 0,

  // Per-exchange annotations (notable ones only — skip null/expected)
  notable_annotations: Object.entries(annotations)
    .filter(([, a]) => a.flag && a.flag !== "expected")
    .map(([id, a]) => ({ exchange: Number(id), note: a.note, flag: a.flag })),
};

console.log(JSON.stringify(result, null, 2));

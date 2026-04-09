/**
 * CardForensics regression test suite.
 *
 * Runs every trace in docs/traces/ through the full analysis pipeline and
 * compares against golden snapshots in tests/snapshots/. Any change in card
 * identification, annotation text, ATR parsing, threat findings, or scoring
 * shows up as a diff.
 *
 * Usage:
 *   npx vite-node tests/regression.js           # compare against snapshots
 *   npx vite-node tests/regression.js --update   # regenerate snapshots
 */
import "reflect-metadata";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "fs";
import { join, basename } from "path";

// ── Analysis pipeline imports ──
import { identifyCard, ATR_DB_STATS } from "../src/analysis/cardid.js";
import { autoAnnotate, classifySW, PIV_OBJECTS, PIV_KEY_REFS, PIV_ALGORITHMS } from "../src/analysis/annotate.js";
import { lookupAID, getAllAIDs } from "../src/analysis/aid-database.js";
import { analyzeThreats } from "../src/analysis/threats.js";
import { computeSecurityScore, computeComplianceProfile } from "../src/analysis/scoring.js";
import { checkKnownKeys } from "../src/crypto.js";
import { analyzeIntegrity, classifyErrors } from "../src/analysis/integrity.js";
import { checkCertProvisioning } from "../src/analysis/certcheck.js";
import { buildObjectLedger } from "../src/analysis/ledger.js";
import { buildTopSummary } from "../src/analysis/summary.js";
import { extractTokenMetadata } from "../src/analysis/tokenid.js";
import { parseATR, formatATRSummary } from "../src/atr-parser.js";
import { groupSessions, buildProtocolStates } from "../src/protocol.js";
import { decodeCmd, decodeRsp, hexStr, INS_MAP, lookupSW } from "../src/decode.js";
import { TLV_TAGS } from "../src/knowledge.js";

const TRACES_DIR = join(import.meta.dirname, "../docs/traces");
const SNAP_DIR = join(import.meta.dirname, "snapshots");
const UPDATE = process.argv.includes("--update");

// ── CryptoTokenKit log parser ──
function parseLog(text) {
  const lines = text.split("\n").filter(l => l.includes("APDULog"));
  const exchanges = [];
  let pending = null;
  for (const line of lines) {
    const m = line.match(/APDU\s*(->|<-)\s*((?:[0-9a-fA-F]{2}\s*)+)/);
    if (!m) continue;
    const dir = m[1];
    const bytes = m[2].trim().split(/\s+/).map(h => parseInt(h, 16));
    // Extract timestamp
    const tsm = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)/);
    const ts = tsm ? tsm[1] : null;
    if (dir === "->") {
      if (pending) exchanges.push(pending);
      pending = { cmd: { bytes, ts }, rsp: null, idx: exchanges.length };
    } else if (dir === "<-" && pending) {
      pending.rsp = { bytes, ts };
      exchanges.push(pending);
      pending = null;
    }
  }
  if (pending) exchanges.push(pending);
  return exchanges;
}

// ── Build full analysis snapshot for one trace ──
async function analyzeTrace(exchanges, atr) {
  const snap = {};

  // Card identification
  const cardResult = identifyCard(exchanges, atr);
  snap.cardId = cardResult ? {
    name: cardResult.profile.name,
    id: cardResult.profile.id,
    vendor: cardResult.profile.vendor,
    confidence: cardResult.confidence,
    signals: cardResult.signals,
    cardType: cardResult.profile.cardType || null,
  } : null;

  // ATR-only identification (tests the database independently of APDU heuristics)
  const atrOnly = atr ? identifyCard([], atr) : null;
  snap.atrOnlyId = atrOnly ? {
    name: atrOnly.profile.name,
    confidence: atrOnly.confidence,
  } : null;

  // ATR structural parse
  if (atr) {
    const parsed = parseATR(atr);
    snap.atrParse = {
      convention: parsed.convention,
      protocols: parsed.protocols,
      historicalAscii: parsed.historicalAscii,
      checkValid: parsed.checkByte !== null ? parsed.checkValid : null,
      summary: formatATRSummary(parsed),
    };
  }

  // Sessions
  const sessions = groupSessions(exchanges);
  snap.sessionCount = sessions.length;

  // Protocol states
  let protoStates = null;
  try {
    protoStates = buildProtocolStates(exchanges);
  } catch { /* protocol state builder may not be available */ }

  // Annotations — capture every single one
  snap.annotations = [];
  for (let i = 0; i < exchanges.length; i++) {
    const ex = exchanges[i];
    const cmd = decodeCmd(ex.cmd.bytes);
    const insName = cmd ? (INS_MAP[cmd.ins] || `INS_${cmd.ins.toString(16).toUpperCase()}`) : "?";
    try {
      const ann = autoAnnotate(ex, protoStates?.[i] || null);
      snap.annotations.push({
        idx: i,
        ins: insName,
        note: ann?.note || null,
        flag: ann?.flag || null,
      });
    } catch (e) {
      snap.annotations.push({ idx: i, ins: insName, error: e.message });
    }
  }

  // Annotation stats
  const annotated = snap.annotations.filter(a => a.note).length;
  const flags = {};
  for (const a of snap.annotations) {
    if (a.flag) flags[a.flag] = (flags[a.flag] || 0) + 1;
  }
  snap.annotationStats = { total: exchanges.length, annotated, flags };

  // Integrity
  try {
    snap.integrity = analyzeIntegrity(exchanges, sessions);
  } catch { snap.integrity = null; }

  // Object ledger
  try {
    snap.objectLedger = buildObjectLedger(exchanges, protoStates);
  } catch { snap.objectLedger = null; }

  // Threats
  try {
    snap.threats = analyzeThreats(exchanges, protoStates, snap.integrity);
  } catch { snap.threats = []; }
  // Normalize threats for snapshot (strip exchangeId variability)
  snap.threatSummary = snap.threats.map(t => ({
    id: t.id, severity: t.severity, type: t.type, title: t.title,
  }));

  // Cert provisioning
  try {
    snap.certProvisioning = checkCertProvisioning(exchanges, snap.objectLedger);
  } catch { snap.certProvisioning = null; }

  // Scoring (requires full pipeline — wrap each dependency)
  let keyCheck = null;
  try { keyCheck = await checkKnownKeys(exchanges); } catch {}
  try {
    const errorProfile = { errors: [], errorRate: 0 };
    try { Object.assign(errorProfile, classifyErrors(exchanges)); } catch {}
    snap.score = computeSecurityScore(keyCheck, snap.integrity, errorProfile, snap.certProvisioning, exchanges, protoStates, snap.threats);
  } catch { snap.score = null; }

  try {
    snap.compliance = computeComplianceProfile(exchanges);
  } catch { snap.compliance = null; }

  // Token identity metadata
  try {
    snap.tokenMeta = extractTokenMetadata(exchanges);
  } catch { snap.tokenMeta = null; }

  return snap;
}

// ── Known ATRs per trace (not in the log files, would come from reader) ──
const KNOWN_ATRS = {
  "yubico_piv.log": "3BFD1300008131FE158073C021C057597562694B657940",
  "safenet_fusion.log": "3BFF9600008131FE4380318065B0846566FB12017882900085",
  "safenet_etoken.log": "3BD518008131FE7D8073C82110F4",
};

// ── Main ──
mkdirSync(SNAP_DIR, { recursive: true });

const traceFiles = readdirSync(TRACES_DIR).filter(f => f.endsWith(".log")).sort();
let failures = 0;
let total = 0;

console.log(UPDATE ? "UPDATING SNAPSHOTS\n" : "REGRESSION TEST\n");
console.log(`ATR DB: ${ATR_DB_STATS.total} entries | AID DB: ${getAllAIDs().length} entries | TLV tags: ${Object.keys(TLV_TAGS).length}\n`);

for (const traceFile of traceFiles) {
  total++;
  const logText = readFileSync(join(TRACES_DIR, traceFile), "utf-8");
  const exchanges = parseLog(logText);
  const atr = KNOWN_ATRS[traceFile] || null;
  const snap = await analyzeTrace(exchanges, atr);
  const snapPath = join(SNAP_DIR, traceFile.replace(".log", ".snapshot.json"));

  if (UPDATE) {
    writeFileSync(snapPath, JSON.stringify(snap, null, 2) + "\n");
    console.log(`  UPDATED  ${traceFile} (${exchanges.length} exchanges, ${snap.annotationStats.annotated} annotated)`);
    continue;
  }

  // Compare against golden file
  if (!existsSync(snapPath)) {
    console.log(`  NEW      ${traceFile} — no snapshot yet, run with --update`);
    failures++;
    continue;
  }

  const golden = JSON.parse(readFileSync(snapPath, "utf-8"));
  const diffs = diffSnapshots(golden, snap, traceFile);

  if (diffs.length === 0) {
    console.log(`  PASS     ${traceFile} (${exchanges.length} exchanges)`);
  } else {
    failures++;
    console.log(`  FAIL     ${traceFile} — ${diffs.length} difference(s):`);
    for (const d of diffs.slice(0, 20)) {
      console.log(`           ${d}`);
    }
    if (diffs.length > 20) console.log(`           ... and ${diffs.length - 20} more`);
  }
}

console.log(`\n${total} traces, ${total - failures} passed, ${failures} failed`);
if (!UPDATE && failures > 0) {
  console.log("\nRun with --update to regenerate snapshots after intentional changes.");
  process.exit(1);
}

// ── Snapshot diff engine ──
function diffSnapshots(golden, actual, traceName) {
  const diffs = [];

  // Card identification
  if (JSON.stringify(golden.cardId) !== JSON.stringify(actual.cardId)) {
    if (golden.cardId?.name !== actual.cardId?.name)
      diffs.push(`cardId.name: "${golden.cardId?.name}" → "${actual.cardId?.name}"`);
    if (golden.cardId?.confidence !== actual.cardId?.confidence)
      diffs.push(`cardId.confidence: ${golden.cardId?.confidence} → ${actual.cardId?.confidence}`);
    if (golden.cardId?.vendor !== actual.cardId?.vendor)
      diffs.push(`cardId.vendor: "${golden.cardId?.vendor}" → "${actual.cardId?.vendor}"`);
    if (JSON.stringify(golden.cardId?.signals) !== JSON.stringify(actual.cardId?.signals))
      diffs.push(`cardId.signals changed`);
  }

  // ATR-only identification
  if (golden.atrOnlyId?.name !== actual.atrOnlyId?.name)
    diffs.push(`atrOnlyId.name: "${golden.atrOnlyId?.name}" → "${actual.atrOnlyId?.name}"`);

  // ATR parse
  if (JSON.stringify(golden.atrParse) !== JSON.stringify(actual.atrParse))
    diffs.push(`atrParse changed: ${JSON.stringify(actual.atrParse)}`);

  // Session count
  if (golden.sessionCount !== actual.sessionCount)
    diffs.push(`sessionCount: ${golden.sessionCount} → ${actual.sessionCount}`);

  // Annotation stats
  if (golden.annotationStats?.annotated !== actual.annotationStats?.annotated)
    diffs.push(`annotations.annotated: ${golden.annotationStats?.annotated} → ${actual.annotationStats?.annotated}`);
  if (JSON.stringify(golden.annotationStats?.flags) !== JSON.stringify(actual.annotationStats?.flags))
    diffs.push(`annotations.flags: ${JSON.stringify(golden.annotationStats?.flags)} → ${JSON.stringify(actual.annotationStats?.flags)}`);

  // Per-annotation diffs (the core regression check)
  const maxLen = Math.max(golden.annotations?.length || 0, actual.annotations?.length || 0);
  for (let i = 0; i < maxLen; i++) {
    const g = golden.annotations?.[i];
    const a = actual.annotations?.[i];
    if (!g && a) { diffs.push(`annotation[${i}]: NEW ${a.ins} "${a.note}"`); continue; }
    if (g && !a) { diffs.push(`annotation[${i}]: REMOVED ${g.ins} "${g.note}"`); continue; }
    if (g.note !== a.note) diffs.push(`annotation[${i}] (${a.ins}): "${g.note}" → "${a.note}"`);
    if (g.flag !== a.flag) diffs.push(`annotation[${i}] (${a.ins}): flag "${g.flag}" → "${a.flag}"`);
    if (g.error !== a.error) diffs.push(`annotation[${i}] (${a.ins}): error "${g.error}" → "${a.error}"`);
  }

  // Threat findings
  if (JSON.stringify(golden.threatSummary) !== JSON.stringify(actual.threatSummary)) {
    const gIds = new Set((golden.threatSummary || []).map(t => t.id));
    const aIds = new Set((actual.threatSummary || []).map(t => t.id));
    for (const id of aIds) { if (!gIds.has(id)) diffs.push(`threat NEW: ${id}`); }
    for (const id of gIds) { if (!aIds.has(id)) diffs.push(`threat REMOVED: ${id}`); }
  }

  // Security score
  if (golden.score?.score !== actual.score?.score)
    diffs.push(`score: ${golden.score?.score} → ${actual.score?.score}`);

  // Token identity metadata
  if (JSON.stringify(golden.tokenMeta) !== JSON.stringify(actual.tokenMeta)) {
    if (golden.tokenMeta?.serial !== actual.tokenMeta?.serial)
      diffs.push(`tokenMeta.serial: "${golden.tokenMeta?.serial}" → "${actual.tokenMeta?.serial}"`);
    if (golden.tokenMeta?.version !== actual.tokenMeta?.version)
      diffs.push(`tokenMeta.version: "${golden.tokenMeta?.version}" → "${actual.tokenMeta?.version}"`);
    if (golden.tokenMeta?.vendor !== actual.tokenMeta?.vendor)
      diffs.push(`tokenMeta.vendor: "${golden.tokenMeta?.vendor}" → "${actual.tokenMeta?.vendor}"`);
    if (JSON.stringify(golden.tokenMeta?.chuid) !== JSON.stringify(actual.tokenMeta?.chuid))
      diffs.push(`tokenMeta.chuid changed`);
  }

  return diffs;
}

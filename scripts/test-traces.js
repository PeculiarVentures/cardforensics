/**
 * Test harness: run all trace files through the analysis pipeline
 * and report card identification, annotation, and ATR parsing results.
 *
 * Usage: node --experimental-vm-modules scripts/test-traces.js
 */
import { readFileSync } from "fs";
import { join, basename } from "path";

// ── Import analysis modules ──
import { identifyCard, CARD_PROFILES, ATR_DB_STATS } from "../src/analysis/cardid.js";
import { autoAnnotate, classifySW, PIV_OBJECTS, PIV_KEY_REFS, PIV_ALGORITHMS } from "../src/analysis/annotate.js";
import { lookupAID, getAllAIDs } from "../src/analysis/aid-database.js";
import { parseATR, formatATRSummary } from "../src/atr-parser.js";
import { TLV_TAGS, lookupTag, interpretValue, SPEC_DB } from "../src/knowledge.js";
import { decodeCmd, decodeRsp, hexStr, INS_MAP, lookupSW } from "../src/decode.js";

const TRACES_DIR = join(import.meta.dirname, "../docs/traces");

// ── Parse a CryptoTokenKit log into exchanges ──
function parseLog(text) {
  const lines = text.split("\n").filter(l => l.includes("APDULog"));
  const exchanges = [];
  let pending = null;

  for (const line of lines) {
    const m = line.match(/APDU\s*(->|<-)\s*((?:[0-9a-fA-F]{2}\s*)+)/);
    if (!m) continue;
    const dir = m[1];
    const bytes = m[2].trim().split(/\s+/).map(h => parseInt(h, 16));

    if (dir === "->") {
      if (pending) exchanges.push(pending);
      pending = { cmd: { bytes }, rsp: null };
    } else if (dir === "<-" && pending) {
      pending.rsp = { bytes };
      exchanges.push(pending);
      pending = null;
    }
  }
  if (pending) exchanges.push(pending);
  return exchanges;
}

// ── Run tests ──
console.log("═══════════════════════════════════════════════════════════");
console.log(" CardForensics Test Harness — All 6 PRs merged");
console.log("═══════════════════════════════════════════════════════════\n");

// Database stats
console.log("ATR Database Stats:");
console.log(`  PV entries:       ${ATR_DB_STATS.pvEntries}`);
console.log(`  pcsc-tools exact: ${ATR_DB_STATS.pcscExact}`);
console.log(`  pcsc-tools masks: ${ATR_DB_STATS.pcscWildcards}`);
console.log(`  Total:            ${ATR_DB_STATS.total}`);
console.log(`  AID entries:      ${getAllAIDs().length}`);
console.log(`  TLV tags:         ${Object.keys(TLV_TAGS).length}`);
console.log(`  Spec entries:     ${Object.keys(SPEC_DB).length}`);
console.log(`  PIV objects:      ${Object.keys(PIV_OBJECTS).length}`);
console.log(`  PIV key refs:     ${Object.keys(PIV_KEY_REFS).length}`);
console.log(`  PIV algorithms:   ${Object.keys(PIV_ALGORITHMS).length}`);
console.log(`  INS names:        ${Object.keys(INS_MAP).length}\n`);

// Process each trace
const traces = ["yubico_piv.log", "safenet_fusion.log", "safenet_etoken.log"];
let allPassed = true;

for (const traceFile of traces) {
  const path = join(TRACES_DIR, traceFile);
  let text;
  try { text = readFileSync(path, "utf-8"); } catch { console.log(`SKIP: ${traceFile} not found`); continue; }

  console.log(`\n${"─".repeat(60)}`);
  console.log(`TRACE: ${traceFile}`);
  console.log(`${"─".repeat(60)}`);

  const exchanges = parseLog(text);
  console.log(`  Exchanges parsed: ${exchanges.length}`);

  if (exchanges.length === 0) {
    console.log("  ERROR: No exchanges parsed!");
    allPassed = false;
    continue;
  }

  // Card identification
  const cardResult = identifyCard(exchanges, null);
  if (cardResult) {
    console.log(`  Card ID:          ${cardResult.profile.name}`);
    console.log(`  Vendor:           ${cardResult.profile.vendor}`);
    console.log(`  Confidence:       ${(cardResult.confidence * 100).toFixed(0)}%`);
    console.log(`  Signals:          ${cardResult.signals.join(", ")}`);
    if (cardResult.profile.cardType) console.log(`  Card type:        ${cardResult.profile.cardType}`);
  } else {
    console.log("  Card ID:          UNIDENTIFIED");
  }

  // Annotation pass
  let annotated = 0, flagged = 0, errors = [];
  for (const ex of exchanges) {
    try {
      const ann = autoAnnotate(ex, null);
      if (ann) {
        annotated++;
        if (ann.flag === "bug" || ann.flag === "warn") flagged++;
      }
    } catch (e) {
      errors.push(`Exchange annotation error: ${e.message}`);
      allPassed = false;
    }
  }
  console.log(`  Annotated:        ${annotated}/${exchanges.length} exchanges`);
  console.log(`  Flagged:          ${flagged} (bug/warn)`);

  // Show first 10 annotations for manual review
  console.log(`\n  First 10 annotations:`);
  let shown = 0;
  for (const ex of exchanges) {
    if (shown >= 10) break;
    const ann = autoAnnotate(ex, null);
    if (ann) {
      const flag = ann.flag ? ` [${ann.flag}]` : "";
      console.log(`    ${ann.note}${flag}`);
      shown++;
    }
  }

  // ATR parser test (use a known ATR for this card type)
  const knownATRs = {
    "yubico_piv.log": "3BFD1300008131FE158073C021C057597562694B657940",
    "safenet_fusion.log": "3BFF9600008131FE4380318065B0846566FB12017882900085",
    "safenet_etoken.log": "3BD518008131FE7D8073C82110F4",
  };
  const testATR = knownATRs[traceFile];
  if (testATR) {
    const parsed = parseATR(testATR);
    const summary = formatATRSummary(parsed);
    console.log(`\n  ATR parse (${testATR.substring(0, 20)}...):`);
    console.log(`    Summary:    ${summary}`);
    console.log(`    Convention: ${parsed.convention}`);
    console.log(`    Protocols:  ${parsed.protocols.join(", ")}`);
    if (parsed.historicalAscii) console.log(`    Historical: "${parsed.historicalAscii}"`);
    console.log(`    TCK:        ${parsed.checkByte !== null ? (parsed.checkValid ? "valid" : "INVALID") : "not present"}`);

    // Also test ATR identification via the expanded database
    const atrId = identifyCard([], testATR);
    if (atrId) {
      console.log(`    ATR DB hit: ${atrId.profile.name} (${(atrId.confidence * 100).toFixed(0)}%)`);
    } else {
      console.log(`    ATR DB hit: none`);
    }
  }

  if (errors.length) {
    console.log(`\n  ERRORS:`);
    for (const e of errors) console.log(`    ${e}`);
  }
}

// AID lookup spot checks
console.log(`\n${"─".repeat(60)}`);
console.log("AID Lookup Spot Checks:");
console.log(`${"─".repeat(60)}`);
const aidTests = [
  "A0000000041010", "A0000000031010", "A000000025010104",
  "D27600012401", "A0000006472F0001", "A000000308000010",
  "A000000177504B43532D3135", "E80704007F00070302",
];
for (const aid of aidTests) {
  const result = lookupAID(aid);
  console.log(`  ${aid} → ${result ? `${result.name} (${result.category})` : "NOT FOUND"}`);
}

console.log(`\n${"═".repeat(60)}`);
console.log(allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
console.log(`${"═".repeat(60)}\n`);
process.exit(allPassed ? 0 : 1);

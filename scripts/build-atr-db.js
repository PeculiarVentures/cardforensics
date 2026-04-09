#!/usr/bin/env node
/**
 * Parse pcsc-tools smartcard_list.txt into a compact JSON ATR database.
 *
 * Source: https://github.com/LudovicRousseau/pcsc-tools
 *         (smartcard_list.txt — community-maintained ATR database)
 *
 * Usage:
 *   curl -sL https://raw.githubusercontent.com/LudovicRousseau/pcsc-tools/master/smartcard_list.txt -o smartcard_list.txt
 *   node scripts/build-atr-db.js smartcard_list.txt > src/analysis/pcsc-atr-db.json
 */

import { readFileSync } from "fs";

const file = process.argv[2];
if (!file) { console.error("Usage: node build-atr-db.js <smartcard_list.txt>"); process.exit(1); }
const raw = readFileSync(file, "utf-8");

// ── Category extraction from description parentheses ──
const CAT_MAP = [
  [/\(Bank\)/i, "payment"], [/\bEMV\b/i, "payment"], [/\bVisa\b/i, "payment"],
  [/\bMastercard\b|Maestro/i, "payment"], [/\bAmex\b|\bAmerican Express/i, "payment"],
  [/\beID\b|\bidentity\b|\bPassport\b|\bcitizen/i, "eid"],
  [/\bPIV\b|\bFIPS.?201/i, "piv"],
  [/\(PKI\)/i, "pki"], [/\bOpenPGP\b/i, "pki"], [/\bcertificat/i, "pki"],
  [/\bFIDO\b|\bU2F\b/i, "fido"],
  [/\bSIM\b|\bUSIM\b|\bGSM\b|\bTelecomm/i, "sim"],
  [/\bTransport\b|\bCalypso\b|\bNavigo\b|\bMOBIB/i, "transport"],
  [/\bMIFARE\b|\bDESFire\b/i, "transport"],
  [/\bJavaCard\b|\bJCOP\b/i, "javacard"],
  [/\bHealth\b|\bVitale\b|\bEHIC/i, "health"],
  [/\bYubi/i, "security-key"], [/\bNitrokey/i, "security-key"],
  [/\bSafeNet\b|\beToken\b|\bIDPrime/i, "token"],
  [/\bGemalto\b|\bThales\b/i, "token"],
  [/\bHSM\b/i, "hsm"],
];

function categorize(names) {
  const joined = names.join(" ");
  for (const [re, cat] of CAT_MAP) {
    if (re.test(joined)) return cat;
  }
  // Check parenthetical hints
  const m = joined.match(/\(([^)]+)\)\s*$/);
  if (m) {
    const hint = m[1].toLowerCase();
    if (hint === "bank") return "payment";
    if (hint === "other") return null;
  }
  return null;
}

// ── Parse smartcard_list.txt ──
const entries = [];
let currentATR = null;
let currentNames = [];

for (const line of raw.split("\n")) {
  const trimmed = line.trimEnd();

  // Skip comments
  if (trimmed.startsWith("#")) continue;

  // Blank line terminates an entry
  if (trimmed === "") {
    if (currentATR && currentNames.length) {
      entries.push({ atr: currentATR, names: currentNames });
    }
    currentATR = null;
    currentNames = [];
    continue;
  }

  // Tab-indented line = description
  if (trimmed.startsWith("\t")) {
    const desc = trimmed.trim();
    // Skip bare URLs (keep URLs in parentheses as part of description)
    if (desc && !desc.match(/^https?:\/\//)) {
      currentNames.push(desc);
    }
    continue;
  }

  // ATR line: hex bytes optionally with ".." wildcards
  if (/^[0-9A-Fa-f. ]+$/.test(trimmed)) {
    // Flush previous entry
    if (currentATR && currentNames.length) {
      entries.push({ atr: currentATR, names: currentNames });
    }
    currentATR = trimmed;
    currentNames = [];
  }
}
// Flush last
if (currentATR && currentNames.length) {
  entries.push({ atr: currentATR, names: currentNames });
}

// ── Build output ──
const exact = [];   // entries without wildcards
const masked = [];  // entries with ".." wildcards

for (const { atr, names } of entries) {
  // Normalize: uppercase, strip spaces (but preserve ".." markers)
  const norm = atr.replace(/ /g, "").toUpperCase();
  const hasWildcard = norm.includes("..");
  const name = names[0]; // primary name
  const type = categorize(names);

  const rec = { a: norm, n: name };
  if (type) rec.t = type;

  if (hasWildcard) {
    masked.push(rec);
  } else {
    exact.push(rec);
  }
}

const db = {
  _source: "https://github.com/LudovicRousseau/pcsc-tools/blob/master/smartcard_list.txt",
  _generated: new Date().toISOString().split("T")[0],
  _stats: { exact: exact.length, masked: masked.length, total: exact.length + masked.length },
  exact,
  masked,
};

process.stdout.write(JSON.stringify(db) + "\n");

/**
 * Card family identification via ATR database, AID, tag, and CLA heuristics.
 *
 * ATR matching uses two databases:
 *  1. PeculiarVentures/webcrypto-local card-database.json (85 entries, includes
 *     PKCS#11 driver paths and readOnly flags).
 *  2. Community ATR database derived from pcsc-tools smartcard_list.txt (~5,000
 *     entries including ~200 wildcard/mask patterns). See scripts/build-atr-db.js.
 *
 * Plus built-in AID/CLA/tag heuristics for SafeNet, YubiKey, Gemalto,
 * and generic PIV.
 */
import { hexStr, decodeCmd, decodeRsp } from "../decode.js";
import cardDB from "./card-database.json";
import pcscDB from "./pcsc-atr-db.json";

// ── ATR database: PV card-database.json (exact + prefix) ──

const pvIndex = new Map();
for (const entry of cardDB.cards) {
  const key = entry.atr.toUpperCase().replace(/\s+/g, "");
  pvIndex.set(key, entry);
}

// ── ATR database: pcsc-tools (exact map + compiled wildcard matchers) ──

const pcscExactIndex = new Map();
for (const rec of pcscDB.exact) {
  pcscExactIndex.set(rec.a, rec);
}

/**
 * Compile a wildcard ATR pattern (using ".." for any-byte) into a test function.
 * Each ".." matches exactly one hex byte pair (two hex chars).
 * @param {string} pattern - e.g. "3B..0081.."
 * @returns {(atr: string) => boolean}
 */
function compileWildcard(pattern) {
  let reStr = "^";
  for (let i = 0; i < pattern.length; i += 2) {
    const pair = pattern.substring(i, i + 2);
    reStr += pair === ".." ? "[0-9A-F]{2}" : pair.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  reStr += "$";
  const re = new RegExp(reStr);
  return (atr) => re.test(atr);
}

const pcscWildcards = pcscDB.masked.map(rec => ({
  ...rec,
  test: compileWildcard(rec.a),
}));

/**
 * Match ATR against all databases.
 * Priority: PV exact > pcsc-tools exact > PV prefix > pcsc-tools wildcard.
 *
 * @param {string|null} atr - ATR hex string
 * @returns {{ name: string, source: "pv"|"pcsc", type?: string, readOnly?: boolean, atr?: string, driver?: string }|null}
 */
function matchATR(atr) {
  if (!atr) return null;
  const norm = atr.toUpperCase().replace(/\s+/g, "");

  // 1. PV exact (has driver/readOnly metadata)
  if (pvIndex.has(norm)) {
    const e = pvIndex.get(norm);
    return { name: e.name, source: "pv", readOnly: e.readOnly, atr: e.atr, driver: e.driver };
  }

  // 2. pcsc-tools exact
  if (pcscExactIndex.has(norm)) {
    const r = pcscExactIndex.get(norm);
    return { name: r.n, source: "pcsc", type: r.t || null };
  }

  // 3. PV prefix match
  for (const [key, entry] of pvIndex) {
    if (norm.startsWith(key) || key.startsWith(norm)) {
      return { name: entry.name, source: "pv", readOnly: entry.readOnly, atr: entry.atr, driver: entry.driver };
    }
  }

  // 4. pcsc-tools wildcard/mask match
  for (const wc of pcscWildcards) {
    if (wc.test(norm)) {
      return { name: wc.n, source: "pcsc", type: wc.t || null };
    }
  }

  return null;
}

/** Expose database stats for UI display. */
export const ATR_DB_STATS = {
  pvEntries: pvIndex.size,
  pcscExact: pcscExactIndex.size,
  pcscWildcards: pcscWildcards.length,
  get total() { return this.pvEntries + this.pcscExact + this.pcscWildcards; },
};

/** Known card profiles with identification signal definitions. */
export const CARD_PROFILES = [
  { id: "safenet-etoken-fusion-piv", name: "SafeNet eToken Fusion NFC PIV", vendor: "Thales (SafeNet)", readOnly: false, signals: [{ type: "tag", value: "FF F3", desc: "SafeNet key container namespace" }, { type: "tag", value: "DF30", desc: "SafeNet firmware version tag" }, { type: "cla", value: 0x81, desc: "SafeNet vendor CLA" }] },
  { id: "safenet-etoken-5110",       name: "SafeNet eToken 5110",           vendor: "Thales (SafeNet)", readOnly: false, signals: [{ type: "tag", value: "FF F3", desc: "SafeNet key container namespace" }, { type: "cla", value: 0x81, desc: "SafeNet vendor CLA" }] },
  { id: "yubikey-piv",               name: "YubiKey (PIV)",                 vendor: "Yubico",           readOnly: false, signals: [{ type: "aid", value: "A000000527", desc: "Yubico PIV AID prefix" }] },
  { id: "gemalto-idprime",           name: "Gemalto/Thales IDPrime",        vendor: "Thales (Gemalto)", readOnly: false, signals: [{ type: "aid", value: "A0000001520000", desc: "Gemalto IDPrime AID" }] },
  { id: "piv-generic",               name: "PIV-compatible smart card",     vendor: "Unknown",          readOnly: false, signals: [{ type: "aid", value: "A000000308000010", desc: "NIST PIV AID" }] },
];

/**
 * Identify the card family from observed APDU patterns and optional ATR.
 * @param {object[]} exchanges - Parsed APDU exchanges
 * @param {string|null} atr - ATR hex string (from log extraction), or null
 * @returns {{ profile, confidence: number, signals: string[], atrMatch?: object }} | null
 */
export function identifyCard(exchanges, atr) {
  const selects = exchanges.filter(ex => {
    const cmd = decodeCmd(ex.cmd.bytes), rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    return cmd?.ins === 0xA4 && rsp?.sw === 0x9000 && cmd.data?.length;
  });
  const selectedAIDs = selects.map(ex => hexStr(decodeCmd(ex.cmd.bytes).data || []).replace(/ /g, "").toUpperCase());
  const claSet = new Set(exchanges.map(ex => decodeCmd(ex.cmd.bytes)?.cla).filter(Boolean));
  const getDataTags = exchanges
    .filter(ex => { const cmd = decodeCmd(ex.cmd.bytes); return cmd?.ins === 0xCB || cmd?.ins === 0xCA; })
    .flatMap(ex => {
      const d = decodeCmd(ex.cmd.bytes).data;
      if (!d) return [];
      if (d[0] === 0x5C && d[1] >= 2) return [hexStr(d.slice(2, 2 + d[1])).replace(/ /g, "").toUpperCase()];
      return [hexStr([d[0]]).toUpperCase()];
    });

  // ── ATR-based identification (highest confidence when available) ──
  const atrMatch = matchATR(atr);

  // ── AID/CLA/tag heuristics ──
  const hasSafeNetFF3  = getDataTags.some(t => t.startsWith("FFF3") || t.startsWith("FF F3"));
  const hasVendorCLA81 = claSet.has(0x81);
  const firmwareTag    = exchanges.some(ex => { const cmd = decodeCmd(ex.cmd.bytes); return (cmd?.ins === 0xCB || cmd?.ins === 0xCA) && cmd?.data?.[0] === 0xDF && cmd?.data?.[1] === 0x30; });

  // SafeNet: strong signal from tag/CLA heuristics
  if (hasSafeNetFF3 && hasVendorCLA81 && firmwareTag) {
    const result = { profile: CARD_PROFILES[0], confidence: 0.96, signals: ["SafeNet FF F3 key containers", "DF30 firmware version tag", "CLA=0x81 vendor commands"] };
    if (atrMatch) { result.confidence = 0.99; result.signals.push(`ATR match: ${atrMatch.name}`); result.atrMatch = atrMatch; }
    return result;
  }
  if (hasSafeNetFF3 && hasVendorCLA81) {
    const result = { profile: CARD_PROFILES[1], confidence: 0.88, signals: ["SafeNet FF F3 key containers", "CLA=0x81 vendor commands"] };
    if (atrMatch) { result.confidence = 0.95; result.signals.push(`ATR match: ${atrMatch.name}`); result.atrMatch = atrMatch; }
    return result;
  }

  // YubiKey: AID prefix
  if (selectedAIDs.some(a => a.startsWith("A000000527"))) {
    const result = { profile: CARD_PROFILES[2], confidence: 0.95, signals: ["Yubico AID selected"] };
    if (atrMatch) { result.confidence = 0.99; result.signals.push(`ATR match: ${atrMatch.name}`); result.atrMatch = atrMatch; }
    return result;
  }

  // Gemalto IDPrime: AID
  if (selectedAIDs.some(a => a.startsWith("A0000001520000"))) {
    const result = { profile: CARD_PROFILES[3], confidence: 0.90, signals: ["Gemalto IDPrime AID selected"] };
    if (atrMatch) { result.confidence = 0.97; result.signals.push(`ATR match: ${atrMatch.name}`); result.atrMatch = atrMatch; }
    return result;
  }

  // ATR-only match (no AID/CLA/tag match but ATR recognized)
  if (atrMatch) {
    const isReadOnly = atrMatch.readOnly === true;
    const name = atrMatch.name;
    const type = atrMatch.type || null;
    const synthProfile = {
      id: type ? `${type}-${name.substring(0, 20).toLowerCase().replace(/\W+/g, "-")}` : `atr-${(atr || "").substring(0, 12).toLowerCase()}`,
      name, vendor: inferVendor(name), readOnly: isReadOnly, cardType: type,
      signals: [{ type: "atr", value: atr, desc: `ATR database match (${atrMatch.source})` }],
    };
    const confidence = atrMatch.source === "pv" ? 0.92 : 0.85;
    return {
      profile: synthProfile, confidence,
      signals: [`ATR match: ${name}`, isReadOnly ? "card is read-only" : "card supports key operations"],
      atrMatch,
    };
  }

  // Generic PIV fallback
  if (selectedAIDs.some(a => a.startsWith("A000000308000010"))) {
    return { profile: CARD_PROFILES[4], confidence: 0.60, signals: ["PIV AID selected, no ATR available for specific identification"] };
  }

  return null;
}

/** Infer vendor from card database name string. */
function inferVendor(name) {
  if (/yubi/i.test(name)) return "Yubico";
  if (/safenet|thales|gemalto|idprime/i.test(name)) return "Thales";
  if (/pivkey/i.test(name)) return "Taglio/PIVKey";
  if (/goldkey/i.test(name)) return "GoldKey Security";
  if (/athena/i.test(name)) return "Athena";
  if (/nitrokey/i.test(name)) return "Nitrokey";
  if (/rutoken/i.test(name)) return "Aktiv Co.";
  if (/oberthur|idemia/i.test(name)) return "IDEMIA";
  if (/nxp|jcop/i.test(name)) return "NXP";
  if (/feitian/i.test(name)) return "Feitian";
  if (/taglio/i.test(name)) return "Taglio";
  if (/giesecke|g&d|starcos/i.test(name)) return "Giesecke+Devrient";
  if (/acs\b|advanced card/i.test(name)) return "ACS";
  if (/national identity|eID|CNS/i.test(name)) return "Government eID";
  return "Unknown";
}

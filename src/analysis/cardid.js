/**
 * Card family identification via ATR database, AID, tag, and CLA heuristics.
 *
 * Matches observed APDU patterns and optional ATR against known card profiles
 * using the PeculiarVentures/webcrypto-local card database (85 ATR entries)
 * plus built-in AID/CLA/tag heuristics for SafeNet, YubiKey, Gemalto,
 * and generic PIV.
 */
import { hexStr, decodeCmd, decodeRsp } from "../decode.js";
import cardDB from "./card-database.json";

// ── ATR database lookup (exact + prefix matching) ──

const atrIndex = new Map();
for (const entry of cardDB.cards) {
  const key = entry.atr.toUpperCase().replace(/\s+/g, "");
  atrIndex.set(key, entry);
}

/**
 * Match ATR against the PV card database.
 * Tries exact match first, then prefix match (some readers append
 * extra bytes after the historical characters).
 */
function matchATR(atr) {
  if (!atr) return null;
  const norm = atr.toUpperCase().replace(/\s+/g, "");
  // Exact match
  if (atrIndex.has(norm)) return atrIndex.get(norm);
  // Prefix match (ATR in DB might be shorter than observed)
  for (const [key, entry] of atrIndex) {
    if (norm.startsWith(key) || key.startsWith(norm)) return entry;
  }
  return null;
}

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
    // Synthesize a profile from the database entry
    const synthProfile = {
      id: `atr-${atrMatch.atr.substring(0, 12).toLowerCase()}`,
      name, vendor: inferVendor(name), readOnly: isReadOnly,
      signals: [{ type: "atr", value: atrMatch.atr, desc: `ATR database match` }],
    };
    return {
      profile: synthProfile, confidence: 0.92,
      signals: [`ATR database match: ${name}`, isReadOnly ? "card is read-only" : "card supports key operations"],
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
  if (/national identity|eID|CNS/i.test(name)) return "Government eID";
  return "Unknown";
}

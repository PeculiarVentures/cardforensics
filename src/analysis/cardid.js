/**
 * Card family identification via ATR database, AID, tag, CLA, and pattern heuristics.
 *
 * ATR matching uses two databases:
 *  1. PeculiarVentures/webcrypto-local card-database.json (85 entries, includes
 *     PKCS#11 driver paths and readOnly flags).
 *  2. Community ATR database derived from pcsc-tools smartcard_list.txt (~5,000
 *     entries including ~200 wildcard/mask patterns). See scripts/build-atr-db.js.
 *
 * Plus built-in AID/CLA/tag heuristics for SafeNet, YubiKey, Gemalto,
 * and generic PIV. Falls back to regex-based ATR pattern matching for
 * card family hints (EMV, SIM, JavaCard, transport, eID).
 */
import { hexStr, decodeCmd, decodeRsp } from "../decode.js";
import cardDB from "./card-database.json";
import pcscDB from "./pcsc-atr-db.json";
import { lookupAID, AID_CATEGORIES } from "./aid-database.js";

// ── ATR pattern heuristics (informed by card-spy atr.ts) ──
const ATR_PATTERNS = [
  { pattern: /^3BF81300008131FE/, name: "YubiKey", type: "security-key" },
  { pattern: /^3B8D80018073C021C057597562694B657940/, name: "YubiKey NEO", type: "security-key" },
  { pattern: /^3BFD1300008131FE158073C021C057597562694B657940/, name: "YubiKey 4", type: "security-key" },
  { pattern: /^3BFC1300008131FE15597562696B65794E454F/, name: "YubiKey NEO", type: "security-key" },
  { pattern: /^3BFF9600008131FE4380318065B08/, name: "SafeNet eToken", type: "token" },
  { pattern: /^3BD518/, name: "SafeNet eToken 5100/ePass", type: "token" },
  { pattern: /^3BFE1800008131FE454.*4853/, name: "Nitrokey HSM", type: "security-key" },
  { pattern: /^3B67/, name: "EMV Card", type: "payment" },
  { pattern: /^3B6[89ABC]/, name: "EMV Card", type: "payment" },
  { pattern: /^3B.*4A434F50/, name: "JCOP Card", type: "javacard" },
  { pattern: /^3BF[89].*4A617661/, name: "JavaCard", type: "javacard" },
  { pattern: /^3B8980014A434F50/, name: "NXP JCOP", type: "javacard" },
  { pattern: /^3B3F/, name: "GSM SIM", type: "sim" },
  { pattern: /^3B9[0-9A-F]96/, name: "USIM", type: "sim" },
  { pattern: /^3B1[EF]/, name: "Mini SIM", type: "sim" },
  { pattern: /^3B7F.*00006563/, name: "Belgian eID", type: "eid" },
  { pattern: /^3B9813400AA503/, name: "Belgian eID", type: "eid" },
  { pattern: /^3B7F960000006A444E4965/, name: "Spanish DNIe", type: "eid" },
  { pattern: /^3B8F80/, name: "Calypso Transport", type: "transport" },
  { pattern: /^3B8180018080/, name: "MIFARE DESFire", type: "transport" },
  { pattern: /^3B8[0-9A-F]80.*D276000085/, name: "MIFARE DESFire EV", type: "transport" },
  { pattern: /^3B8[0-9A-F]80/, name: "Contact Smart Card", type: "generic" },
];

function matchATRPattern(atrHex) {
  if (!atrHex) return null;
  for (const { pattern, name, type } of ATR_PATTERNS) {
    if (pattern.test(atrHex)) return { name, type };
  }
  return null;
}

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

function matchATR(atr) {
  if (!atr) return null;
  const norm = atr.toUpperCase().replace(/\s+/g, "");
  if (pvIndex.has(norm)) { const e = pvIndex.get(norm); return { name: e.name, source: "pv", readOnly: e.readOnly, atr: e.atr, driver: e.driver }; }
  if (pcscExactIndex.has(norm)) { const r = pcscExactIndex.get(norm); return { name: r.n, source: "pcsc", type: r.t || null }; }
  for (const [key, entry] of pvIndex) { if (norm.startsWith(key) || key.startsWith(norm)) return { name: entry.name, source: "pv", readOnly: entry.readOnly, atr: entry.atr, driver: entry.driver }; }
  for (const wc of pcscWildcards) { if (wc.test(norm)) return { name: wc.n, source: "pcsc", type: wc.t || null }; }
  return null;
}

export const ATR_DB_STATS = {
  pvEntries: pvIndex.size,
  pcscExact: pcscExactIndex.size,
  pcscWildcards: pcscWildcards.length,
  get total() { return this.pvEntries + this.pcscExact + this.pcscWildcards; },
};

export const CARD_PROFILES = [
  { id: "safenet-etoken-fusion-piv", name: "SafeNet eToken Fusion NFC PIV", vendor: "Thales (SafeNet)", readOnly: false, signals: [{ type: "tag", value: "FF F3", desc: "SafeNet key container namespace" }, { type: "tag", value: "DF30", desc: "SafeNet firmware version tag" }, { type: "cla", value: 0x81, desc: "SafeNet vendor CLA" }] },
  { id: "safenet-etoken-5110", name: "SafeNet eToken 5110", vendor: "Thales (SafeNet)", readOnly: false, signals: [{ type: "tag", value: "FF F3", desc: "SafeNet key container namespace" }, { type: "cla", value: 0x81, desc: "SafeNet vendor CLA" }] },
  { id: "yubikey-piv", name: "YubiKey (PIV)", vendor: "Yubico", readOnly: false, signals: [{ type: "aid", value: "A000000527", desc: "Yubico PIV AID prefix" }] },
  { id: "gemalto-idprime", name: "Gemalto/Thales IDPrime", vendor: "Thales (Gemalto)", readOnly: false, signals: [{ type: "aid", value: "A0000001520000", desc: "Gemalto IDPrime AID" }] },
  { id: "piv-generic", name: "PIV-compatible smart card", vendor: "Unknown", readOnly: false, signals: [{ type: "aid", value: "A000000308000010", desc: "NIST PIV AID" }] },
];

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

  const atrMatch = matchATR(atr);
  const hasSafeNetFF3 = getDataTags.some(t => t.startsWith("FFF3") || t.startsWith("FF F3"));
  const hasVendorCLA81 = claSet.has(0x81);
  const firmwareTag = exchanges.some(ex => { const cmd = decodeCmd(ex.cmd.bytes); return (cmd?.ins === 0xCB || cmd?.ins === 0xCA) && cmd?.data?.[0] === 0xDF && cmd?.data?.[1] === 0x30; });

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
  if (selectedAIDs.some(a => a.startsWith("A000000527"))) {
    const result = { profile: CARD_PROFILES[2], confidence: 0.95, signals: ["Yubico AID selected"] };
    if (atrMatch) { result.confidence = 0.99; result.signals.push(`ATR match: ${atrMatch.name}`); result.atrMatch = atrMatch; }
    return result;
  }
  if (selectedAIDs.some(a => a.startsWith("A0000001520000"))) {
    const result = { profile: CARD_PROFILES[3], confidence: 0.90, signals: ["Gemalto IDPrime AID selected"] };
    if (atrMatch) { result.confidence = 0.97; result.signals.push(`ATR match: ${atrMatch.name}`); result.atrMatch = atrMatch; }
    return result;
  }

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
    return { profile: synthProfile, confidence, signals: [`ATR match: ${name}`, isReadOnly ? "card is read-only" : "card supports key operations"], atrMatch };
  }

  if (selectedAIDs.some(a => a.startsWith("A000000308000010"))) {
    return { profile: CARD_PROFILES[4], confidence: 0.60, signals: ["PIV AID selected, no ATR available for specific identification"] };
  }

  // AID database fallback
  for (const aid of selectedAIDs) {
    const aidInfo = lookupAID(aid);
    if (aidInfo) {
      const categoryLabel = AID_CATEGORIES[aidInfo.category] || aidInfo.category;
      const synthProfile = {
        id: `aid-${aidInfo.category}-${aidInfo.name.substring(0, 20).toLowerCase().replace(/\W+/g, "-")}`,
        name: aidInfo.name, vendor: inferVendor(aidInfo.name), readOnly: true, cardType: aidInfo.category,
        signals: [{ type: "aid", value: aidInfo.prefix, desc: `${categoryLabel} application` }],
      };
      return { profile: synthProfile, confidence: 0.75, signals: [`AID match: ${aidInfo.name} (${categoryLabel})`], atrMatch: atrMatch || undefined };
    }
  }

  // ATR pattern heuristic fallback
  if (atr) {
    const norm = atr.toUpperCase().replace(/\s+/g, "");
    const patternMatch = matchATRPattern(norm);
    if (patternMatch) {
      const synthProfile = {
        id: `pattern-${patternMatch.type}-${patternMatch.name.toLowerCase().replace(/\W+/g, "-")}`,
        name: patternMatch.name, vendor: inferVendor(patternMatch.name), readOnly: true, cardType: patternMatch.type,
        signals: [{ type: "atr-pattern", value: atr, desc: "ATR pattern heuristic match" }],
      };
      return { profile: synthProfile, confidence: 0.50, signals: [`ATR pattern: ${patternMatch.name} (heuristic, not confirmed)`] };
    }
  }

  return null;
}

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

/**
 * ISO 7816-3 ATR (Answer To Reset) structural parser.
 *
 * Decomposes an ATR byte sequence into its structural components:
 * convention, supported protocols, interface bytes, historical bytes,
 * and check byte. Provides useful forensic context even when the ATR
 * is not in any database.
 *
 * Parsing approach informed by card-spy (https://github.com/tomkp/card-spy)
 * atr.ts, adapted for CardForensics' trace-analysis context.
 *
 * Reference: ISO/IEC 7816-3:2006, section 8 (Answer to Reset)
 */
import { h } from "./decode.js";

/**
 * @typedef {object} ParsedATR
 * @property {number[]} bytes - Raw ATR bytes
 * @property {"direct"|"inverse"|"unknown"} convention - Byte convention
 * @property {string[]} protocols - Supported protocols (e.g. ["T=0", "T=1"])
 * @property {number[]} historicalBytes - Historical bytes (card-specific)
 * @property {string|null} historicalAscii - ASCII decode if all bytes are printable
 * @property {number|null} checkByte - TCK if present
 * @property {boolean} checkValid - Whether TCK XOR check passes
 * @property {object[]} interfaceBytes - Decoded interface byte groups [{name, value, desc}]
 */

/**
 * Parse an ATR hex string or byte array into structured components.
 *
 * @param {string|number[]} atr - ATR as hex string or byte array
 * @returns {ParsedATR}
 */
export function parseATR(atr) {
  const bytes = typeof atr === "string"
    ? hexToBytes(atr)
    : Array.from(atr);

  const result = {
    bytes,
    convention: "unknown",
    protocols: [],
    historicalBytes: [],
    historicalAscii: null,
    checkByte: null,
    checkValid: false,
    interfaceBytes: [],
  };

  if (bytes.length < 2) return result;

  // ── TS: Initial character (convention) ──
  const ts = bytes[0];
  result.convention = ts === 0x3B ? "direct" : ts === 0x3F ? "inverse" : "unknown";

  // ── T0: Format byte ──
  const t0 = bytes[1];
  const numHistorical = t0 & 0x0F;

  // ── Walk interface bytes (TAi, TBi, TCi, TDi) ──
  // Each TDi indicates the protocol and which interface bytes follow in the next group.
  let idx = 2;
  let td = t0; // T0 acts like TD0 for determining which interface bytes come next
  let group = 1;
  let hasProtocolOtherThanT0 = false;

  while (idx < bytes.length) {
    const hasTA = (td & 0x10) !== 0;
    const hasTB = (td & 0x20) !== 0;
    const hasTC = (td & 0x40) !== 0;
    const hasTD = (td & 0x80) !== 0;

    if (hasTA && idx < bytes.length) {
      const val = bytes[idx++];
      if (group === 1) {
        // TA1: FI (clock rate) and DI (bit rate adjustment)
        const fi = (val >> 4) & 0x0F;
        const di = val & 0x0F;
        result.interfaceBytes.push({ name: "TA1", value: val, desc: `FI=${fi} DI=${di} (clock/bit rate)` });
      } else {
        result.interfaceBytes.push({ name: `TA${group}`, value: val, desc: null });
      }
    }

    if (hasTB && idx < bytes.length) {
      const val = bytes[idx++];
      result.interfaceBytes.push({ name: `TB${group}`, value: val, desc: group === 1 ? "deprecated (Vpp)" : null });
    }

    if (hasTC && idx < bytes.length) {
      const val = bytes[idx++];
      if (group === 1) {
        result.interfaceBytes.push({ name: "TC1", value: val, desc: `extra guard time N=${val}` });
      } else if (group === 2) {
        result.interfaceBytes.push({ name: "TC2", value: val, desc: `T=0 work waiting time WI=${val}` });
      } else {
        result.interfaceBytes.push({ name: `TC${group}`, value: val, desc: null });
      }
    }

    if (hasTD && idx < bytes.length) {
      td = bytes[idx++];
      const proto = td & 0x0F;
      const protoStr = `T=${proto}`;
      if (!result.protocols.includes(protoStr)) {
        result.protocols.push(protoStr);
      }
      if (proto !== 0) hasProtocolOtherThanT0 = true;
      result.interfaceBytes.push({ name: `TD${group}`, value: td, desc: `next protocol: ${protoStr}` });
      group++;
    } else {
      break;
    }
  }

  // Default to T=0 if no TD1 present
  if (result.protocols.length === 0) {
    result.protocols.push("T=0");
  }

  // ── Historical bytes ──
  // TCK is present if any protocol other than T=0 is indicated
  const hasTCK = hasProtocolOtherThanT0;
  const histStart = idx;
  const histEnd = Math.min(histStart + numHistorical, bytes.length - (hasTCK ? 1 : 0));
  result.historicalBytes = bytes.slice(histStart, histEnd);

  // Try ASCII decode
  if (result.historicalBytes.length > 0 &&
      result.historicalBytes.every(b => b >= 0x20 && b <= 0x7E)) {
    result.historicalAscii = String.fromCharCode(...result.historicalBytes);
  }

  // ── Check byte (TCK) ──
  if (hasTCK && bytes.length > histEnd) {
    result.checkByte = bytes[histEnd];
    // TCK is XOR of all bytes from T0 to TCK inclusive (should equal 0)
    let xor = 0;
    for (let i = 1; i <= histEnd; i++) xor ^= bytes[i];
    result.checkValid = xor === 0;
  }

  return result;
}

/**
 * Format a parsed ATR into a concise human-readable summary line.
 * @param {ParsedATR} parsed
 * @returns {string}
 */
export function formatATRSummary(parsed) {
  const parts = [];
  if (parsed.convention !== "unknown") {
    parts.push(parsed.convention === "direct" ? "Direct" : "Inverse");
  }
  if (parsed.protocols.length > 0) {
    parts.push(parsed.protocols.join("/"));
  }
  if (parsed.historicalAscii) {
    parts.push(`"${parsed.historicalAscii}"`);
  }
  if (parsed.checkByte !== null) {
    parts.push(parsed.checkValid ? "TCK:ok" : "TCK:FAIL");
  }
  return parts.join(" | ") || "Unknown card";
}

/**
 * Format ATR bytes for display with spacing.
 * @param {string|number[]} atr
 * @returns {string}
 */
export function formatATRHex(atr) {
  const bytes = typeof atr === "string" ? hexToBytes(atr) : atr;
  return bytes.map(b => h(b)).join(" ");
}

// ── Internal helpers ──

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "");
  const out = [];
  for (let i = 0; i < clean.length; i += 2) {
    out.push(parseInt(clean.substring(i, i + 2), 16));
  }
  return out;
}

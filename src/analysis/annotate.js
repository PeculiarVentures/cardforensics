/**
 * Deterministic per-exchange annotation engine.
 *
 * Produces human-readable notes for each APDU exchange based on
 * decoded command/response bytes and protocol state. No AI involved.
 *
 * Flags:
 *   "bug"      — likely protocol error or sequencing mistake
 *   "warn"     — unexpected but not necessarily wrong
 *   "key"      — key material or credential observed
 *   "expected" — expected probe miss (6A82/6A80 during discovery)
 */
import { h, hexStr, decodeCmd, decodeRsp, INS_MAP, lookupSW } from "../decode.js";
import { lintTLV } from "../tlv.js";
import { lookupAID } from "./aid-database.js";

// ── Status Word Context Classifier ───────────────────────────────────────

/**
 * Classify a status word's severity in context.
 * A 6A82 during SELECT is "expected" (probe miss), but during
 * an authenticated session it's "notable".
 *
 * @param {number} sw - 16-bit status word
 * @param {object} cmd - Decoded command
 * @param {object} protoState - Protocol state at this exchange
 * @returns {"ok"|"expected"|"notable"|"anomaly"}
 */
export function classifySW(sw, cmd, protoState) {
  if (!sw) return "ok";
  const sw1 = (sw >> 8) & 0xFF;
  if (sw === 0x9000 || sw1 === 0x61) return "ok";
  if (sw1 === 0x63) return "notable";
  const ins = cmd?.ins ?? -1;
  if (sw === 0x6A82) return (ins === 0xA4 || ins === 0xCB || ins === 0xCA) ? "expected" : "notable";
  if (sw === 0x6A80) return (ins === 0xCB || ins === 0xCA) ? "expected" : "notable";
  if ([0x6A81, 0x6881, 0x6D00, 0x6E00].includes(sw)) return "expected";
  if (sw === 0x6A86) return (ins === 0xCB || ins === 0xCA || ins === 0xA4) ? "expected" : "notable";
  if (sw === 0x6982) return !protoState?.authenticated ? "notable" : "anomaly";
  if (sw === 0x6985 || sw === 0x6983) return "anomaly";
  if (sw === 0x6A88) return "notable";
  return "notable";
}

// ── Per-Exchange Annotation ──────────────────────────────────────────────

/**
 * Generate a deterministic annotation for an APDU exchange.
 *
 * @param {object} ex - Exchange with .cmd and .rsp
 * @param {object} protoState - Protocol state snapshot for this exchange
 * @returns {{ note: string, flag: string|null }} | null
 */
export function autoAnnotate(ex, protoState) {
  const cmd = decodeCmd(ex.cmd.bytes);
  const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
  if (!cmd) return null;
  const sw = rsp?.sw ?? 0;
  const swOk = sw === 0x9000;
  const sw6A80 = sw === 0x6A80;

  // Malformed TLV check
  if (swOk && rsp?.data?.length > 2 && (rsp.data[0] & 0xE0) === 0x60) {
    if (lintTLV(Array.from(rsp.data)).some(i => i.kind === "overread"))
      return { note: "⚠ MALFORMED TLV — length field overruns response data", flag: "bug" };
  }

  // GEN AUTH (INS 0x87)
  if (cmd.ins === 0x87) {
    const d = cmd.data;
    if (d?.[0] === 0x7C && d?.[1] === 0x02 && d?.[2] === 0x81 && d?.[3] === 0x00)
      return { note: "GEN AUTH step 1: request card challenge (16B nonce)", flag: null };
    if (d?.[0] === 0x7C && d?.[2] === 0x82) {
      if ((d[3] === 0x00 || d[1] === 0x12) && sw6A80)
        return { note: "GEN AUTH step 3 (PROBABLE BUG): empty 82 00 after completed auth → 6A80 — host sequencing error", flag: "bug" };
      if (d[3] === 0x10 && swOk)
        return { note: "GEN AUTH step 2: host cryptogram accepted — SCP03 channel likely established ✓ (inferred)", flag: null };
    }
    return { note: `GEN AUTH P1=${h(cmd.p1)} P2=${h(cmd.p2)} → ${swOk ? "ok" : h(sw >> 8) + h(sw & 0xff)}`, flag: sw6A80 ? "warn" : null };
  }

  // SELECT (INS 0xA4)
  if (cmd.ins === 0xA4) {
    const aid = hexStr(cmd.data || []);
    const aidNorm = aid.replace(/ /g, "").toUpperCase();
    // Check AID database for a known application name
    const aidInfo = lookupAID(aidNorm);
    if (aid.startsWith("A0 00 00 03 08 00 00 10 00 01")) return { note: "SELECT ISD v1", flag: null };
    if (aid.startsWith("A0 00 00 03 08 00 00 10 00 02")) return { note: "SELECT ISD v2 on ch1", flag: null };
    if (aid.startsWith("A0 00 00 03 08 00 00 10 00"))   return { note: "SELECT PIV applet", flag: null };
    if (aid.startsWith("A0 00 00 00 18")) return { note: `SELECT PKCS#15 → ${swOk ? "found" : "not found"}`, flag: swOk ? null : "warn" };
    if (!cmd.data?.length && swOk) return { note: "SELECT MF (no AID) → GP FCI returned", flag: null };
    if (aidInfo) {
      const status = swOk ? "success" : h(sw >> 8) + h(sw & 0xff);
      return { note: `SELECT ${aidInfo.name} → ${status}`, flag: swOk ? null : "warn" };
    }
    return { note: `SELECT AID → ${swOk ? "success" : h(sw >> 8) + h(sw & 0xff)}`, flag: swOk ? null : "warn" };
  }

  // GET DATA (INS 0xCB / 0xCA)
  if (cmd.ins === 0xCB || cmd.ins === 0xCA) {
    const d = cmd.data;
    // Vendor-specific tags (SafeNet DF namespace) — check these first, they are not secrets
    if (d?.[0] === 0xDF) {
      if (d[1] === 0x39) { const cnt = rsp?.data ? hexStr(rsp.data) : "?"; return { note: `GET usage counter DF39 → 0x${cnt.replace(/ /g, "")}`, flag: null }; }
      if (d[1] === 0x30) { const ver = rsp?.data ? String.fromCharCode(...rsp.data.filter(b => b >= 0x20 && b < 0x7F)) : "?"; return { note: swOk ? `GET firmware version → "${ver}"` : `GET firmware version → ${h(sw >> 8)}${h(sw & 0xff)}`, flag: null }; }
      if (d[1] === 0x35) return { note: "GET object directory DF35", flag: null };
      if (d[1] === 0x34) return { note: "GET key directory DF34", flag: null };
    }
    // Standard tag-list based GET DATA — known public objects
    if (d?.[0] === 0x5C) {
      const tag = d.slice(2, 2 + d[1]);
      const th = hexStr(tag);
      if (th === "7E") return { note: swOk ? "GET CCCID (7E) → present" : `GET CCCID (7E) → ${h(sw >> 8)}${h(sw & 0xff)}`, flag: null };
      if (th === "9F 7F") return { note: "GET CPLC (9F7F) → card production lifecycle data", flag: null };
      if (tag[0] === 0xFF && tag[1] === 0xF3) { const slot = h(tag[2]); return sw6A80 ? { note: `GET key container FF F3 ${slot} → not found`, flag: null } : { note: `GET key container FF F3 ${slot} → ${rsp?.data?.length ?? 0}B`, flag: null }; }
      if (tag[0] === 0x5F && tag[1] === 0xFF && tag[2] === 0x12) return { note: "GET card identity (5FFF12) → label/serial/product", flag: null };
      if (tag[0] === 0x5F && tag[1] === 0xC1) { const piv = h(tag[2]); return { note: swOk ? `GET PIV data 5FC1${piv} → ${rsp?.data?.length ?? 0}B` : `GET PIV data 5FC1${piv} → not populated (${h(sw >> 8)}${h(sw & 0xff)})`, flag: null }; }
      if (tag[0] === 0xFF && tag[1] === 0x90) return { note: `GET PIV key template FF90${h(tag[2])} → ${swOk ? `${rsp?.data?.length ?? 0}B` : "empty"}`, flag: null };
      if (tag[0] === 0xFF && tag[1] === 0x84) return { note: `GET PIV key info FF84${h(tag[2])} → ${swOk ? `${rsp?.data?.length ?? 0}B` : "empty"}`, flag: null };
      return { note: `GET DATA tag=${th} → ${swOk ? rsp?.data?.length + "B" : h(sw >> 8) + h(sw & 0xff)}`, flag: sw6A80 ? null : swOk ? null : "warn" };
    }
    // GP key set query (4D tag)
    if (d?.[0] === 0x4D && d?.[2] === 0xFF) {
      const ks1 = h(d[3]), ks2 = h(d[4]);
      return { note: swOk ? `GET key set FF${ks1}/${ks2} → ${rsp?.data?.length ?? 0}B` : `GET key set FF${ks1}/${ks2} → ${h(sw >> 8)}${h(sw & 0xff)}`, flag: sw === 0x6881 ? "warn" : null };
    }
    // Key-sized payload from unknown tag — possible secret (info only, not proven)
    if (rsp?.sw === 0x9000 && rsp.data?.length && [16, 24, 32].includes(rsp.data.length) && !rsp.data.every(b => b === rsp.data[0]))
      return { note: `GET DATA → ${rsp.data.length}B key-sized payload from unrecognized object — review recommended`, flag: "warn" };
    return { note: `GET DATA → ${lookupSW(sw).msg}`, flag: sw !== 0x9000 ? "warn" : null };
  }

  // PUT DATA (INS 0xDB)
  if (cmd.ins === 0xDB) {
    const d = cmd.data;
    if (d?.[0] === 0x5C && d[1] >= 3) {
      const tag = d.slice(2, 2 + d[1]), th = hexStr(tag);
      if (tag[0] === 0xFF && tag[1] === 0xF3) {
        const slot = h(tag[2]), payload = d.slice(2 + d[1]);
        return payload.length <= 2
          ? { note: `PUT key container FF F3 ${slot}: wipe slot`, flag: null }
          : { note: `PUT key container FF F3 ${slot}: write ${payload.length}B`, flag: null };
      }
      if (tag[0] === 0xFF && tag[1] === 0x90) return { note: `PUT PIV key template FF90${h(tag[2])}: init empty template`, flag: null };
      if (tag[0] === 0xFF && tag[1] === 0x84) return { note: `PUT PIV key info FF84${h(tag[2])}: init empty key info`, flag: null };
      return { note: `PUT DATA tag=${th} → ${swOk ? "ok" : h(sw >> 8) + h(sw & 0xff)}`, flag: null };
    }
    return { note: "PUT DATA", flag: null };
  }

  // Other known instructions
  if (cmd.ins === 0x2C) return cmd.p2 === 0x80
    ? { note: "CHANGE REF DATA P2=80 (admin): set PUK+PIN credential", flag: "key" }
    : { note: `CHANGE REF DATA P2=${h(cmd.p2)}`, flag: null };
  if (cmd.ins === 0x84) return { note: "GET CHALLENGE (random nonce request)", flag: null };

  // Generic error handling
  if (rsp && rsp.sw !== 0x9000) {
    const swInfo = lookupSW(rsp.sw);
    const cls = classifySW(rsp.sw, cmd, null);
    if (cls === "expected") return { note: `${swInfo.msg} — expected probe miss`, flag: "expected" };
    if (cls === "anomaly")  return { note: `${swInfo.msg} (${h(rsp.sw1)}${h(rsp.sw2)})`, flag: "bug" };
    return { note: `${swInfo.msg} (${h(rsp.sw1)}${h(rsp.sw2)})`, flag: null };
  }
  return null;
}

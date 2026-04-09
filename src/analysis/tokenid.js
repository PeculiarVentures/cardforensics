/**
 * Token identity metadata extractor.
 *
 * Walks all exchanges and extracts identity fields from successful
 * responses: hardware serial, firmware/applet version, CHUID fields
 * (FASC-N, GUID, expiration, signature). Works for YubiKey, SafeNet
 * eToken, and generic PIV cards.
 *
 * Returns null if no identity data is found.
 */
import { decodeCmd, decodeRsp, hexStr, h } from "../decode.js";

// ── Flat TLV parser (mirrors ExchangeDecoders.parseFlatTLV) ─────────────

function parseFlatTLV(data) {
  const tags = [];
  let i = 0;
  while (i < data.length - 1) {
    let tag = data[i++];
    if ((tag & 0x1F) === 0x1F) { tag = (tag << 8) | data[i++]; }
    if (i >= data.length) break;
    let len = data[i++];
    if (len === 0x81) { len = data[i++]; }
    else if (len === 0x82) { len = (data[i++] << 8) | data[i++]; }
    else if (len > 0x82) break;
    if (i + len > data.length) break;
    tags.push({ tag, data: data.slice(i, i + len) });
    i += len;
  }
  return tags;
}

// ── CHUID parser ────────────────────────────────────────────────────────

function parseCHUID(rspData) {
  let bytes = Array.from(rspData);
  // Skip 0x53 PIV container wrapper
  if (bytes.length > 2 && bytes[0] === 0x53) {
    let off = 1, len = bytes[off++];
    if (len === 0x81 && off < bytes.length) len = bytes[off++];
    else if (len === 0x82 && off + 1 < bytes.length) { len = (bytes[off] << 8) | bytes[off + 1]; off += 2; }
    bytes = bytes.slice(off);
  }
  const result = {};
  for (const t of parseFlatTLV(bytes)) {
    if (t.tag === 0x30) {
      result.fascn = Array.from(t.data).map(b => h(b)).join("").toUpperCase();
    } else if (t.tag === 0x34 && t.data.length === 16) {
      const hex = Array.from(t.data).map(b => h(b)).join("");
      result.guid = `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`.toUpperCase();
    } else if (t.tag === 0x36 && t.data.length === 16) {
      const hex = Array.from(t.data).map(b => h(b)).join("");
      result.cardholderUUID = `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`.toUpperCase();
    } else if (t.tag === 0x35) {
      try {
        const s = String.fromCharCode(...t.data);
        result.expiration = /^\d{8}$/.test(s) ? `${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}` : s;
      } catch { result.expiration = hexStr(t.data); }
    } else if (t.tag === 0x3E) {
      result.hasSignature = t.data.length > 0;
      result.signatureLength = t.data.length;
    }
  }
  return Object.keys(result).length > 0 ? result : null;
}

// ── ASCII decoder helper ────────────────────────────────────────────────

function decodeASCII(bytes) {
  return String.fromCharCode(...bytes.filter(b => b >= 0x20 && b < 0x7F));
}

// ── Main extractor ──────────────────────────────────────────────────────

/**
 * Extract all identity metadata from a trace's exchanges.
 *
 * @param {object[]} exchanges - Parsed APDU exchanges
 * @returns {{ serial, version, chuid, vendor }|null}
 */
export function extractTokenMetadata(exchanges) {
  const meta = { serial: null, version: null, chuid: null, vendor: null };
  let found = false;

  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes);
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    if (!cmd || !rsp || rsp.sw !== 0x9000 || !rsp.data?.length) continue;

    // YubiKey firmware version (INS 0xFD)
    if (cmd.ins === 0xFD && rsp.data.length >= 3) {
      meta.version = `${rsp.data[0]}.${rsp.data[1]}.${rsp.data[2]}`;
      meta.vendor = meta.vendor ?? "Yubico";
      found = true;
    }

    // YubiKey serial (INS 0x01, 4 bytes big-endian)
    if (cmd.ins === 0x01 && rsp.data.length === 4) {
      const sn = (rsp.data[0] << 24 | rsp.data[1] << 16 | rsp.data[2] << 8 | rsp.data[3]) >>> 0;
      meta.serial = String(sn);
      meta.vendor = meta.vendor ?? "Yubico";
      found = true;
    }

    // SafeNet hardware serial (CLA=0x82, INS=0xCA, P1=0x01, P2=0x04)
    if (cmd.cla === 0x82 && cmd.ins === 0xCA && cmd.p1 === 0x01 && cmd.p2 === 0x04 && rsp.data.length > 2) {
      meta.serial = decodeASCII(rsp.data.slice(2));
      meta.vendor = meta.vendor ?? "Thales (SafeNet)";
      found = true;
    }

    // SafeNet applet version — two formats:
    //   1. CLA=0x81, INS=0xCB, data starts with DF 30 (data-field form)
    //   2. CLA=0x81/0x00, INS=0xCB/0xCA, P1=0xDF, P2=0x30 (P1/P2 form)
    // Response TLV: DF 30 <len> <ASCII version>
    if ((cmd.ins === 0xCB || cmd.ins === 0xCA) && rsp.data.length >= 4) {
      const isDF30Data = cmd.data?.[0] === 0xDF && cmd.data?.[1] === 0x30;
      const isDF30P1P2 = cmd.p1 === 0xDF && cmd.p2 === 0x30;
      if (isDF30Data || isDF30P1P2) {
        // Response is TLV: DF 30 <len> <value>
        const rd = rsp.data;
        if (rd[0] === 0xDF && rd[1] === 0x30 && rd.length > rd[2] + 3) {
          meta.version = decodeASCII(rd.slice(3, 3 + rd[2]));
        } else if (rd.length > 3) {
          meta.version = decodeASCII(rd.slice(3));
        }
        meta.vendor = meta.vendor ?? "Thales (SafeNet)";
        found = true;
      }
    }

    // CHUID response (GET DATA for 5FC102)
    if ((cmd.ins === 0xCB || cmd.ins === 0xCA) && cmd.data) {
      const d = cmd.data;
      if (d[0] === 0x5C && d[1] >= 3 && d[2] === 0x5F && d[3] === 0xC1 && d[4] === 0x02) {
        const chuid = parseCHUID(rsp.data);
        if (chuid) { meta.chuid = chuid; found = true; }
      }
    }
  }

  return found ? meta : null;
}

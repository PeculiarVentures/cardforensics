/**
 * Pure decode functions for structured APDU responses.
 *
 * These are data-only transforms: bytes in, {label, value}[] out.
 * Shared by ExchangeDecoders.jsx (SPA) and analyze.js (skill).
 * No React, no rendering, no side effects.
 */
import { decodeCmd, decodeRsp, hexStr, h } from "../decode.js";
import { decodeCPLC, decodeKeySetResponse } from "../tlv.js";

// ── Helpers ──────────────────────────────────────────────────────────────

const bytesToAscii = (b) =>
  b.filter((x) => x >= 0x20 && x <= 0x7e && x !== 0xff)
    .map((x) => String.fromCharCode(x))
    .join("");

function formatUUID(bytes) {
  if (bytes.length < 16) return hexStr(bytes);
  const hex = Array.from(bytes).map((b) => h(b)).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Parse simple BER-TLV tags from a byte array (non-recursive, single level). */
export function parseFlatTLV(data) {
  const tags = [];
  let i = 0;
  while (i < data.length - 1) {
    let tag = data[i++];
    if ((tag & 0x1f) === 0x1f) {
      tag = (tag << 8) | data[i++];
    }
    if (i >= data.length) break;
    let len = data[i++];
    if (len === 0x81) {
      len = data[i++];
    } else if (len === 0x82) {
      len = (data[i++] << 8) | data[i++];
    } else if (len > 0x82) break;
    if (i + len > data.length) {
      tags.push({ tag, data: data.slice(i), truncated: true });
      break;
    }
    tags.push({ tag, data: data.slice(i, i + len) });
    i += len;
  }
  return tags;
}

// ── Individual decoders ──────────────────────────────────────────────────

/** Decode CHUID (Card Holder Unique Identifier, tag 5FC102). */
export function decodeCHUID(data) {
  const CHUID_TAGS = {
    0x30: "FASC-N",
    0x32: "Organizational Identifier",
    0x33: "DUNS",
    0x34: "GUID",
    0x35: "Expiration Date",
    0x36: "Cardholder UUID",
    0x3e: "Issuer Asymmetric Signature",
    0xfe: "Error Detection Code",
    0xee: "Buffer Length",
  };
  // Skip 0x53 PIV container wrapper if present (SP 800-73-4 section 3.1.2)
  let unwrapped = Array.from(data);
  if (unwrapped.length > 2 && unwrapped[0] === 0x53) {
    let off = 1,
      len = unwrapped[off++];
    if (len === 0x81 && off < unwrapped.length) len = unwrapped[off++];
    else if (len === 0x82 && off + 1 < unwrapped.length) {
      len = (unwrapped[off] << 8) | unwrapped[off + 1];
      off += 2;
    }
    unwrapped = unwrapped.slice(off);
  }
  const tags = parseFlatTLV(unwrapped);
  return tags.map((t) => {
    const label = CHUID_TAGS[t.tag] || `Tag ${h(t.tag)}`;
    let value;
    if (t.tag === 0x34 && t.data.length === 16) {
      value = formatUUID(t.data);
    } else if (t.tag === 0x36 && t.data.length === 16) {
      value = formatUUID(t.data);
    } else if (t.tag === 0x35 && t.data.length === 8) {
      const s = String.fromCharCode(...t.data);
      value = /^\d{8}$/.test(s) ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}` : s;
    } else if (t.tag === 0x3e) {
      value = t.data.length > 0 ? `${t.data.length}B signature` : "absent";
    } else {
      value = t.data.length <= 16 ? hexStr(t.data) : `${hexStr(t.data.slice(0, 12))}... (${t.data.length}B)`;
    }
    return { label, value };
  });
}

/** Decode CCC (Card Capability Container, tag 7E). */
export function decodeCCC(data) {
  const CCC_TAGS = {
    0xf0: "Card Identifier",
    0xf1: "Capability Container Version",
    0xf2: "Capability Grammar Version",
    0xf3: "Applications CardURL",
    0xf4: "PKCS#15",
    0xf5: "Registered Data Model Number",
    0xf6: "Access Control Rule Table",
    0xf7: "Card APDUs",
    0xfa: "Redirection Tag",
    0xfb: "Capability Tuples (CTs)",
    0xfc: "Status Tuples (STs)",
    0xfd: "Next CCC",
    0xfe: "Error Detection Code",
  };
  const tags = parseFlatTLV(Array.from(data));
  return tags.map((t) => ({
    label: CCC_TAGS[t.tag] || `Tag ${h(t.tag)}`,
    value:
      t.data.length <= 16
        ? hexStr(t.data)
        : `${hexStr(t.data.slice(0, 12))}... (${t.data.length}B)`,
  }));
}

/** Decode PUK+PIN credential block (16-byte, FF-padded). */
export function decodeCredentialBlock(data) {
  if (!data || data.length !== 16) return null;
  const pukRaw = data.slice(0, 8).filter((b) => b !== 0xff && b !== 0x00);
  const pinRaw = data.slice(8, 16).filter((b) => b !== 0xff && b !== 0x00);
  return [
    {
      label: "PUK (bytes 0-7)",
      value: pukRaw.length > 0 ? `${pukRaw.length}-digit credential [redacted]` : "(empty / FF-padded)",
      warn: pukRaw.length > 0,
    },
    {
      label: "PIN (bytes 8-15)",
      value: pinRaw.length > 0 ? `${pinRaw.length}-digit credential [redacted]` : "(empty / FF-padded)",
      warn: pinRaw.length > 0,
    },
  ];
}

/** Decode PIV Discovery Object (tag 7E). */
export function decodeDiscoveryObject(data) {
  const fields = [];
  let d = Array.from(data);
  let i = 0;
  if (d[0] === 0x7e) i = 2; // skip 7E container tag+len
  while (i < d.length - 3) {
    if (d[i] === 0x4f) {
      const len = d[i + 1];
      fields.push({
        label: "PIV AID",
        value: hexStr(d.slice(i + 2, i + 2 + len)),
      });
      i += 2 + len;
    } else if (d[i] === 0x5f && d[i + 1] === 0x2f) {
      const len = d[i + 2];
      const pp = d[i + 3];
      const flags = [];
      if (pp & 0x40) flags.push("global PIN");
      if (pp & 0x20) flags.push("app PIN");
      fields.push({
        label: "PIN Policy",
        value: `0x${h(pp)}${flags.length ? ` (${flags.join(", ")})` : ""}`,
      });
      i += 3 + len;
    } else {
      i++;
    }
  }
  return fields;
}

/**
 * Master decoder: takes a raw exchange object and returns decoded fields,
 * or null if no decoder matches.
 *
 * @param {{ cmd: { bytes: number[] }, rsp?: { bytes: number[] } }} ex
 * @returns {{ title: string, fields: { label: string, value: string, warn?: boolean }[] } | null}
 */
export function decodeExchange(ex) {
  const cmd = decodeCmd(ex.cmd.bytes);
  const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
  if (!cmd) return null;

  // YubiKey GET VERSION (INS 0xFD)
  if (cmd.ins === 0xfd && rsp?.sw === 0x9000 && rsp.data?.length >= 3) {
    const [major, minor, patch] = rsp.data;
    return {
      title: "YubiKey Firmware Version",
      fields: [{ label: "Version", value: `${major}.${minor}.${patch}` }],
    };
  }

  // YubiKey GET SERIAL (INS 0x01 after Yubico management applet)
  if (cmd.ins === 0x01 && rsp?.sw === 0x9000 && rsp.data?.length === 4) {
    const serial =
      ((rsp.data[0] << 24) | (rsp.data[1] << 16) | (rsp.data[2] << 8) | rsp.data[3]) >>> 0;
    return {
      title: "YubiKey Serial Number",
      fields: [{ label: "Serial", value: String(serial) }],
    };
  }

  // SafeNet GET SERIAL (CLA=0x82, INS=0xCA, P1=0x01, P2=0x04)
  if (
    cmd.cla === 0x82 &&
    cmd.ins === 0xca &&
    cmd.p1 === 0x01 &&
    cmd.p2 === 0x04 &&
    rsp?.sw === 0x9000 &&
    rsp.data?.length > 2
  ) {
    const serialBytes = rsp.data.slice(2);
    const serial = bytesToAscii(serialBytes);
    return {
      title: "SafeNet Hardware Serial",
      fields: [
        { label: "Serial", value: serial },
        { label: "Raw", value: hexStr(rsp.data) },
      ],
    };
  }

  // SafeNet applet version (DF30)
  const isDF30Data = cmd.data?.length >= 2 && cmd.data[0] === 0xdf && cmd.data[1] === 0x30;
  const isDF30P1P2 = cmd.p1 === 0xdf && cmd.p2 === 0x30;
  if (
    (cmd.ins === 0xcb || cmd.ins === 0xca) &&
    (isDF30Data || isDF30P1P2) &&
    rsp?.sw === 0x9000 &&
    rsp.data?.length > 3
  ) {
    const rd = rsp.data;
    const version =
      rd[0] === 0xdf && rd[1] === 0x30 && rd.length > rd[2] + 3
        ? bytesToAscii(rd.slice(3, 3 + rd[2]))
        : bytesToAscii(rd.slice(3));
    return {
      title: "SafeNet Applet Version",
      fields: [{ label: "Version", value: version }],
    };
  }

  // CHANGE REFERENCE DATA / RESET RETRY with 16-byte credential block
  if ((cmd.ins === 0x2c || cmd.ins === 0x24) && cmd.data?.length === 16) {
    const fields = decodeCredentialBlock(Array.from(cmd.data));
    if (fields) {
      fields.push({
        label: "P2",
        value: `${h(cmd.p2)} (${cmd.p2 === 0x80 ? "Global PIN" : cmd.p2 === 0x81 ? "PIV App PIN" : `ref ${h(cmd.p2)}`})`,
      });
      return {
        title: cmd.ins === 0x2c ? "CHANGE REFERENCE DATA" : "RESET RETRY COUNTER",
        fields,
      };
    }
  }

  // Everything below requires successful response with data
  if (!rsp || rsp.sw !== 0x9000 || !rsp.data?.length) return null;

  if (cmd.ins === 0xcb || cmd.ins === 0xca) {
    const d = cmd.data;
    const tag = d?.[0] === 0x5c ? hexStr(d.slice(2, 2 + (d[1] ?? 0))).replace(/ /g, "") : "";

    // CPLC (tag 9F7F)
    if (tag === "9F7F" && rsp.data.length >= 42) {
      const cplc = decodeCPLC(rsp.data);
      if (cplc) return { title: "CPLC -- Card Production Life Cycle Data", fields: cplc };
    }

    // Discovery Object (tag 7E — SP 800-73-4 Table 3)
    if (tag === "7E" && rsp.data.length >= 4) {
      const fields = decodeDiscoveryObject(rsp.data);
      if (fields.length) return { title: "Discovery Object", fields };
    }

    // CCC (tag 5FC107 — Card Capability Container)
    if (tag === "5FC107" && rsp.data.length >= 10) {
      const fields = decodeCCC(rsp.data);
      if (fields.length) return { title: "CCC -- Card Capability Container", fields };
    }

    // CHUID (tag 5FC102)
    if (tag === "5FC102" && rsp.data.length >= 20) {
      const fields = decodeCHUID(rsp.data);
      if (fields.length) return { title: "CHUID -- Card Holder Unique Identifier", fields };
    }

    // GP key set (4D tag)
    if (d?.[0] === 0x4d) {
      const ks = decodeKeySetResponse(rsp.data);
      if (ks?.length) {
        return {
          title: "GP Key Set Information",
          fields: ks.map((k) => ({
            label: `Key ${h(k.id)} (v${k.version})`,
            value: `${k.type} -- ${k.length * 8}-bit`,
          })),
        };
      }
    }
  }

  // SafeNet hardware serial (CLA 0x82, INS 0xCA, misc P1/P2)
  if (cmd.cla === 0x82 && cmd.ins === 0xca && rsp?.sw === 0x9000 && rsp.data?.length > 2) {
    const d = rsp.data.slice(0, -2 < 0 ? undefined : rsp.data.length);
    const start = d.findIndex((b, i) => i > 2 && b >= 0x30 && b <= 0x7a);
    if (start >= 0) {
      return {
        title: "SafeNet Hardware Data",
        fields: [{ label: "Value", value: bytesToAscii(d.slice(start)) }],
      };
    }
  }

  return null;
}

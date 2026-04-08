/**
 * TLV parsing, visual hex segmenting, CPLC decoding, and key set decoding.
 *
 * parseTLVSegs — recursive TLV parser that produces colored segments
 * buildCmdSegs / buildRspSegs — APDU field segmenter for AnnotatedHex
 * decodeCPLC — Card Production Life Cycle data parser
 * lintTLV — structural TLV validator (detects overreads, truncation)
 */
// ── TLV ───────────────────────────────────────────────────────────────────
// TLV parsing, visual segmenting, CPLC decoder, key set decoder, TLV linter.
import { h, hexStr, decodeCmd, decodeRsp, descCLA, INS_MAP, lookupSW } from "./decode.js";
import { lookupTag, interpretValue, SPECS } from "./knowledge.js";
import { C } from "./theme.js";

const CPLC_LAYOUT = [
  { name: "IC Fabricator", size: 2, kind: "fab" }, { name: "IC Type", size: 2 },
  { name: "OS Provider", size: 2, kind: "fab" }, { name: "OS Release Date", size: 2, kind: "date" },
  { name: "OS Release Level", size: 2 }, { name: "IC Fabrication Date", size: 2, kind: "date" },
  { name: "IC Serial Number", size: 4 }, { name: "IC Batch ID", size: 2 },
  { name: "IC Module Fabricator", size: 2, kind: "fab" }, { name: "IC Module Pkg Date", size: 2, kind: "date" },
  { name: "ICC Manufacturer", size: 2, kind: "fab" }, { name: "IC Embedding Date", size: 2, kind: "date" },
  { name: "Pre-Personalizer", size: 2, kind: "fab" }, { name: "Pre-Pers Date", size: 2, kind: "date" },
  { name: "Pre-Pers Equipment ID", size: 4 }, { name: "Personalizer", size: 2, kind: "fab" },
  { name: "Personalization Date", size: 2, kind: "date" }, { name: "Pers Equipment ID", size: 4 },
];
const FABRICATORS = {
  "3B00": "NXP Semiconductors", "4090": "Infineon Technologies", "4180": "Atmel",
  "4250": "Texas Instruments", "4790": "Infineon", "6030": "Renesas",
  "1192": "Samsung", "5310": "Samsung",
};
function cplcDate(bytes) {
  const y = bytes[0] >> 4, ddd = ((bytes[0] & 0xF) * 100) + ((bytes[1] >> 4) * 10) + (bytes[1] & 0xF);
  if (y === 0 && ddd === 0) return "not set";
  if (ddd < 1 || ddd > 366) return `${hexStr(bytes)} (invalid)`;
  return `×${y} day ${ddd}`;
}
function decodeCPLC(bytes) {
  if (!bytes || bytes.length < 42) return null;
  const fields = []; let off = 0;
  for (const f of CPLC_LAYOUT) {
    const fb = bytes.slice(off, off + f.size), raw = hexStr(fb);
    const key = raw.replace(/ /g, "").substring(0, 4).toUpperCase();
    fields.push({ name: f.name, raw, interp: f.kind === "fab" ? (FABRICATORS[key] ?? null) : f.kind === "date" ? cplcDate(fb) : null });
    off += f.size;
  }
  return fields;
}

const SCP_IDS = { 0x01:"SCP01", 0x02:"SCP02", 0x03:"SCP03", 0x81:"SCP01", 0x82:"SCP02", 0x83:"SCP03" };
const KEY_TYPES = { 0x80:"DES (ECB)", 0x81:"DES (CBC)", 0x82:"3DES-CBC", 0x88:"AES-128", 0x8B:"AES-256", 0x09:"AES" };

function walkTLV(bytes, found = {}) {
  let i = 0;
  while (i < bytes.length) {
    if (bytes[i] === 0x00 || bytes[i] === 0xFF) { i++; continue; }
    const tag = bytes[i++]; if (i >= bytes.length) break;
    let len = bytes[i++];
    if (len === 0x81 && i < bytes.length) len = bytes[i++];
    else if (len === 0x82 && i + 1 < bytes.length) { len = (bytes[i] << 8) | bytes[i + 1]; i += 2; }
    if (i + len > bytes.length) break;
    const val = bytes.slice(i, i + len);
    if (!(tag in found)) found[tag] = val;
    if (tag & 0x20) walkTLV(val, found);
    i += len;
  }
  return found;
}

function decodeKeySetResponse(data) {
  const tags = walkTLV(data), get = (t) => tags[t] ?? null;
  return {
    keySetId: get(0x83) ? h(get(0x83)[0]) : null,
    scpId:    get(0x9D) ? (SCP_IDS[get(0x9D)[0]] ?? `0x${h(get(0x9D)[0])}`) : null,
    scpOpts:  get(0x9E) ? `0x${h(get(0x9E)[0])}` : null,
    keyType:  get(0x80) ? (KEY_TYPES[get(0x80)[0]] ?? `0x${h(get(0x80)[0])}`) : null,
    kcvs:     get(0x91) ? hexStr(get(0x91)) : null,
  };
}


const SEG_PALETTE = ["#4a9eff","#a78bfa","#f472b6","#fb923c","#34d399","#38bdf8","#fbbf24","#e879f9","#4ade80","#f87171"];

function parseTLVSegs(bytes, depth = 0, colorIdx = { v: 0 }) {
  const segs = []; let i = 0;
  while (i < bytes.length) {
    const tagStart = i; let b = bytes[i++];
    while ((b & 0x1F) === 0x1F && i < bytes.length) b = bytes[i++];
    const tagBytes = bytes.slice(tagStart, i);
    const color = SEG_PALETTE[colorIdx.v++ % SEG_PALETTE.length];
    const tagInfo = lookupTag(tagBytes);
    if (i >= bytes.length) { segs.push({ bytes: tagBytes, label: "Tag", detail: tagInfo ? `${tagInfo.name} — ${tagInfo.desc}` : `Tag ${hexStr(tagBytes)}`, color, field: "tag" }); break; }
    const lenStart = i; let lenByte = bytes[i++], length = lenByte;
    if (lenByte === 0x81 && i < bytes.length) length = bytes[i++];
    else if (lenByte === 0x82 && i + 1 < bytes.length) { length = (bytes[i] << 8) | bytes[i + 1]; i += 2; }
    const lenBytes = bytes.slice(lenStart, i), valueBytes = bytes.slice(i, i + length);
    i += length;
    const isConstructed = (tagBytes[0] & 0x20) !== 0;
    const tagLabel = tagInfo ? tagInfo.name : `Tag ${hexStr(tagBytes)}`;
    const tagDesc = tagInfo ? tagInfo.desc : "Unknown tag";
    const interp = interpretValue(tagBytes, valueBytes);
    segs.push({ bytes: tagBytes, label: tagLabel, detail: tagDesc, spec: tagInfo?.spec ?? null, color, field: "tag" });
    segs.push({ bytes: lenBytes, label: "Length", detail: `${length} bytes of ${tagLabel}`, color: color + "99", field: "len" });
    if (isConstructed && valueBytes.length > 0 && depth < 3) segs.push(...parseTLVSegs(valueBytes, depth + 1, colorIdx));
    else segs.push({ bytes: valueBytes, label: `${tagLabel} value`, detail: interp ? `${tagDesc}\n→ ${interp}` : `${tagDesc} (${length} bytes)`, color, field: "val" });
  }
  return segs;
}

// ── APDU SEGMENTER ────────────────────────────────────────────────────────
const FIELD_COLORS = { CLA:"#a78bfa", INS:"#4a9eff", P1:"#38bdf8", P2:"#38bdf8", Lc:"#94a3b8", Le:"#94a3b8" };

function buildCmdSegs(cmdBytes) {
  if (!cmdBytes || cmdBytes.length < 2) return [];
  const cd = decodeCmd(cmdBytes);
  if (!cd) return [{ bytes: cmdBytes, label: "Raw", detail: "Could not parse", color: C.muted, field: "raw" }];
  const CLA_NOTES = { 0x00: "ISO base channel", 0x80: "GP Card Manager", 0x81: "GP channel 1", 0x84: "GP — SM requested" };
  const INS_NOTES = { 0xA4: "SELECT — activate application by AID", 0xCB: "GET DATA — retrieve data object", 0xDB: "PUT DATA — write data object", 0x87: "GENERAL AUTHENTICATE (PIV)", 0x82: "EXTERNAL AUTHENTICATE", 0x84: "GET CHALLENGE", 0x20: "VERIFY — verify PIN", 0x2C: "CHANGE REFERENCE DATA" };
  const segs = [
    { bytes: [cd.cla], label: "CLA", detail: `Class byte — ${descCLA(cd.cla)}\n${CLA_NOTES[cd.cla] ?? "CLA 0x" + h(cd.cla)}`, color: FIELD_COLORS.CLA, field: "hdr" },
    { bytes: [cd.ins], label: "INS", detail: `Instruction — ${INS_MAP[cd.ins] ?? "unknown"}\n${INS_NOTES[cd.ins] ?? "INS 0x" + h(cd.ins)}`, color: FIELD_COLORS.INS, field: "hdr" },
    { bytes: [cd.p1], label: "P1", detail: `Parameter 1: 0x${h(cd.p1)} — INS-specific meaning.`, color: FIELD_COLORS.P1, field: "hdr" },
    { bytes: [cd.p2], label: "P2", detail: `Parameter 2: 0x${h(cd.p2)} — INS-specific meaning.`, color: FIELD_COLORS.P2, field: "hdr" },
  ];
  if (cd.lc != null) {
    segs.push({ bytes: [cd.lc], label: "Lc", detail: `Data field length: ${cd.lc} bytes`, color: FIELD_COLORS.Lc, field: "len" });
    if (cd.data?.length) {
      try { const tlv = parseTLVSegs(cd.data); if (tlv.some(s => s.bytes.length < cd.data.length)) segs.push(...tlv); else throw 0; }
      catch { segs.push({ bytes: cd.data, label: "Data", detail: `Command data (${cd.data.length} bytes)`, color: "#fbbf24", field: "data" }); }
    }
  }
  if (cd.le != null) segs.push({ bytes: [cd.le === 256 ? 0 : cd.le], label: "Le", detail: `Expected response length: ${cd.le === 256 ? "256 (0x00)" : cd.le} bytes`, color: FIELD_COLORS.Le, field: "len" });
  return segs;
}

function buildRspSegs(rspBytes) {
  if (!rspBytes || rspBytes.length < 2) return [];
  const rd = decodeRsp(rspBytes); if (!rd) return [];
  const segs = [];
  if (rd.data?.length) {
    try { const tlv = parseTLVSegs(rd.data); if (tlv.some(s => s.bytes.length < rd.data.length)) segs.push(...tlv); else throw 0; }
    catch { segs.push({ bytes: rd.data, label: "Response Data", detail: `Response body (${rd.data.length} bytes)`, color: "#fbbf24", field: "data" }); }
  }
  const swMsg = lookupSW(rd.sw);
  const swC = rd.sw === 0x9000 ? C.green : rd.sw >= 0x6000 ? C.red : C.amber;
  segs.push({ bytes: [rd.sw1], label: "SW1", detail: `Status Word byte 1: 0x${h(rd.sw1)}`, color: swC, field: "sw" });
  segs.push({ bytes: [rd.sw2], label: "SW2", detail: `SW2: 0x${h(rd.sw2)}\n→ ${swMsg.msg}\n\n9000 = success; 6xxx = errors/warnings.`, color: swC, field: "sw" });
  return segs;
}

// ── TLV LINTER ────────────────────────────────────────────────────────────
function lintTLV(bytes) {
  const issues = []; let i = 0;
  while (i < bytes.length) {
    const tagStart = i;
    let tag = bytes[i++];
    // Handle multi-byte tags: if low 5 bits are all 1s, tag continues
    if ((tag & 0x1F) === 0x1F) {
      while (i < bytes.length && (bytes[i] & 0x80)) { tag = (tag << 8) | bytes[i++]; }
      if (i < bytes.length) { tag = (tag << 8) | bytes[i++]; }
      else { issues.push({ kind: "truncated-tag", offset: tagStart }); break; }
    }
    if (i >= bytes.length) { issues.push({ kind: "truncated-tag", offset: tagStart }); break; }
    let len = bytes[i++];
    if (len === 0x81) { if (i >= bytes.length) { issues.push({ kind: "truncated-length", offset: tagStart }); break; } len = bytes[i++]; }
    else if (len === 0x82) { if (i + 1 >= bytes.length) { issues.push({ kind: "truncated-length", offset: tagStart }); break; } len = (bytes[i++] << 8) | bytes[i++]; }
    else if (len > 0x82) { break; } // indefinite or long form we don't handle
    if (i + len > bytes.length) { issues.push({ kind: "overread", offset: tagStart, tag: h(tag), claimed: len, available: bytes.length - i }); break; }
    i += len;
  }
  return issues;
}


export { CPLC_LAYOUT, FABRICATORS, cplcDate, decodeCPLC };
export { SCP_IDS, KEY_TYPES, walkTLV, decodeKeySetResponse };
export { SEG_PALETTE, parseTLVSegs, FIELD_COLORS, buildCmdSegs, buildRspSegs };
export { lintTLV };

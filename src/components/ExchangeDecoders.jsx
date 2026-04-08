/** Inline decoders for structured APDU responses: CPLC, GP key sets, CCC, CHUID, YubiKey version, credentials. */
import { Fragment } from "react";
import { decodeCmd, decodeRsp, hexStr, h } from "../decode.js";
import { decodeCPLC, decodeKeySetResponse } from "../tlv.js";
import { C } from "../theme.js";

const styles = {
  container: { padding: "6px 10px", background: "#0e1218", borderTop: `1px solid ${C.border}`, fontSize: 11 },
  label: { color: C.teal, fontWeight: 600, marginBottom: 4, display: "block" },
  row: { display: "flex", gap: 8, color: C.muted, lineHeight: 1.6 },
  key: { color: C.dim, minWidth: 140, flexShrink: 0 },
  value: { color: C.text, fontFamily: "monospace" },
  redacted: { color: C.red, fontFamily: "monospace" },
};

/** Parse simple BER-TLV tags from a byte array (non-recursive, single level). */
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
    if (i + len > data.length) { tags.push({ tag, data: data.slice(i), truncated: true }); break; }
    tags.push({ tag, data: data.slice(i, i + len) });
    i += len;
  }
  return tags;
}

/** Decode CCC (Card Capability Container, tag 7E). */
function decodeCCC(data) {
  const CCC_TAGS = {
    0xF0: "Card Identifier",
    0xF1: "Capability Container Version",
    0xF2: "Capability Grammar Version",
    0xF3: "Applications CardURL",
    0xF4: "PKCS#15",
    0xF5: "Registered Data Model Number",
    0xF6: "Access Control Rule Table",
    0xF7: "Card APDUs",
    0xFA: "Redirection Tag",
    0xFB: "Capability Tuples (CTs)",
    0xFC: "Status Tuples (STs)",
    0xFD: "Next CCC",
    0xFE: "Error Detection Code",
  };
  const tags = parseFlatTLV(Array.from(data));
  return tags.map(t => ({
    label: CCC_TAGS[t.tag] ?? `Tag ${h(t.tag)}`,
    value: t.data.length <= 16 ? hexStr(t.data) : `${hexStr(t.data.slice(0, 12))}... (${t.data.length}B)`,
  }));
}

/** Decode CHUID (Card Holder Unique Identifier, tag 5FC102). */
function decodeCHUID(data) {
  const CHUID_TAGS = {
    0x30: "FASC-N",
    0x32: "Organizational Identifier",
    0x33: "DUNS",
    0x34: "GUID",
    0x35: "Expiration Date",
    0x36: "Cardholder UUID",
    0x3E: "Issuer Asymmetric Signature",
    0xFE: "Error Detection Code",
    0xEE: "Buffer Length",
  };
  const tags = parseFlatTLV(Array.from(data));
  return tags.map(t => {
    const label = CHUID_TAGS[t.tag] ?? `Tag ${h(t.tag)}`;
    let value;
    if (t.tag === 0x34 && t.data.length === 16) {
      // GUID as UUID format
      const hex = Array.from(t.data).map(b => h(b)).join("");
      value = `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
    } else if (t.tag === 0x35 && t.data.length === 8) {
      // Expiration as ASCII date
      value = String.fromCharCode(...t.data);
    } else if (t.tag === 0x3E) {
      value = `${t.data.length}B signature`;
    } else {
      value = t.data.length <= 16 ? hexStr(t.data) : `${hexStr(t.data.slice(0, 12))}... (${t.data.length}B)`;
    }
    return { label, value };
  });
}

/** Decode PUK+PIN credential block (16-byte, FF-padded). */
function decodeCredentialBlock(data) {
  if (!data || data.length !== 16) return null;
  const pukRaw = data.slice(0, 8).filter(b => b !== 0xFF && b !== 0x00);
  const pinRaw = data.slice(8, 16).filter(b => b !== 0xFF && b !== 0x00);
  const pukLen = pukRaw.length;
  const pinLen = pinRaw.length;
  return [
    { label: "PUK (bytes 0-7)", value: pukLen > 0 ? `${pukLen}-digit credential [redacted]` : "(empty / FF-padded)" },
    { label: "PIN (bytes 8-15)", value: pinLen > 0 ? `${pinLen}-digit credential [redacted]` : "(empty / FF-padded)" },
  ];
}

function ExchangeDecoders({ ex }) {
  const cmd = decodeCmd(ex.cmd.bytes);
  const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
  if (!cmd) return null;

  // YubiKey GET VERSION (INS 0xFD)
  if (cmd.ins === 0xFD && rsp?.sw === 0x9000 && rsp.data?.length >= 3) {
    const [major, minor, patch] = rsp.data;
    return (
      <div style={styles.container}>
        <span style={styles.label}>YubiKey Firmware Version</span>
        <div style={styles.row}>
          <span style={styles.key}>Version</span>
          <span style={styles.value}>{major}.{minor}.{patch}</span>
        </div>
      </div>
    );
  }

  // YubiKey GET SERIAL (INS 0x01 after Yubico management applet)
  if (cmd.ins === 0x01 && rsp?.sw === 0x9000 && rsp.data?.length === 4) {
    const serial = (rsp.data[0] << 24 | rsp.data[1] << 16 | rsp.data[2] << 8 | rsp.data[3]) >>> 0;
    return (
      <div style={styles.container}>
        <span style={styles.label}>YubiKey Serial Number</span>
        <div style={styles.row}>
          <span style={styles.key}>Serial</span>
          <span style={styles.value}>{serial}</span>
        </div>
      </div>
    );
  }

  // CHANGE REFERENCE DATA (INS 0x2C) with 16-byte credential block
  if ((cmd.ins === 0x2C || cmd.ins === 0x24) && cmd.data?.length === 16) {
    const fields = decodeCredentialBlock(Array.from(cmd.data));
    if (fields) return (
      <div style={styles.container}>
        <span style={styles.label}>{cmd.ins === 0x2C ? "CHANGE REFERENCE DATA" : "RESET RETRY COUNTER"} Credential Block</span>
        {fields.map((f, i) => (
          <div key={i} style={styles.row}>
            <span style={styles.key}>{f.label}</span>
            <span style={f.value.includes("redacted") ? styles.redacted : styles.value}>{f.value}</span>
          </div>
        ))}
        <div style={styles.row}>
          <span style={styles.key}>P2</span>
          <span style={styles.value}>{h(cmd.p2)} ({cmd.p2 === 0x80 ? "Global PIN" : cmd.p2 === 0x81 ? "PIV App PIN" : `ref ${h(cmd.p2)}`})</span>
        </div>
      </div>
    );
  }

  // Everything below requires a successful response with data
  if (!rsp || rsp.sw !== 0x9000 || !rsp.data?.length) return null;

  // CPLC (tag 9F7F)
  if ((cmd.ins === 0xCB || cmd.ins === 0xCA) && cmd.data) {
    const d = cmd.data;
    const tag = d[0] === 0x5C ? hexStr(d.slice(2, 2 + (d[1] ?? 0))).replace(/ /g, "") : "";

    if (tag === "9F7F" && rsp.data.length >= 42) {
      const cplc = decodeCPLC(rsp.data);
      if (cplc) return (
        <div style={styles.container}>
          <span style={styles.label}>CPLC — Card Production Life Cycle Data</span>
          {cplc.map((field, i) => (
            <div key={i} style={styles.row}>
              <span style={styles.key}>{field.label}</span>
              <span style={styles.value}>{field.value}</span>
            </div>
          ))}
        </div>
      );
    }

    // CCC (tag 7E)
    if (tag === "7E" && rsp.data.length >= 10) {
      const fields = decodeCCC(rsp.data);
      if (fields.length) return (
        <div style={styles.container}>
          <span style={styles.label}>CCC — Card Capability Container</span>
          {fields.map((f, i) => (
            <div key={i} style={styles.row}>
              <span style={styles.key}>{f.label}</span>
              <span style={styles.value}>{f.value}</span>
            </div>
          ))}
        </div>
      );
    }

    // CHUID (tag 5FC102)
    if (tag === "5FC102" && rsp.data.length >= 20) {
      const fields = decodeCHUID(rsp.data);
      if (fields.length) return (
        <div style={styles.container}>
          <span style={styles.label}>CHUID — Card Holder Unique Identifier</span>
          {fields.map((f, i) => (
            <div key={i} style={styles.row}>
              <span style={styles.key}>{f.label}</span>
              <span style={styles.value}>{f.value}</span>
            </div>
          ))}
        </div>
      );
    }
  }

  // GP key set (4D tag)
  if ((cmd.ins === 0xCB || cmd.ins === 0xCA) && cmd.data?.[0] === 0x4D) {
    const ks = decodeKeySetResponse(rsp.data);
    if (ks?.length) return (
      <div style={styles.container}>
        <span style={styles.label}>GP Key Set Information</span>
        {ks.map((k, i) => (
          <div key={i} style={styles.row}>
            <span style={styles.key}>Key {h(k.id)} (v{k.version})</span>
            <span style={styles.value}>{k.type} — {k.length * 8}-bit</span>
          </div>
        ))}
      </div>
    );
  }

  return null;
}

export default ExchangeDecoders;

/**
 * Specification database, TLV tag dictionary, and INS-to-spec mapping.
 *
 * Contains reference data for ISO 7816-4, GlobalPlatform Card Spec,
 * GP SCP03, NIST SP 800-73-4 (PIV), plus SafeNet vendor tags.
 * Used by the SpecPanel UI and the TLV annotator.
 */
// ── KNOWLEDGE ─────────────────────────────────────────────────────────────
// Spec database (ISO 7816, GP, PIV), TLV tag dictionary, INS-to-spec mapping.
import { hexStr, h } from "./decode.js";

const SPECS = {
  iso7816_4: { short: "ISO 7816-4", name: "ISO/IEC 7816-4: Organization, security and commands", url: "https://www.iso.org/standard/77180.html" },
  iso7816_5: { short: "ISO 7816-5", name: "ISO/IEC 7816-5: Registration of application providers", url: "https://www.iso.org/standard/34259.html" },
  gp_card:   { short: "GP Card 2.3", name: "GlobalPlatform Card Specification v2.3.1", url: "https://globalplatform.org/specs-library/card-specification-v2-3-1/" },
  gp_scp03:  { short: "GP SCP03", name: "GlobalPlatform Secure Channel Protocol 03", url: "https://globalplatform.org/specs-library/secure-channel-protocol-03-amendment-d-v1-1-2/" },
  nist_73:   { short: "SP 800-73-4", name: "NIST SP 800-73-4: Interfaces for Personal Identity Verification", url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf" },
  gp_cplc:   { short: "GP CPLC", name: "GlobalPlatform CPLC — Card Production Life Cycle Data", url: "https://globalplatform.org/specs-library/card-specification-v2-3-1/" },
};

const SPEC_DB = {
  iso7816_4: {
    key: "iso7816_4", short: "ISO 7816-4", access: "paid",
    title: "ISO/IEC 7816-4:2020 — Organization, security and commands",
    url: "https://www.iso.org/standard/77180.html", pdfUrl: null,
    description: "Foundational smart card command standard. Defines APDU structure, command set, status words, and BER-TLV.",
    sections: [
      { ref: "§6", title: "APDU structure", desc: "CLA, INS, P1, P2, Lc, Le fields" },
      { ref: "§10.1", title: "SELECT", desc: "INS 0xA4 — select application by AID" },
      { ref: "§10.7", title: "VERIFY", desc: "INS 0x20 — verify PIN; decrements retry counter" },
      { ref: "§10.9", title: "CHANGE REFERENCE DATA", desc: "INS 0x24/0x2C — change PIN or admin credential" },
      { ref: "§11.6", title: "GENERAL AUTHENTICATE", desc: "INS 0x87 — challenge-response authentication" },
      { ref: "Annex A", title: "Status words", desc: "Complete SW1 SW2 table" },
    ],
  },
  nist_73: {
    key: "nist_73", short: "SP 800-73-4", access: "free",
    title: "NIST SP 800-73-4 — Interfaces for Personal Identity Verification",
    url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf",
    pdfUrl: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf",
    description: "Defines the PIV card's data model, command set, and cryptographic mechanisms.",
    sections: [
      { ref: "§3.5", title: "GET DATA (INS 0xCB)", desc: "Read a PIV data object by tag", url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=32" },
      { ref: "§3.6", title: "PUT DATA (INS 0xDB)", desc: "Write a PIV data object", url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=34" },
      { ref: "§3.7", title: "GENERAL AUTHENTICATE (INS 0x87)", desc: "Cryptographic authentication", url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=35" },
      { ref: "Table 3", title: "PIV data objects & tags", url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=17" },
      { ref: "Appendix B", title: "Default card management key", desc: "01 02 03 04 05 06 07 08 (×2 for AES-128)", url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=52" },
    ],
  },
  gp_card: {
    key: "gp_card", short: "GP Card 2.3", access: "free-registration",
    title: "GlobalPlatform Card Specification v2.3.1",
    url: "https://globalplatform.org/specs-library/card-specification-v2-3-1/",
    pdfUrl: "https://globalplatform.org/wp-content/uploads/2017/04/GPC_2.3_E_1.pdf",
    description: "Defines GP card architecture: ISD, Security Domains, key management, SCP protocols.",
    sections: [
      { ref: "§7", title: "Issuer Security Domain", desc: "ISD, INITIALIZE UPDATE / EXTERNAL AUTHENTICATE" },
      { ref: "§10", title: "Security", desc: "Key diversification, SCP01/02/03, security level negotiation" },
      { ref: "Appendix A", title: "CPLC", desc: "42-byte Card Production Life Cycle structure" },
      { ref: "Appendix E", title: "Default static keys", desc: "40..4F — test-only, never production" },
    ],
  },
  gp_scp03: {
    key: "gp_scp03", short: "GP SCP03", access: "free-registration",
    title: "GlobalPlatform SCP03 — Secure Channel Protocol 03",
    url: "https://globalplatform.org/specs-library/secure-channel-protocol-03-amendment-d-v1-1-2/",
    pdfUrl: "https://globalplatform.org/wp-content/uploads/2017/09/GPC_2.2_F_SCP03_v1.0.pdf",
    description: "AES-based secure channel: mutual authentication, C-MAC, R-MAC, optional encryption.",
    sections: [
      { ref: "§3", title: "INITIALIZE UPDATE", desc: "INS 0x50: host challenge; card returns challenge + cryptogram" },
      { ref: "§4", title: "EXTERNAL AUTHENTICATE", desc: "INS 0x82: host proves key knowledge; sets security level" },
      { ref: "§5", title: "Session key derivation", desc: "S-ENC, S-MAC, S-RMAC via AES-CMAC KDF (NIST 800-108)" },
    ],
  },
};

const INS_SPECS = {
  0xA4: [{ key: "nist_73", ref: "§3.1" }, { key: "iso7816_4", ref: "§10.1" }],
  0xCB: [{ key: "nist_73", ref: "§3.5" }], 0xCA: [{ key: "nist_73", ref: "§3.5" }],
  0xDB: [{ key: "nist_73", ref: "§3.6" }],
  0x87: [{ key: "nist_73", ref: "§3.7" }, { key: "gp_scp03", ref: "§3" }],
  0x20: [{ key: "nist_73", ref: "§3.2" }, { key: "iso7816_4", ref: "§10.7" }],
  0x2C: [{ key: "iso7816_4", ref: "§10.9" }],
  0x82: [{ key: "gp_scp03", ref: "§4" }], 0x84: [{ key: "gp_scp03", ref: "§3" }],
};

const TLV_TAGS = {
  // SafeNet/Thales proprietary
  "4D": { name: "SafeNet Key Query", desc: "SafeNet proprietary key-slot query wrapper. Vendor-defined — no public spec.", spec: null },
  "5F FF 12": { name: "SafeNet Card Identity", desc: "SafeNet card label, serial number, and product code.", spec: null },
  "DF 30": { name: "SafeNet Firmware Version", desc: "SafeNet card firmware version. DF namespace is vendor-defined.", spec: null },
  "DF 34": { name: "SafeNet Key Directory", desc: "SafeNet directory of key containers.", spec: null },
  "DF 35": { name: "SafeNet Object List", desc: "SafeNet directory of all data objects.", spec: null },
  "DF 39": { name: "SafeNet Usage Counter", desc: "SafeNet operation counter. Increments on authenticated operations.", spec: null },
  "FF F3": { name: "SafeNet Key Container", desc: "SafeNet proprietary key container. Each sub-tag addresses one slot.", spec: null },
  // Standard ISO 7816-4
  "53": { name: "Discretionary Data", desc: "Application-defined discretionary data template.", spec: "iso7816_4" },
  "5C": { name: "Tag List", desc: "List of tags to retrieve in GET DATA.", spec: "iso7816_4" },
  "6F": { name: "FCI Template", desc: "File Control Information returned by SELECT.", spec: "iso7816_4" },
  "7C": { name: "Dynamic Auth Template", desc: "Dynamic authentication template per ISO 7816-4 §11.6. Sub-tags: 81=challenge, 82=response.", spec: "iso7816_4" },
  "80": { name: "Proprietary", desc: "Context-dependent primitive data.", spec: "iso7816_4" },
  "81": { name: "Challenge / Nonce", desc: "In 7C context: card-generated nonce or witness.", spec: "iso7816_4" },
  "82": { name: "Response / Cryptogram", desc: "In 7C context: host cryptogram proving key knowledge.", spec: "iso7816_4" },
  "83": { name: "Reference / Key ID", desc: "Key reference or object identifier.", spec: "iso7816_4" },
  "84": { name: "AID", desc: "Application Identifier per ISO 7816-5.", spec: "iso7816_5" },
  // GlobalPlatform
  "8A": { name: "Life Cycle State", desc: "INSTALLED(01), SELECTABLE(03), PERSONALIZED(05), BLOCKED(07).", spec: "gp_card" },
  "8C": { name: "Card Data", desc: "GP card data — card type, SCP version.", spec: "gp_card" },
  "9F 7F": { name: "CPLC", desc: "Card Production Life Cycle — chip manufacturer, OS, personalization data.", spec: "gp_card" },
  "A0": { name: "Application Template", desc: "GP application template containing AID and metadata.", spec: "gp_card" },
  "E2": { name: "Key Set Info", desc: "GP key set information record.", spec: "gp_card" },
  // PIV
  "5F C1": { name: "PIV Data Object", desc: "PIV data object by slot ID.", spec: "nist_73" },
  "7E": { name: "CCCID", desc: "Card Capability Container ID.", spec: "nist_73" },
  "FF 84": { name: "PIV Key Info", desc: "PIV key information by slot.", spec: "nist_73" },
  "FF 90": { name: "PIV Key Template", desc: "PIV key template (CRT: 7F48 algorithm info, 7F49 public key).", spec: "nist_73" },
};

function lookupTag(tagBytes) {
  const k = hexStr(tagBytes);
  return TLV_TAGS[k] ?? TLV_TAGS[h(tagBytes[0])] ?? null;
}

function interpretValue(tagBytes, valueBytes) {
  const k = hexStr(tagBytes);
  if (k === "DF 30") { try { return `"${String.fromCharCode(...valueBytes.filter(b => b >= 0x20 && b < 0x7F))}"` } catch { return null; } }
  if (k === "DF 39") { const v = valueBytes.reduce((a, b) => (a << 8) | b, 0); return `0x${v.toString(16).padStart(8,"0").toUpperCase()} (${v} uses)`; }
  if ((k === "84" || k === "4F") && valueBytes.length >= 5) return `AID: ${hexStr(valueBytes)}`;
  if (k === "8A" && valueBytes.length === 1) return ({ 0x01:"INSTALLED", 0x03:"SELECTABLE", 0x05:"PERSONALIZED", 0x07:"BLOCKED", 0x0F:"LOCKED" })[valueBytes[0]] ?? `0x${h(valueBytes[0])}`;
  return null;
}


export { SPECS, SPEC_DB, INS_SPECS, TLV_TAGS, lookupTag, interpretValue };

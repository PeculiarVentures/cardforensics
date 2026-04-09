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
  emv:       { short: "EMV", name: "EMV Contactless Specifications for Payment Systems (Books 1-4)", url: "https://www.emvco.com/emv-technologies/contact/" },
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
  emv: {
    key: "emv", short: "EMV", access: "free-registration",
    title: "EMV Contactless Specifications for Payment Systems",
    url: "https://www.emvco.com/emv-technologies/contact/",
    pdfUrl: null,
    description: "Defines payment card transaction flow: application selection, card authentication, cardholder verification, and transaction processing.",
    sections: [
      { ref: "Book 1 §12", title: "Application Selection", desc: "PSE/PPSE directory, AID matching, application priority" },
      { ref: "Book 3 §6.5", title: "GET PROCESSING OPTIONS", desc: "INS 0xA8 — initialize transaction, return AIP + AFL" },
      { ref: "Book 3 §7", title: "READ APPLICATION DATA", desc: "Read records from SFIs indicated by AFL" },
      { ref: "Book 3 §10", title: "Cardholder Verification", desc: "CVM list processing — PIN, signature, no CVM" },
      { ref: "Book 3 §11", title: "Terminal Risk Management", desc: "Floor limits, random selection, velocity checking" },
    ],
  },
};

const INS_SPECS = {
  0xA4: [{ key: "nist_73", ref: "§3.1" }, { key: "iso7816_4", ref: "§10.1" }, { key: "emv", ref: "Book 1 §12" }],
  0xCB: [{ key: "nist_73", ref: "§3.5" }], 0xCA: [{ key: "nist_73", ref: "§3.5" }],
  0xDB: [{ key: "nist_73", ref: "§3.6" }],
  0x87: [{ key: "nist_73", ref: "§3.7" }, { key: "gp_scp03", ref: "§3" }],
  0x20: [{ key: "nist_73", ref: "§3.2" }, { key: "iso7816_4", ref: "§10.7" }],
  0x2C: [{ key: "iso7816_4", ref: "§10.9" }],
  0x82: [{ key: "gp_scp03", ref: "§4" }], 0x84: [{ key: "gp_scp03", ref: "§3" }],
  // EMV-specific instructions
  0xA8: [{ key: "emv", ref: "Book 3 §6.5" }],   // GET PROCESSING OPTIONS
  0xB2: [{ key: "emv", ref: "Book 3 §7" }],      // READ RECORD
  0xAE: [{ key: "emv", ref: "Book 3 §6.5.8" }],  // GENERATE AC
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
  // ── EMV tags (informed by card-spy emv-tags.ts, https://github.com/tomkp/card-spy) ──
  "4F": { name: "AID", desc: "Application Identifier (DF name).", spec: "emv" },
  "50": { name: "Application Label", desc: "Mnemonic associated with the AID (1-16 alphanumeric chars).", spec: "emv" },
  "57": { name: "Track 2 Equivalent", desc: "Track 2 data (contains PAN, expiry, service code). SENSITIVE.", spec: "emv" },
  "5A": { name: "PAN", desc: "Primary Account Number. SENSITIVE — should not appear in cleartext.", spec: "emv" },
  "5F 20": { name: "Cardholder Name", desc: "Cardholder name in extended ASCII.", spec: "emv" },
  "5F 24": { name: "Expiration Date", desc: "Application expiration date (YYMMDD).", spec: "emv" },
  "5F 25": { name: "Effective Date", desc: "Application effective date (YYMMDD).", spec: "emv" },
  "5F 28": { name: "Issuer Country Code", desc: "ISO 3166-1 country code of card issuer.", spec: "emv" },
  "5F 2A": { name: "Transaction Currency Code", desc: "ISO 4217 currency code for this transaction.", spec: "emv" },
  "5F 2D": { name: "Language Preference", desc: "1-4 language codes (ISO 639-1) preferred by cardholder.", spec: "emv" },
  "5F 34": { name: "PAN Sequence Number", desc: "Distinguishes cards with the same PAN.", spec: "emv" },
  "61": { name: "Application Template", desc: "Contains AID and optional label in PSE/PPSE directory.", spec: "emv" },
  "70": { name: "EMV Record Template", desc: "Record data read from application files.", spec: "emv" },
  "77": { name: "Response Template (Format 2)", desc: "Constructed response to GPO — contains AIP + AFL.", spec: "emv" },
  "87": { name: "Application Priority", desc: "Priority indicator for application selection.", spec: "emv" },
  "88": { name: "SFI", desc: "Short File Identifier for READ RECORD.", spec: "emv" },
  "8E": { name: "CVM List", desc: "Cardholder Verification Method list — PIN, signature, no-CVM rules.", spec: "emv" },
  "8F": { name: "CA Public Key Index", desc: "Index of Certification Authority public key for SDA/DDA.", spec: "emv" },
  "90": { name: "Issuer PK Certificate", desc: "Certificate containing the issuer public key.", spec: "emv" },
  "92": { name: "Issuer PK Remainder", desc: "Remaining bytes of issuer public key (if needed).", spec: "emv" },
  "93": { name: "Signed Static App Data", desc: "Digitally signed static application data (SDA).", spec: "emv" },
  "94": { name: "AFL", desc: "Application File Locator — which records to read for transaction.", spec: "emv" },
  "95": { name: "TVR", desc: "Terminal Verification Results (5 bytes of risk flags).", spec: "emv" },
  "9A": { name: "Transaction Date", desc: "Local date of transaction (YYMMDD).", spec: "emv" },
  "9C": { name: "Transaction Type", desc: "00=purchase, 01=cash advance, 09=purchase+cashback, 20=refund.", spec: "emv" },
  "9F 02": { name: "Amount Authorized", desc: "Transaction amount in minor units.", spec: "emv" },
  "9F 03": { name: "Amount Other", desc: "Secondary amount (e.g. cashback).", spec: "emv" },
  "9F 06": { name: "AID (Terminal)", desc: "AID used by the terminal for this transaction.", spec: "emv" },
  "9F 07": { name: "AUC", desc: "Application Usage Control — domestic/intl, cash/goods, ATM restrictions.", spec: "emv" },
  "9F 08": { name: "App Version Number", desc: "Card application version assigned by payment scheme.", spec: "emv" },
  "9F 0D": { name: "IAC Default", desc: "Issuer Action Code — default conditions for offline decline.", spec: "emv" },
  "9F 0E": { name: "IAC Denial", desc: "Issuer Action Code — conditions that always cause denial.", spec: "emv" },
  "9F 0F": { name: "IAC Online", desc: "Issuer Action Code — conditions requiring online authorization.", spec: "emv" },
  "9F 10": { name: "Issuer Application Data", desc: "Proprietary data from issuer for online auth message.", spec: "emv" },
  "9F 12": { name: "App Preferred Name", desc: "Preferred name for application (in language of 5F2D).", spec: "emv" },
  "9F 17": { name: "PIN Try Counter", desc: "Remaining offline PIN verification attempts.", spec: "emv" },
  "9F 1A": { name: "Terminal Country Code", desc: "Country code of terminal.", spec: "emv" },
  "9F 1F": { name: "Track 1 Discretionary", desc: "Track 1 discretionary data. May contain SENSITIVE cardholder info.", spec: "emv" },
  "9F 26": { name: "Application Cryptogram", desc: "Card-generated cryptogram (TC, ARQC, or AAC).", spec: "emv" },
  "9F 27": { name: "CID", desc: "Cryptogram Information Data — identifies cryptogram type.", spec: "emv" },
  "9F 32": { name: "Issuer PK Exponent", desc: "Exponent of the issuer public key.", spec: "emv" },
  "9F 33": { name: "Terminal Capabilities", desc: "Terminal input/CVM/security capabilities.", spec: "emv" },
  "9F 34": { name: "CVM Results", desc: "Cardholder verification method actually applied.", spec: "emv" },
  "9F 36": { name: "ATC", desc: "Application Transaction Counter — increments each transaction.", spec: "emv" },
  "9F 37": { name: "Unpredictable Number", desc: "Random number generated by terminal for each transaction.", spec: "emv" },
  "9F 38": { name: "PDOL", desc: "Processing Data Object List — terminal data requested by card for GPO.", spec: "emv" },
  "9F 42": { name: "App Currency Code", desc: "Currency code associated with the application.", spec: "emv" },
  "9F 46": { name: "ICC PK Certificate", desc: "Certificate containing the ICC public key for DDA/CDA.", spec: "emv" },
  "9F 47": { name: "ICC PK Exponent", desc: "Exponent of the ICC public key.", spec: "emv" },
  "9F 48": { name: "ICC PK Remainder", desc: "Remaining bytes of ICC public key (if needed).", spec: "emv" },
  "9F 49": { name: "DDOL", desc: "Dynamic Data Object List — data for internal authenticate.", spec: "emv" },
  "9F 4A": { name: "SDA Tag List", desc: "List of tags included in Static Data Authentication.", spec: "emv" },
  "A5": { name: "FCI Proprietary Template", desc: "Proprietary data within FCI returned by SELECT.", spec: "emv" },
  "BF 0C": { name: "FCI Issuer Discretionary", desc: "Issuer-specific data in FCI (may contain directory entries).", spec: "emv" },
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
  // EMV value interpreters
  if (k === "50" || k === "5F 20" || k === "5F 2D" || k === "9F 12") {
    // Text fields: Application Label, Cardholder Name, Language Preference, App Preferred Name
    try { return `"${String.fromCharCode(...valueBytes.filter(b => b >= 0x20 && b < 0x7F))}"` } catch { return null; }
  }
  if (k === "5A") {
    // PAN — mask middle digits for display
    const pan = valueBytes.map(b => h(b)).join("").replace(/F+$/i, "");
    if (pan.length >= 8) return `PAN: ${pan.substring(0, 4)}****${pan.substring(pan.length - 4)}`;
    return `PAN: ${pan}`;
  }
  if (k === "5F 24" || k === "5F 25" || k === "9A") {
    // Date fields: YYMMDD BCD
    if (valueBytes.length >= 3) return `20${h(valueBytes[0])}/${h(valueBytes[1])}/${h(valueBytes[2])}`;
  }
  if (k === "9C" && valueBytes.length === 1) {
    return ({ 0x00:"Purchase", 0x01:"Cash Advance", 0x09:"Purchase+Cashback", 0x20:"Refund" })[valueBytes[0]] ?? `Type 0x${h(valueBytes[0])}`;
  }
  if (k === "9F 27" && valueBytes.length === 1) {
    const type = (valueBytes[0] >> 6) & 0x03;
    return ({ 0:"AAC (decline)", 1:"TC (offline approve)", 2:"ARQC (online request)" })[type] ?? `CID 0x${h(valueBytes[0])}`;
  }
  if (k === "9F 36" && valueBytes.length === 2) {
    const atc = (valueBytes[0] << 8) | valueBytes[1];
    return `ATC: ${atc} transactions`;
  }
  if (k === "9F 17" && valueBytes.length === 1) {
    return `${valueBytes[0]} PIN tries remaining`;
  }
  return null;
}


export { SPECS, SPEC_DB, INS_SPECS, TLV_TAGS, lookupTag, interpretValue };

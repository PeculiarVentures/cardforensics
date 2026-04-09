/**
 * Application Identifier (AID) database for SELECT command annotation.
 *
 * Sources:
 *  - EMV/eID/OpenPGP/FIDO AIDs informed by card-spy handler definitions
 *    (https://github.com/tomkp/card-spy)
 *  - PIV/GP AIDs from existing CardForensics knowledge base
 *  - ISO 7816-5, EMV Book 1, NIST SP 800-73-4, FIDO Alliance specs
 *
 * Each entry maps an AID hex prefix to a name and category.
 * Lookup is prefix-based: the longest matching prefix wins.
 */

/** @type {Array<{ prefix: string, name: string, category: string }>} */
const AID_ENTRIES = [
  // ── EMV / Payment ──
  { prefix: "A0000000041010",   name: "Mastercard Credit/Debit",       category: "payment" },
  { prefix: "A0000000043060",   name: "Mastercard Maestro",            category: "payment" },
  { prefix: "A0000000042203",   name: "Mastercard US Maestro",         category: "payment" },
  { prefix: "A00000000410101213", name: "Mastercard PayPass M/Chip",   category: "payment" },
  { prefix: "A00000000410101215", name: "Mastercard PayPass MStripe",  category: "payment" },
  { prefix: "A000000003101001", name: "Visa Credit",                   category: "payment" },
  { prefix: "A000000003101002", name: "Visa Debit",                    category: "payment" },
  { prefix: "A0000000031010",   name: "Visa Credit/Debit",            category: "payment" },
  { prefix: "A0000000032010",   name: "Visa Electron",                category: "payment" },
  { prefix: "A0000000033010",   name: "Visa Interlink",               category: "payment" },
  { prefix: "A0000000038010",   name: "Visa Plus",                    category: "payment" },
  { prefix: "A0000000038002",   name: "Visa Plus",                    category: "payment" },
  { prefix: "A0000000039010",   name: "Visa V Pay",                   category: "payment" },
  { prefix: "A000000025010104", name: "American Express",              category: "payment" },
  { prefix: "A000000025010701", name: "American Express ExpressPay",   category: "payment" },
  { prefix: "A0000001523010",   name: "Discover",                     category: "payment" },
  { prefix: "A0000001524010",   name: "Discover Common Debit",        category: "payment" },
  { prefix: "A0000000651010",   name: "JCB",                          category: "payment" },
  { prefix: "A0000002771010",   name: "Interac",                      category: "payment" },
  { prefix: "325041592E5359532E4444463031", name: "PSE (Payment System Environment)", category: "payment" },
  { prefix: "325041592E5359532E444446303031", name: "PPSE (Proximity PSE)",           category: "payment" },

  // ── PIV / US Government ──
  { prefix: "A000000308000010000100", name: "NIST PIV",                category: "piv" },
  { prefix: "A00000030800001000",     name: "NIST PIV",                category: "piv" },
  { prefix: "A000000308000010",       name: "NIST PIV",                category: "piv" },

  // ── Yubico ──
  { prefix: "A000000527",       name: "Yubico PIV",                   category: "piv" },
  { prefix: "A0000005272101",   name: "Yubico OTP",                   category: "security-key" },

  // ── OpenPGP ──
  { prefix: "D27600012401",     name: "OpenPGP",                      category: "pki" },

  // ── FIDO / WebAuthn ──
  { prefix: "A0000006472F0001", name: "FIDO U2F",                     category: "fido" },
  { prefix: "A0000006472F0002", name: "FIDO2 / CTAP2",               category: "fido" },

  // ── GlobalPlatform ──
  { prefix: "A000000151000000", name: "GP ISD (Issuer Security Domain)", category: "gp" },
  { prefix: "A0000001510000",   name: "GP Card Manager",              category: "gp" },

  // ── eID: Belgian ──
  { prefix: "A000000177504B43532D3135", name: "Belgian eID (BELPIC)",  category: "eid" },

  // ── eID: German ──
  { prefix: "E80704007F00070302",       name: "German eID (nPA)",      category: "eid" },
  { prefix: "A000000167455349474E",     name: "German eSign",          category: "eid" },

  // ── eID: Estonian ──
  { prefix: "D23300000045737445494420763335", name: "Estonian eID",     category: "eid" },
  { prefix: "A000000077010800070000FE00000100", name: "Estonian eID Auth", category: "eid" },

  // ── eID: Portuguese ──
  { prefix: "D2760001354B414E4D31",     name: "Portuguese Citizen Card", category: "eid" },

  // ── eID: Spanish ──
  { prefix: "A00000006303100102",       name: "Spanish DNIe Auth",     category: "eid" },
  { prefix: "A0000000630310",           name: "Spanish DNIe",          category: "eid" },

  // ── eID: Italian ──
  { prefix: "A0000000308001",           name: "Italian CIE",           category: "eid" },

  // ── eID: Generic IAS-ECC ──
  { prefix: "A0000000770101",           name: "IAS-ECC",               category: "eid" },

  // ── Gemalto / Thales ──
  { prefix: "A0000001520000",   name: "Gemalto IDPrime",              category: "pki" },

  // ── Health cards ──
  { prefix: "D2760001448000",   name: "German Health Card (eGK)",     category: "health" },
  { prefix: "A0000000040000",   name: "European Health Insurance (EHIC)", category: "health" },
];

// Sort by prefix length descending so longest-prefix match wins
AID_ENTRIES.sort((a, b) => b.prefix.length - a.prefix.length);

/**
 * Look up an AID by prefix match (longest match wins).
 * @param {string} aidHex - AID as uppercase hex string (no spaces)
 * @returns {{ name: string, category: string, prefix: string }|null}
 */
export function lookupAID(aidHex) {
  if (!aidHex) return null;
  const norm = aidHex.toUpperCase().replace(/\s+/g, "");
  for (const entry of AID_ENTRIES) {
    if (norm.startsWith(entry.prefix)) return entry;
  }
  return null;
}

/**
 * Get all known AIDs (for UI display / filtering).
 * @returns {Array<{ prefix: string, name: string, category: string }>}
 */
export function getAllAIDs() {
  return AID_ENTRIES;
}

/** Category display labels. */
export const AID_CATEGORIES = {
  payment: "Payment / EMV",
  piv: "PIV / US Government",
  pki: "PKI / Certificates",
  fido: "FIDO / WebAuthn",
  gp: "GlobalPlatform",
  eid: "Electronic Identity",
  health: "Health Card",
  "security-key": "Security Key",
};

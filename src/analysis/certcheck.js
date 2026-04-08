/**
 * PIV certificate slot provisioning checker.
 *
 * Uses FINAL observed state across the entire trace. If a cert slot
 * returns 6A80 during early discovery but 9000 after provisioning,
 * the final state is "populated".
 *
 * Accepts an optional objectLedger for cross-referencing: if the ledger
 * recorded a successful read for a cert tag, that overrides any
 * earlier "absent" observation.
 */
import { h, hexStr, decodeCmd, decodeRsp } from "../decode.js";

/** PIV certificate data object tags and their slot assignments. */
export const PIV_CERT_SLOT_TAGS = {
  "5FC105": { name: "PIV Authentication", slot: "9A", required: true  },
  "5FC10A": { name: "Digital Signature",  slot: "9C", required: true  },
  "5FC10B": { name: "Key Management",     slot: "9D", required: false },
  "5FC101": { name: "Card Authentication", slot: "9E", required: false },
};

/**
 * Extract the cert slot tag hex from a GET DATA command, if any.
 * Handles both INS CB (tag list in data) and INS CA (tag in P1/P2).
 */
function extractCertTag(cmd) {
  if (!cmd) return null;
  // INS CB: tag list in data field (5C LL tag...)
  if (cmd.ins === 0xCB && cmd.data?.[0] === 0x5C && cmd.data[1] >= 2) {
    return hexStr(cmd.data.slice(2, 2 + cmd.data[1])).replace(/ /g, "").toUpperCase();
  }
  // INS CA: some implementations encode tag in P1/P2
  if (cmd.ins === 0xCA && (cmd.p1 || cmd.p2)) {
    // Try matching P1||P2 as a 2-byte prefix against known 3-byte tags
    const p1p2 = `${h(cmd.p1)}${h(cmd.p2)}`.toUpperCase();
    for (const tag of Object.keys(PIV_CERT_SLOT_TAGS)) {
      if (tag.startsWith(p1p2)) return tag;
    }
  }
  return null;
}

/**
 * Check which PIV certificate slots are populated vs empty.
 * Uses final observed state (last successful read wins).
 *
 * @param {object[]} exchanges - All APDU exchanges
 * @param {object[]} objectLedger - Optional ledger for cross-reference
 * @returns {{ probed, populated, absent, slotDetails, allEmpty, partial, full }}
 */
export function checkCertProvisioning(exchanges, objectLedger) {
  const results = {};

  // Pass 1: scan all GET DATA commands for cert slot tags
  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes);
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    if (!cmd || !rsp) continue;
    if (cmd.ins !== 0xCB && cmd.ins !== 0xCA) continue;

    const tagHex = extractCertTag(cmd);
    if (!tagHex || !PIV_CERT_SLOT_TAGS[tagHex]) continue;

    const entry = results[tagHex] ?? { probed: false, populated: false, size: 0, lastSW: 0, exchangeId: null };
    entry.probed = true;
    entry.lastSW = rsp.sw;
    entry.exchangeId = ex.id; // always track latest exchange for this slot
    // Populated is sticky: once a successful read with data is seen, it stays populated
    if (rsp.sw === 0x9000 && rsp.data?.length > 50) {
      entry.populated = true;
      entry.size = Math.max(entry.size, rsp.data.length);
      entry.populatedExId = ex.id; // track the successful read specifically
    }
    results[tagHex] = entry;
  }

  // Pass 2: cross-reference with object ledger if available
  if (objectLedger) {
    for (const obj of objectLedger) {
      const normalized = obj.id.replace(/ /g, "").toUpperCase();
      if (PIV_CERT_SLOT_TAGS[normalized] && obj.reads?.ok > 0 && obj.size > 50) {
        const entry = results[normalized] ?? { probed: false, populated: false, size: 0, lastSW: 0 };
        entry.probed = true;
        entry.populated = true;
        entry.size = Math.max(entry.size, obj.size ?? 0);
        results[normalized] = entry;
      }
    }
  }

  const probed = Object.keys(results);
  const populated = probed.filter(t => results[t].populated);
  const absent = probed.filter(t => !results[t].populated);
  return {
    probed, populated, absent, slotDetails: results,
    allEmpty: probed.length > 0 && populated.length === 0,
    partial: populated.length > 0 && absent.length > 0,
    full: Object.keys(PIV_CERT_SLOT_TAGS).filter(t => PIV_CERT_SLOT_TAGS[t].required).every(t => results[t]?.populated),
  };
}

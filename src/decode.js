/**
 * APDU decoding, hex formatting, and CryptoTokenKit log parsing.
 *
 * Pure functions with no project dependencies. This is the foundation
 * module — everything else imports from here.
 *
 * Naming: `h()` and `hexStr()` are intentionally short because they
 * appear hundreds of times in format strings and TLV builders.
 */

// ── Hex Formatting ───────────────────────────────────────────────────────

/** djb2 hash of first 500 chars. Stable cache key per log file. */
export function traceHash(log) {
  let hash = 5381;
  const sample = log.slice(0, 500);
  for (let i = 0; i < sample.length; i++) hash = ((hash << 5) + hash) ^ sample.charCodeAt(i);
  return (hash >>> 0).toString(36);
}

/** Format byte as uppercase hex. Short name — used hundreds of times. */
export const h = (byte, pad = 2) => (byte ?? 0).toString(16).padStart(pad, "0").toUpperCase();

/** Format byte array as space-separated uppercase hex. */
export const hexStr = (arr) => (arr || []).map(b => h(b)).join(" ");

// ── Instruction & Status Word Lookup ─────────────────────────────────────

/** Human-readable names for common ISO 7816-4 / GP / PIV / EMV instructions. */
export const INS_MAP = {
  0xA4: "SELECT",       0xCB: "GET DATA",    0xCA: "GET DATA",
  0xDB: "PUT DATA",     0x87: "GEN AUTH",     0x82: "EXT AUTH",
  0x84: "GET CHALLENGE", 0x2C: "CHG REF DATA", 0x20: "VERIFY",
  0xE2: "APPEND RECORD", 0xF2: "GET STATUS",
  0xFD: "YUBI GET VERSION", 0x01: "YUBI GET SERIAL",
  // EMV
  0xA8: "GET PROCESSING OPTIONS", 0xB2: "READ RECORD", 0xAE: "GENERATE AC",
  0x88: "INTERNAL AUTH",
};

/** Well-known status words with severity classification. */
export const SW_MAP = {
  0x9000: { msg: "Success",                        s: "ok"   },
  0x6200: { msg: "No info — NV unchanged",          s: "warn" },
  0x6800: { msg: "No info given",                   s: "warn" },
  0x6881: { msg: "Channel unsupported",             s: "warn" },
  0x6982: { msg: "Security status not satisfied",   s: "err"  },
  0x6983: { msg: "Auth method blocked",             s: "err"  },
  0x6984: { msg: "Reference data invalidated",      s: "err"  },
  0x6985: { msg: "Conditions of use not satisfied", s: "err"  },
  0x6987: { msg: "Missing SM data objects",         s: "err"  },
  0x6988: { msg: "Incorrect SM data objects",       s: "err"  },
  0x6A80: { msg: "Wrong data",                      s: "err"  },
  0x6A81: { msg: "Function not supported",          s: "warn" },
  0x6A82: { msg: "File/app not found",              s: "err"  },
  0x6A83: { msg: "Record not found",                s: "err"  },
  0x6A84: { msg: "Not enough memory",               s: "err"  },
  0x6A86: { msg: "Bad P1/P2",                       s: "err"  },
  0x6A88: { msg: "Reference data not found",        s: "err"  },
  0x6D00: { msg: "INS not supported",               s: "warn" },
  0x6E00: { msg: "CLA not supported",               s: "warn" },
  0x6F00: { msg: "Unknown error",                   s: "err"  },
};

/**
 * Look up a 16-bit status word. Handles 61xx (pending data)
 * and 63Cx (retry counter) ranges dynamically.
 * @param {number} sw - 16-bit status word (e.g. 0x9000)
 * @returns {{ msg: string, s: "ok"|"err"|"warn"|"info" }}
 */
export function lookupSW(sw) {
  if (SW_MAP[sw]) return SW_MAP[sw];
  if ((sw >> 8) === 0x61) return { msg: `${sw & 0xff}B pending`, s: "ok" };
  if ((sw >> 8) === 0x63) return { msg: `Retries: ${sw & 0x0f}`, s: "warn" };
  return { msg: `SW ${h(sw >> 8)}${h(sw & 0xff)}`, s: "info" };
}

/**
 * Describe CLA byte: ISO channel, GP channel, secure messaging.
 * @param {number} cla - Class byte
 * @returns {string} Human-readable CLA description
 */
export function descCLA(cla) {
  if (cla & 0x80) {
    const ch = cla & 0x03, sm = (cla >> 2) & 0x03;
    return ch ? `GP ch${ch}${sm ? " SM" : ""}` : `GP${sm ? " SM" : ""}`;
  }
  if (cla & 0x40) {
    const ch = (cla & 0x0F) + 4, sm = (cla >> 4) & 0x03;
    return `ch${ch}${sm ? " SM" : ""}`;
  }
  const ch = cla & 0x03, sm = (cla >> 2) & 0x03;
  return ch ? `ch${ch}${sm ? " SM" : ""}` : sm ? "ISO SM" : "ISO";
}

// ── APDU Command / Response Parsing ──────────────────────────────────────

/**
 * Parse raw command APDU bytes into structured fields.
 * Handles both short-form and extended Lc/Le.
 *
 * @param {number[]} bytes - Raw command bytes
 * @returns {{ cla: number, ins: number, p1: number, p2: number,
 *             lc: number|null, data: number[], le: number|null }} | null
 */
export function decodeCmd(bytes) {
  if (!bytes || bytes.length < 2) return null;
  const [cla, ins, p1 = 0, p2 = 0] = bytes;
  let lc = null, data = [], le = null;
  if (bytes.length > 4) {
    const b4 = bytes[4];
    if (b4 === 0x00 && bytes.length > 7) {
      // Extended APDU: Lc = bytes[5:7] (big-endian 16-bit)
      const extLc = (bytes[5] << 8) | bytes[6];
      if (extLc > 0 && bytes.length >= 7 + extLc) {
        lc = extLc;
        data = Array.from(bytes.slice(7, 7 + extLc));
        if (bytes.length > 7 + extLc) le = (bytes[7 + extLc] << 8) | (bytes[8 + extLc] ?? 0);
      } else if (extLc === 0 && bytes.length === 7) {
        le = 65536; // Extended Le only
      } else {
        lc = 0; data = Array.from(bytes.slice(5)); // Fallback
      }
    } else if (bytes.length === 5) {
      le = b4 === 0 ? 256 : b4;
    } else if (bytes.length === 5 + b4) {
      lc = b4; data = Array.from(bytes.slice(5));
    } else if (bytes.length === 6 + b4) {
      lc = b4; data = Array.from(bytes.slice(5, 5 + b4)); le = bytes[5 + b4];
    } else {
      lc = b4; data = Array.from(bytes.slice(5));
    }
  }
  return { cla, ins, p1, p2, lc, data, le };
}

/**
 * Parse raw response APDU bytes into data + status word.
 * @param {number[]} bytes - Raw response bytes (minimum 2 for SW)
 * @returns {{ sw1: number, sw2: number, sw: number, data: number[] }} | null
 */
export function decodeRsp(bytes) {
  if (!bytes || bytes.length < 2) return null;
  const sw1 = bytes[bytes.length - 2], sw2 = bytes[bytes.length - 1];
  return { sw1, sw2, sw: (sw1 << 8) | sw2, data: bytes.slice(0, -2) };
}

// ── Log Parsing ──────────────────────────────────────────────────────────

/**
 * Parse macOS CryptoTokenKit log lines into structured APDU entries.
 * Expects lines matching the format:
 *   YYYY-MM-DD HH:MM:SS.nnn ... APDU -> xx xx xx ...
 *   YYYY-MM-DD HH:MM:SS.nnn ... APDU <- xx xx xx ...
 *
 * @param {string} raw - Full log file contents
 * @returns {{ ts: string, thread: string, dir: "->"|"<-", hex: string, bytes: number[] }[]}
 */
export function parseEntries(raw) {
  const entries = [];
  for (const line of raw.split("\n")) {
    const m = line.match(
      /(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)[^\s]*\s+(0x[0-9a-fA-F]+)\s+\w+\s+\S+\s+\d+\s+\d+.*APDU\s+(->|<-)\s+([0-9a-f]{2}(?:\s[0-9a-f]{2})*)/i
    );
    if (!m) continue;
    entries.push({
      ts: m[1], thread: m[2], dir: m[3],
      hex: m[4].trim(),
      bytes: m[4].trim().split(/\s+/).map(x => parseInt(x, 16)),
    });
  }
  return entries;
}

/**
 * Pair command/response entries and collapse 61xx GET RESPONSE chains.
 *
 * When the card returns SW 61xx ("more data available"), the host issues
 * GET RESPONSE commands to retrieve the remaining data. This function
 * reassembles the full response payload into a single logical exchange
 * and records the continuation count.
 *
 * @param {{ ts, dir, hex, bytes }[]} entries - Parsed log entries
 * @returns {{ id: number, cmd: object, rsp: object|null, continuations: number }[]}
 */
export function buildExchanges(entries) {
  const raw = [];
  let i = 0;
  while (i < entries.length) {
    if (entries[i].dir === "->") {
      const cmd = entries[i];
      const rsp = i + 1 < entries.length && entries[i + 1].dir === "<-" ? entries[i + 1] : null;
      raw.push({ cmd, rsp });
      i += rsp ? 2 : 1;
    } else { i++; }
  }

  const exchanges = [];
  let j = 0;
  while (j < raw.length) {
    const base = raw[j];
    const rspBytes = base.rsp?.bytes;

    // Check for 61xx chaining (more data available)
    if (rspBytes?.length >= 2 && rspBytes[rspBytes.length - 2] === 0x61) {
      let accData = Array.from(rspBytes.slice(0, -2));
      let sw1 = rspBytes[rspBytes.length - 2];
      let sw2 = rspBytes[rspBytes.length - 1];
      let continuations = 0, lastTs = base.rsp.ts;

      while (sw1 === 0x61 && j + 1 + continuations < raw.length) {
        const next = raw[j + 1 + continuations];
        const nc = decodeCmd(next.cmd.bytes);
        if (!nc || nc.ins !== 0xC0) break;
        const nr = next.rsp?.bytes;
        if (!nr || nr.length < 2) break;
        accData = accData.concat(Array.from(nr.slice(0, -2)));
        sw1 = nr[nr.length - 2]; sw2 = nr[nr.length - 1];
        lastTs = next.rsp.ts; continuations++;
      }

      const assembled = new Uint8Array([...accData, sw1, sw2]);
      exchanges.push({
        id: exchanges.length, cmd: base.cmd,
        rsp: { ...base.rsp, bytes: Array.from(assembled), hex: Array.from(assembled).map(b => b.toString(16).padStart(2, "0")).join(" "), ts: lastTs, assembled: true, continuations },
        continuations,
      });
      j += 1 + continuations;
    } else {
      exchanges.push({ id: exchanges.length, cmd: base.cmd, rsp: base.rsp, continuations: 0 });
      j++;
    }
  }
  return exchanges;
}

// ── Time Helpers ─────────────────────────────────────────────────────────

/** Parse timestamp string to seconds since midnight. */
export function timeToSec(ts) {
  const [hh, mm, ss] = ts.split(" ")[1].split(":").map(parseFloat);
  return hh * 3600 + mm * 60 + ss;
}

/** Calculate command-to-response execution time in milliseconds. */
export function execDeltaMs(ex) {
  if (!ex.rsp?.ts || !ex.cmd?.ts) return null;
  return Math.round((timeToSec(ex.rsp.ts) - timeToSec(ex.cmd.ts)) * 1000);
}

/**
 * Extract ATR (Answer To Reset) from raw log text.
 * Looks for common CTK/PC/SC ATR patterns in the log. ATR values
 * start with 0x3B (direct convention) or 0x3F (inverse convention).
 * @param {string} raw - Full log file contents
 * @returns {string|null} ATR hex string (uppercase, no spaces) or null
 */
export function extractATR(raw) {
  // Pattern 1: "ATR: 3B xx xx ..." or "ATR = 3B xx xx ..."
  const m1 = raw.match(/ATR\s*[:=]\s*((?:3[BbFf][\s]*(?:[0-9a-fA-F]{2}[\s]*){2,}))/i);
  if (m1) return m1[1].replace(/\s+/g, "").toUpperCase();
  // Pattern 2: "received ATR" or "power on" followed by hex bytes on same or next line
  const m2 = raw.match(/(?:received\s+ATR|power\s*on|card\s+reset)\s*[:=\s]*(3[BbFf](?:\s*[0-9a-fA-F]{2}){2,})/i);
  if (m2) return m2[1].replace(/\s+/g, "").toUpperCase();
  // Pattern 3: standalone hex line starting with 3B/3F that looks like an ATR (8-40 bytes)
  for (const line of raw.split("\n").slice(0, 50)) {
    const m3 = line.match(/\b(3[BbFf](?:\s*[0-9a-fA-F]{2}){7,39})\b/i);
    if (m3 && !line.includes("APDU")) return m3[1].replace(/\s+/g, "").toUpperCase();
  }
  return null;
}

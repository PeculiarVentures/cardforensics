/**
 * Protocol state machine and session boundary detection.
 *
 * Tracks logical channels, selected applets, authentication status,
 * and SCP variant across APDU exchanges. Groups exchanges into
 * sessions based on ISD selection and completed authentication.
 */
import { decodeCmd, decodeRsp, hexStr, h, INS_MAP, timeToSec } from "./decode.js";

// ── Session Boundary Detection ───────────────────────────────────────────

/** True if this command is SELECT for the GP Issuer Security Domain. */
export function isSelectISD(cmd) {
  return cmd?.ins === 0xA4 && (cmd.cla & 0x03) === 0 && cmd.data?.length >= 5 &&
    cmd.data[0] === 0xA0 && cmd.data[1] === 0x00 && cmd.data[2] === 0x00 &&
    cmd.data[3] === 0x03 && cmd.data[4] === 0x08;
}

/** True if this is GEN AUTH step 1 (request card challenge). */
export function isAuthStep1(cmd) {
  return cmd?.ins === 0x87 && cmd?.data?.[0] === 0x7C && cmd?.data?.[2] === 0x81 && cmd?.data?.[3] === 0x00;
}

/** True if this is a successful GEN AUTH step 2 (host cryptogram accepted). */
export function isAuthStep2Success(cmd, rsp) {
  return cmd?.ins === 0x87 && cmd?.data?.[2] === 0x82 && cmd?.data?.[3] === 0x10 && rsp?.sw === 0x9000;
}

/**
 * Split exchanges into logical sessions based on:
 * - SELECT ISD with >3s gap from previous ISD select
 * - Completed EXTERNAL AUTHENTICATE (auth step 2 succeeded)
 *
 * @param {object[]} exchanges - Parsed APDU exchanges
 * @returns {object[][]} Array of sessions, each an array of exchanges
 */
export function groupSessions(exchanges) {
  if (!exchanges.length) return [];
  const sessions = [[exchanges[0]]];
  let lastSelectISDTime = -Infinity;

  for (let i = 1; i < exchanges.length; i++) {
    const ex = exchanges[i];
    const cmd = decodeCmd(ex.cmd.bytes);
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    let boundary = false;

    if (isSelectISD(cmd) && rsp?.sw === 0x9000) {
      const gap = timeToSec(ex.cmd.ts) - lastSelectISDTime;
      if (gap > 3) boundary = true;
      lastSelectISDTime = timeToSec(ex.cmd.ts);
    }
    if (i > 0) {
      const prevCmd = decodeCmd(exchanges[i - 1].cmd.bytes);
      const prevRsp = exchanges[i - 1].rsp ? decodeRsp(exchanges[i - 1].rsp.bytes) : null;
      if (isAuthStep2Success(prevCmd, prevRsp) && !isAuthStep1(cmd)) boundary = true;
    }
    if (boundary) sessions.push([]);
    sessions[sessions.length - 1].push(ex);
  }
  return sessions;
}

// ── AID / Applet Classification ──────────────────────────────────────────

/** Known Application Identifiers (AIDs) and their labels. */
export const AID_LABELS = {
  "A0 00 00 03 08 00 00 10 00 01 00": "ISD v1",
  "A0 00 00 03 08 00 00 10 00 02 00": "ISD v2",
  "A0 00 00 03 08 00 00 10 00":       "PIV",
  "A0 00 00 03 08":                   "ISD",
};

/** Look up a human-readable label for an AID hex string. */
export function aidLabel(aidHex) {
  for (const [prefix, label] of Object.entries(AID_LABELS))
    if (aidHex.startsWith(prefix)) return label;
  return aidHex ? aidHex.substring(0, 14) + "…" : null;
}

/** Named protocol phases for exchange classification. */
export const PHASES = {
  PROBE:    "pre-select probing",
  SELECT:   "application selection",
  GP_ENUM:  "GP card enumeration",
  PIV_ENUM: "PIV discovery",
  VENDOR:   "vendor object inventory",
  AUTH:     "authentication",
  MUTATION: "personalization",
  VERIFY:   "post-write verification",
  IDLE:     "idle / status read",
};

/** Classify an AID into a high-level applet profile. */
export function appletProfile(aidHex) {
  if (!aidHex) return "unknown";
  const normalized = aidHex.replace(/ /g, "").toUpperCase();
  if (normalized.startsWith("A000000003")) return "ISD";
  if (normalized.startsWith("A000000308000010")) return "PIV";
  if (normalized.startsWith("A000000018")) return "PKCS15";
  return "unknown";
}

// ── Protocol State Machine ───────────────────────────────────────────────

/**
 * Walk every exchange and build per-exchange protocol state snapshots.
 *
 * Tracks: logical channel, selected applet, authentication status,
 * SCP variant (SCP03/SCP11), and operational phase. State advances
 * based on successful SELECT, GEN AUTH, etc.
 *
 * @param {object[]} exchanges - Parsed APDU exchanges
 * @returns {Object.<number, { chNum, selected, profile, authenticated, scp, authStep, phase }>}
 */
export function buildProtocolStates(exchanges) {
  const channels = {};
  const mkCh = (n) => ({ num: n, selected: null, profile: "unknown", authenticated: false, scp: null, authStep: 0 });
  const get = (n) => { if (!channels[n]) channels[n] = mkCh(n); return channels[n]; };
  let lastWrittenTag = null, anyAppSelected = false;

  return exchanges.map(ex => {
    const cmd = decodeCmd(ex.cmd.bytes);
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    const chNum = cmd ? (cmd.cla & 0x03) : 0;
    const ch = get(chNum);
    const snap = {
      chNum, selected: ch.selected, profile: ch.profile,
      authenticated: ch.authenticated, scp: ch.scp, authStep: ch.authStep,
      phase: null,
    };

    if (cmd) {
      // Classify phase
      if (cmd.ins === 0xA4) snap.phase = PHASES.SELECT;
      else if ([0x87, 0x50, 0x82, 0x84].includes(cmd.ins)) snap.phase = PHASES.AUTH;
      else if ([0xDB, 0x2C].includes(cmd.ins)) snap.phase = PHASES.MUTATION;
      else if (cmd.ins === 0xCB || cmd.ins === 0xCA) {
        const d = cmd.data;
        const tag = d?.[0] === 0x5C ? d?.slice(2, 2 + (d?.[1] ?? 0)) : null;
        const tagH = tag ? hexStr(tag).replace(/ /g, "") : "";
        if (d?.[0] === 0xDF && (d?.[1] === 0x39 || d?.[1] === 0x30)) snap.phase = PHASES.IDLE;
        else if (tagH.startsWith("FFF3") || d?.[0] === 0xDF || d?.[0] === 0x4D) snap.phase = PHASES.VENDOR;
        else if (tagH.startsWith("5FC1") || tagH === "7E") snap.phase = PHASES.PIV_ENUM;
        else if (tagH === "9F7F" || (d?.[0] === 0xDF && d?.[1] === 0x34)) snap.phase = PHASES.GP_ENUM;
        else if (lastWrittenTag && tagH === lastWrittenTag) snap.phase = PHASES.VERIFY;
        else if (!anyAppSelected) snap.phase = PHASES.PROBE;
        else snap.phase = PHASES.VENDOR;
      } else snap.phase = !anyAppSelected ? PHASES.PROBE : PHASES.IDLE;

      // Advance state on successful commands
      if (cmd.ins === 0xA4 && rsp?.sw === 0x9000) {
        const aidHex = hexStr(cmd.data || []);
        ch.selected = aidLabel(aidHex); ch.profile = appletProfile(aidHex); anyAppSelected = true;
        if (chNum === 0) { ch.authenticated = false; ch.scp = null; ch.authStep = 0; }
      }
      if (cmd.ins === 0x87) {
        if (isAuthStep1(cmd)) ch.authStep = 1;
        else if (cmd.data?.[2] === 0x82 && cmd.data?.[3] === 0x10) {
          if (rsp?.sw === 0x9000) { ch.authenticated = true; ch.scp = "SCP03"; ch.authStep = 2; }
          else { ch.authenticated = false; ch.scp = null; ch.authStep = 0; }
        } else if (rsp?.sw === 0x6A80) { ch.authenticated = false; ch.authStep = 0; }
      }
      if (cmd.ins === 0xDB && rsp?.sw === 0x9000 && cmd.data?.[0] === 0x5C)
        lastWrittenTag = hexStr(cmd.data.slice(2, 2 + (cmd.data[1] ?? 0))).replace(/ /g, "");
    }
    return snap;
  });
}

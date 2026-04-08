/**
 * Security scoring and compliance profiling.
 *
 * computeSecurityScore produces a weighted finding score (0-100).
 * computeComplianceProfile measures standard vs proprietary command usage.
 *
 * Scoring philosophy: unknown evidence is treated as unknown, not negative.
 * Findings that depend on trace completeness are downgraded when the trace
 * is incomplete, and provisioning-state observations are separated from
 * security findings.
 */
import { decodeCmd, h } from "../decode.js";
import { PIV_CERT_SLOT_TAGS } from "./certcheck.js";

/** INS codes that carry plaintext credentials (redacted before AI, flagged in scoring). */
export const SENSITIVE_INS = new Set([0x20, 0x24, 0x26, 0x28, 0x2C]);

/** ISO 7816-4 / GP / PIV standard instruction codes. */
export const STANDARD_INS = new Set([
  0x20, 0x24, 0x2C, 0x44, 0x46, 0x50, 0x82, 0x84, 0x86, 0x87,
  0xA4, 0xB0, 0xB2, 0xD0, 0xD2, 0xD6, 0xCA, 0xCB, 0xDA, 0xDB, 0xE2, 0xE6,
]);

/** Detect whether this trace looks like provisioning (writes, key gen, cert installs). */
function looksLikeProvisioning(exchanges) {
  let writes = 0, certReads = 0, authAttempts = 0;
  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes);
    if (!cmd) continue;
    if (cmd.ins === 0xDB) writes++;
    if ((cmd.ins === 0xCB || cmd.ins === 0xCA) && cmd.data?.[0] === 0x5C) certReads++;
    if (cmd.ins === 0x87 || cmd.ins === 0x82) authAttempts++;
  }
  // Provisioning traces typically have writes and auth setup
  return writes >= 2 || (authAttempts >= 1 && writes >= 1);
}

/**
 * Compute a weighted security finding score (0-100).
 * Deductions are applied for default keys, missing certs, plaintext credentials, etc.
 *
 * Key principles:
 * - Unknown secure messaging = "unproven", scored as info (not high)
 * - Incomplete traces reduce confidence globally, suppressing dependent findings
 * - Empty cert slots during provisioning are readiness observations, not security findings
 *
 * @returns {{ score, label, labelNote, color, deductions[], confidence, isProvisioning }}
 */
export function computeSecurityScore(keyCheck, integrity, errorProfile, certProvision, exchanges, protocolStates) {
  let score = 100;
  const deductions = [];
  const isIncomplete = integrity.kind !== "complete";
  const isProvisioning = looksLikeProvisioning(exchanges);

  // ── Default management key (high confidence regardless of trace completeness) ──
  const uniqueKeys = [...new Set((keyCheck?.matches ?? []).map(m => m.id))];
  if (uniqueKeys.length > 0) {
    score -= 40;
    deductions.push({ reason: `Default management key in use (${uniqueKeys.length} matched)`, points: 40, severity: "critical" });
  }

  // ── Certificate slot population (provisioning readiness, not security) ──
  if (certProvision?.probed.length > 0 && certProvision?.allEmpty) {
    const slotNames = certProvision.probed.map(t => {
      const info = PIV_CERT_SLOT_TAGS[t];
      return info ? `${info.slot} (${info.name})` : t;
    }).join(", ");
    if (isProvisioning) {
      // Expected state during setup: informational only, no score impact
      deductions.push({ reason: `Certificate slots empty (expected during provisioning): ${slotNames}`, points: 0, severity: "info", category: "readiness" });
    } else {
      score -= 10;
      deductions.push({ reason: `All probed certificate slots empty: ${slotNames}`, points: 10, severity: "medium", category: "readiness" });
    }
  } else if (certProvision?.partial) {
    const emptyNames = certProvision.absent.map(t => {
      const info = PIV_CERT_SLOT_TAGS[t];
      return info ? info.slot : t;
    }).join(", ");
    if (isProvisioning) {
      deductions.push({ reason: `Partial cert population (provisioning in progress, empty: ${emptyNames})`, points: 0, severity: "info", category: "readiness" });
    } else {
      score -= 5;
      deductions.push({ reason: `${certProvision.populated.length}/${certProvision.probed.length} cert slots populated (empty: ${emptyNames})`, points: 5, severity: "low", category: "readiness" });
    }
  }

  // ── Sensitive commands without proven secure messaging ──
  // Treat "unproven" as info (absence of evidence != evidence of absence).
  // Only escalate if we can confirm plaintext transmission in a complete trace.
  const plaintextSensitive = exchanges.some(ex => {
    const cmd = decodeCmd(ex.cmd.bytes);
    return SENSITIVE_INS.has(cmd?.ins) && !(protocolStates[ex.id]?.authenticated);
  });
  if (plaintextSensitive) {
    if (isIncomplete) {
      // Incomplete trace: secure messaging may have been established before capture
      deductions.push({ reason: "Sensitive commands observed, but secure messaging state unknown (incomplete trace)", points: 0, severity: "info" });
    } else {
      // Complete trace with no auth proven: meaningful but still not proof of plaintext
      score -= 10;
      deductions.push({ reason: "Sensitive credential commands without proven secure messaging (not confirmed plaintext, but no protection observed in trace)", points: 10, severity: "warn" });
    }
  }

  // ── Incomplete trace ──
  if (isIncomplete) {
    score -= 5;
    deductions.push({ reason: `Incomplete trace (${integrity.kind}) — analysis confidence reduced`, points: 5, severity: "low" });
  }

  // ── Command failures ──
  if (errorProfile.failures > 3) {
    score -= 5;
    deductions.push({ reason: `${errorProfile.failures} real command failures`, points: 5, severity: "low" });
  }

  // Confidence level reflects trace completeness
  const confidence = isIncomplete ? "reduced" : "normal";

  return {
    score: Math.max(0, score),
    label: score >= 80 ? "Low Findings" : score >= 60 ? "Medium Findings" : score >= 40 ? "High Findings" : "Critical Findings",
    labelNote: isIncomplete
      ? "Analysis confidence reduced due to incomplete trace. Some findings may not reflect the full operational context."
      : isProvisioning
        ? "Trace appears to capture provisioning. Cert slot and auth findings reflect setup state, not deployment risk."
        : "Weighted count of findings. Not a deployment risk score.",
    color: score >= 80 ? "#22c55e" : score >= 60 ? "#f59e0b" : score >= 40 ? "#ef4444" : "#dc2626",
    deductions,
    confidence,
    isProvisioning,
  };
}

/**
 * Measure what fraction of commands use standard vs vendor-proprietary INS codes.
 * @returns {{ total, standard, proprietary, unknown, standardPct, proprietaryPct, proprietaryInsCodes[] }}
 */
export function computeComplianceProfile(exchanges) {
  let standard = 0, proprietary = 0, unknown = 0;
  const proprietaryIns = new Set();
  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes);
    if (!cmd) { unknown++; continue; }
    if (((cmd.cla & 0xF0) === 0x80 && cmd.cla !== 0x80) || !STANDARD_INS.has(cmd.ins)) {
      proprietary++;
      proprietaryIns.add(h(cmd.ins));
    } else {
      standard++;
    }
  }
  const total = standard + proprietary + unknown;
  return {
    total, standard, proprietary, unknown,
    standardPct: total ? Math.round(standard / total * 100) : 0,
    proprietaryPct: total ? Math.round(proprietary / total * 100) : 0,
    proprietaryInsCodes: [...proprietaryIns],
  };
}

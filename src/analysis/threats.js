/**
 * Security threat detection engine.
 *
 * Scans APDU exchanges for:
 *   - Cleartext credentials (PINs, PUKs) in VERIFY/CHANGE commands
 *   - Weak/default PINs against known-weak list
 *   - Brute-force patterns (sequential auth failures)
 *   - Blocked authentication (SW 6983)
 *   - Nonce reuse / RNG failure in GEN AUTH challenges
 *   - Timing side-channels in VERIFY/GEN AUTH
 *   - Writes without prior authentication (ACL bypass)
 *   - Bulk erasure patterns (factory wipe)
 *   - Orphaned keys (templates without certs)
 *   - PII exposure (cert data read in cleartext)
 *   - Weak cryptographic algorithms (RSA-1024, 3DES)
 *   - Corrupt TLV objects in card responses
 *   - RSA keys requiring offline ROCA check
 *
 * Deduplicates by threat type, keeping the most severe instance.
 */
import { h, hexStr, decodeCmd, decodeRsp, INS_MAP, execDeltaMs } from "../decode.js";
import { lintTLV } from "../tlv.js";
import { unwrapPIVCert, analyzeCertificate, parseKeyTemplate } from "./x509.js";

/** Common weak PINs and PUKs. */
export const WEAK_PINS = new Set([
  "123456", "12345678", "000000", "00000000", "111111", "11111111",
  "1234", "0000", "9999", "password", "admin", "123123", "654321",
]);

/** Extract ASCII credential from APDU data, stripping FF/00 padding.
 *  Returns null for garbage data (all FF/00) used in intentional lockouts. */
export function extractCleartextCredential(dataBytes) {
  if (!dataBytes?.length) return null;
  // Suppress garbage payloads (all FF or all 00) used for intentional PIN/PUK exhaustion
  if (dataBytes.every(b => b === 0xFF || b === 0x00)) return null;
  const clean = dataBytes.filter(b => b !== 0xFF && b !== 0x00);
  if (!clean.length) return null;
  return clean.every(b => b >= 0x20 && b <= 0x7E) ? String.fromCharCode(...clean) : hexStr(clean);
}

/**
 * Analyze trace for security threats.
 * @param {object[]} exchanges
 * @param {object} protocolStates - Per-exchange protocol state snapshots
 * @param {object} integrity - Trace integrity assessment
 * @returns {{ id, severity, type, icon, title, detail, exchangeId? }[]}
 */
export function analyzeThreats(exchanges, protocolStates, integrity) {
  const threats = [];
  const isFragment = integrity?.isFragment ?? true;
  let seqFailures = 0;
  const seenNonces = new Map();

  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes);
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    const ps = protocolStates?.[ex.id];
    if (!cmd) continue;

    // ── Composite PUK+PIN credential (16-byte block in CHANGE REF DATA) ──
    if ((cmd.ins === 0x24 || cmd.ins === 0x2C) && cmd.data?.length === 16) {
      const half1 = Array.from(cmd.data).slice(0, 8).filter(b => b !== 0xFF && b !== 0x00);
      const half2 = Array.from(cmd.data).slice(8, 16).filter(b => b !== 0xFF && b !== 0x00);
      const puk = half1.every(b => b >= 0x30 && b <= 0x39) ? String.fromCharCode(...half1) : null;
      const pin = half2.every(b => b >= 0x30 && b <= 0x39) ? String.fromCharCode(...half2) : null;
      if (puk || pin) {
        const pukWeak = puk && WEAK_PINS.has(puk);
        const pinWeak = pin && WEAK_PINS.has(pin);
        threats.push({
          id: `cred-split-${ex.id}`, type: "COMPOSITE_CREDENTIAL", icon: "👁",
          severity: (pukWeak || pinWeak) ? "critical" : "warn",
          title: (pukWeak || pinWeak) ? `Default ${pukWeak ? "PUK" : ""} ${pinWeak ? "PIN" : ""} — factory credentials used`.trim() : "PUK + PIN composite credential transmitted",
          detail: `Exchange #${ex.id}: PUK: "${puk ?? "?"}"${pukWeak ? " ⚠ default" : ""}, PIN: "${pin ?? "?"}"${pinWeak ? " ⚠ default" : ""}`,
          cred: `PUK:${puk ?? "?"} PIN:${pin ?? "?"}`, exchangeId: ex.id,
        });
        continue;
      }
    }

    // ── Single cleartext credential ──
    if ([0x20, 0x24, 0x2C].includes(cmd.ins) && cmd.data?.length) {
      const cred = extractCleartextCredential(Array.from(cmd.data));
      if (cred) {
        const accepted = rsp?.sw === 0x9000;
        const isWeak = WEAK_PINS.has(cred);
        const verb = accepted ? "accepted by card" : "transmitted";
        // Default/weak PIN is always critical. Otherwise:
        // - proven plaintext (authenticated=false in complete trace) → warn
        // - unproven (incomplete trace or unknown) → info
        const smUnproven = !ps?.authenticated;
        threats.push({
          id: `cred-${ex.id}`, type: "CLEARTEXT_CREDENTIAL",
          severity: isWeak ? "critical" : smUnproven ? "warn" : "warn",
          title: isWeak
            ? `Default PIN ${verb}${accepted ? " — card is using factory credentials" : ""}`
            : `Credential ${verb}${smUnproven ? " — trace does not confirm secure messaging protection" : ""}`,
          detail: `${INS_MAP[cmd.ins] ?? h(cmd.ins)} at exchange #${ex.id}${isWeak ? ` — "${cred}" matches known default` : ""}`,
          cred, exchangeId: ex.id,
        });
      }
    }

    // ── Sequential auth failures ──
    if (rsp && (rsp.sw & 0xFFF0) === 0x63C0) {
      seqFailures++;
      const retriesLeft = rsp.sw & 0x0F;
      if (seqFailures >= 3) {
        // Look ahead for reset or re-provisioning activity:
        // - YubiKey RESET (INS 0xFB)
        // - PUT DATA (INS 0xDB) — writing new objects
        // - GENERATE KEY PAIR (INS 0x47) — generating new keys
        // - CHANGE REFERENCE DATA (INS 0x24) — setting new PIN
        const laterExchanges = exchanges.slice(exchanges.indexOf(ex) + 1, exchanges.indexOf(ex) + 10);
        const adminFollowup = laterExchanges.find(e2 => {
          const c2 = decodeCmd(e2.cmd.bytes), r2 = e2.rsp ? decodeRsp(e2.rsp.bytes) : null;
          if (!c2 || r2?.sw !== 0x9000) return false;
          return c2.ins === 0xFB || c2.ins === 0xDB || c2.ins === 0x47 || c2.ins === 0x24;
        });
        if (adminFollowup) {
          const followupCmd = decodeCmd(adminFollowup.cmd.bytes);
          const action = followupCmd.ins === 0xFB ? "factory reset (INS FB)" :
                         followupCmd.ins === 0xDB ? "PUT DATA" :
                         followupCmd.ins === 0x47 ? "GENERATE KEY PAIR" : "CHANGE PIN";
          threats.push({
            id: `reset-${ex.id}`, type: "INTENTIONAL_RESET",
            severity: "info",
            title: `Intentional credential exhaustion followed by ${action}`,
            detail: `${seqFailures} consecutive auth failures followed by successful ${action} at exchange #${adminFollowup.id}. Consistent with reset or re-provisioning workflow.`,
            exchangeId: adminFollowup.id,
          });
        } else {
          threats.push({
            id: `authfail-${ex.id}`, type: "AUTH_FAILURE_SEQUENCE",
            severity: retriesLeft === 0 ? "critical" : "warn",
            title: `${seqFailures} consecutive authentication retries — ${retriesLeft} retries remain`,
            detail: `Credential retry counter decremented ${seqFailures} times ending at exchange #${ex.id}. Could indicate failed provisioning, operator error, or unauthorized access attempt.`,
            exchangeId: ex.id,
          });
        }
      }
    } else if (rsp?.sw === 0x9000 && (cmd.ins === 0x20 || cmd.ins === 0x87)) {
      seqFailures = 0;
    }

    // ── Blocked authentication (only flag if NOT part of reset/re-provisioning) ──
    if (rsp?.sw === 0x6983) {
      const nearby = exchanges.slice(exchanges.indexOf(ex) + 1, exchanges.indexOf(ex) + 6);
      const isIntentional = nearby.some(e2 => {
        const c2 = decodeCmd(e2.cmd.bytes), r2 = e2.rsp ? decodeRsp(e2.rsp.bytes) : null;
        if (!c2 || r2?.sw !== 0x9000) return false;
        return c2.ins === 0xFB || c2.ins === 0xDB || c2.ins === 0x47 || c2.ins === 0x24;
      });
      if (!isIntentional) {
        threats.push({
          id: `blocked-${ex.id}`, type: "AUTH_BLOCKED",
          severity: "critical",
          title: "Authentication method blocked (6983)",
          detail: `PIN or key locked at exchange #${ex.id}.`, exchangeId: ex.id,
        });
      }
    }

    // ── Nonce replay / RNG failure ──
    if (cmd.ins === 0x87 && rsp?.sw === 0x9000 && rsp.data?.[0] === 0x7C && rsp.data?.[2] === 0x80) {
      const nonceHex = hexStr(rsp.data.slice(4, 4 + rsp.data[3])).replace(/ /g, "");
      if (seenNonces.has(nonceHex)) {
        threats.push({
          id: `replay-${ex.id}`, type: "RNG_FAILURE", icon: "⚠",
          severity: "critical",
          title: "Duplicate card challenge — RNG failure or replay attack",
          detail: `Nonce seen at #${seenNonces.get(nonceHex)} and again at #${ex.id}.`, exchangeId: ex.id,
        });
      } else {
        seenNonces.set(nonceHex, ex.id);
      }
    }
  }

  // ── Timing analysis ──
  const genAuthTimes = [], verifyTimes = [];
  let lastAuthExId = -1;
  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes);
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    const ps = protocolStates?.[ex.id];
    const dt = execDeltaMs(ex);
    if (!cmd || dt === null || dt < 0) continue;

    if (cmd.ins === 0x87) genAuthTimes.push({ dt, exId: ex.id });
    if (cmd.ins === 0x20) verifyTimes.push({ dt, exId: ex.id });
    if (cmd.ins === 0x87 && rsp?.sw === 0x9000) lastAuthExId = ex.id;

    // Write without prior auth
    if (cmd.ins === 0xDB && rsp?.sw === 0x9000 && !ps?.authenticated && lastAuthExId === -1) {
      threats.push({
        id: `acl-${ex.id}`, type: isFragment ? "UNVERIFIED_WRITE" : "ACL_BYPASS", icon: "△",
        severity: isFragment ? "warn" : "critical",
        title: isFragment ? "PUT DATA succeeded without visible prior auth" : "Protected write succeeded without proven auth — possible ACL bypass",
        detail: isFragment ? `Exchange #${ex.id}: auth may have occurred before capture started.` : `Exchange #${ex.id}: PUT DATA returned 9000 with no auth in this complete trace.`,
        exchangeId: ex.id,
      });
    }
  }

  if (genAuthTimes.length > 0) {
    const avgMs = Math.round(genAuthTimes.reduce((s, t) => s + t.dt, 0) / genAuthTimes.length);
    threats.push({
      id: "timing-crypto", type: "TIMING_PROFILE", icon: "⏱",
      severity: avgMs > 200 ? "warn" : "pass",
      title: avgMs > 200 ? `Slow GEN AUTH (~${avgMs}ms) — likely RSA-2048 or older hardware` : `Fast GEN AUTH (~${avgMs}ms) — consistent with ECC or modern hardware`,
      detail: `Average card crypto execution: ${avgMs}ms.`, exchangeId: genAuthTimes[0].exId,
    });
  }

  if (verifyTimes.length >= 2) {
    const times = verifyTimes.map(t => t.dt);
    const variance = Math.max(...times) - Math.min(...times);
    if (variance > 10) {
      threats.push({
        id: "timing-verify", type: "TIMING_SIDECHANNEL", icon: "⏱",
        severity: "warn",
        title: `VERIFY timing variance ${variance}ms — possible timing side-channel`,
        detail: `PIN verification: ${Math.min(...times)}–${Math.max(...times)}ms.`, exchangeId: verifyTimes[0].exId,
      });
    }
  }

  // ── Bulk erasure (many zero-length PUT DATA = factory wipe) ──
  const wipes = exchanges.filter(ex => {
    const cmd = decodeCmd(ex.cmd.bytes), rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    if (cmd?.ins !== 0xDB || rsp?.sw !== 0x9000 || !cmd.data) return false;
    return Array.from(cmd.data).some((b, i) => b === 0x53 && cmd.data[i + 1] === 0x00);
  });
  if (wipes.length > 10) {
    threats.push({
      id: "bulk-erasure", type: "BULK_ERASURE", icon: "⚠",
      severity: "warn",
      title: `Bulk container erasure — ${wipes.length} zero-length PUT DATA operations`,
      detail: `${wipes.length} PUT DATA with empty value field (53 00). Consistent with factory reset or administrative purge.`,
      exchangeId: wipes[0]?.id,
    });
  }

  // ── Orphaned keys (key templates written but cert slots empty) ──
  const keyTemplateWritten = exchanges.some(ex => {
    const cmd = decodeCmd(ex.cmd.bytes), rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    return cmd?.ins === 0xDB && rsp?.sw === 0x9000 && cmd.data?.[0] === 0x5C && cmd.data?.[1] >= 3 && cmd.data?.[2] === 0xFF && cmd.data?.[3] === 0x90;
  });
  const certSlotsEmpty = exchanges.some(ex => {
    const cmd = decodeCmd(ex.cmd.bytes), rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    if ((cmd?.ins !== 0xCB && cmd?.ins !== 0xCA) || !cmd.data) return false;
    const d = cmd.data;
    const tagHex = d[0] === 0x5C ? hexStr(Array.from(d).slice(2, 2 + (d[1] ?? 0))).replace(/ /g, "").toUpperCase() : "";
    return tagHex.startsWith("5FC1") && rsp?.sw === 0x6A80;
  });
  if (keyTemplateWritten && certSlotsEmpty) {
    threats.push({
      id: "orphaned-keys", type: "ORPHANED_KEYS", icon: "⚠",
      severity: "warn",
      title: "Incomplete provisioning — key templates written but certificate slots empty",
      detail: "PUT DATA targeting FF90xx succeeded, but 5FC1xx reads returned 6A80. Card will fail smart card logon until certificates are provisioned.",
    });
  }

  // ── X.509 Certificate Analysis (cert slot reads) ──
  const PIV_CERT_TAGS = ["5FC105", "5FC10A", "5FC10B", "5FC101"];
  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes), rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    if ((cmd?.ins !== 0xCB && cmd?.ins !== 0xCA) || rsp?.sw !== 0x9000 || !rsp.data?.length || rsp.data.length < 50) continue;
    const d = cmd.data; if (d?.[0] !== 0x5C) continue;
    const tagHex = hexStr(d.slice(2, 2 + (d[1] ?? 0))).replace(/ /g, "").toUpperCase();
    if (!PIV_CERT_TAGS.includes(tagHex)) continue;

    const ps = protocolStates?.[ex.id];
    const smUnproven = !ps?.authenticated;
    const smNote = smUnproven ? " (trace does not confirm channel protection)" : "";

    try {
      const derBytes = unwrapPIVCert(Array.from(rsp.data));
      if (derBytes) {
        const info = analyzeCertificate(derBytes);

        // PII exposure with concrete identity data
        // Cert reads are normal PIV operations; severity depends on whether
        // we can confirm the channel was protected. Unknown = warn, not critical.
        threats.push({
          id: `pii-${ex.id}`, type: "PII_EXPOSURE",
          severity: "warn",
          title: `Identity data read from slot ${tagHex}${smNote}`,
          detail: info.piiFields.join("; "),
          certInfo: { subject: info.subject, serial: info.serial, keyAlg: info.keyAlg, keySize: info.keySize, sigAlg: info.sigAlg, notAfter: info.notAfter?.toISOString() },
          exchangeId: ex.id,
        });

        // Weak signature algorithm
        for (const w of info.weaknesses.filter(w => w.includes("signature") || w.includes("RSA key"))) {
          threats.push({
            id: `weak-cert-${ex.id}`, type: "WEAK_CRYPTO",
            severity: "critical",
            title: `Weak certificate in slot ${tagHex}`,
            detail: w,
            exchangeId: ex.id,
          });
        }

        // Expired or not-yet-valid certificate
        for (const w of info.weaknesses.filter(w => w.includes("Expired") || w.includes("Not yet"))) {
          threats.push({
            id: `lifecycle-${ex.id}`, type: "COMPLIANCE_VIOLATION",
            severity: "warn",
            title: `Certificate lifecycle violation in ${tagHex}`,
            detail: w,
            exchangeId: ex.id,
          });
        }
      } else {
        // Data present but not parseable as PIV cert wrapper
        threats.push({
          id: `pii-${ex.id}`, type: "PII_EXPOSURE",
          severity: "warn",
          title: `Certificate data read from slot ${tagHex}${smNote}`,
          detail: `${rsp.data.length}B read from cert slot. Parse failed but raw data may contain identity material.`,
          exchangeId: ex.id,
        });
      }
    } catch (e) {
      // Certificate slot contained unparseable data
      threats.push({
        id: `corrupt-cert-${ex.id}`, type: "CORRUPT_OBJECT",
        severity: "critical",
        title: `Malformed X.509 in slot ${tagHex}`,
        detail: `Certificate data failed ASN.1 parsing: ${e.message?.substring(0, 120)}`,
        exchangeId: ex.id,
      });
    }
  }

  // ── Key Generation Analysis (INS 0x47) ──
  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes), rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    if (!cmd || cmd.ins !== 0x47 || rsp?.sw !== 0x9000 || !rsp.data?.length) continue;

    const keyInfo = parseKeyTemplate(Array.from(rsp.data));
    if (keyInfo) {
      for (const w of keyInfo.weaknesses) {
        threats.push({
          id: `keygen-${ex.id}`, type: "WEAK_CRYPTO",
          severity: "critical",
          title: `Weak key generated: ${keyInfo.keyType}-${keyInfo.keySize ?? "?"}`,
          detail: w,
          exchangeId: ex.id,
        });
      }
      // ROCA advisory for RSA keys
      if (keyInfo.keyType === "RSA") {
        threats.push({
          id: `roca-${ex.id}`, type: "ROCA",
          severity: "info",
          title: `RSA-${keyInfo.keySize} key generated, ROCA check recommended`,
          detail: "On-card RSA keys should be tested for CVE-2017-15361. Export the public modulus and verify.",
          exchangeId: ex.id,
        });
      }
    } else {
      // Fallback: flag based on P1 algorithm indicator without template parsing
      const WEAK_P1 = { 0x06: "RSA-1024", 0x05: "3DES" };
      if (WEAK_P1[cmd.p1]) {
        threats.push({
          id: `weak-keygen-${ex.id}`, type: "WEAK_CRYPTO",
          severity: "critical",
          title: `Deprecated algorithm: ${WEAK_P1[cmd.p1]}`,
          detail: `Key generation used algorithm indicator P1=${h(cmd.p1)}.`,
          exchangeId: ex.id,
        });
      }
    }
  }

  // ── TLV lint (non-cert data objects) ──
  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes), rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    if ((cmd?.ins !== 0xCB && cmd?.ins !== 0xCA) || rsp?.sw !== 0x9000 || !rsp.data?.length) continue;
    // Skip cert slots (handled above with full x509 parsing)
    const d = cmd.data;
    if (d?.[0] === 0x5C) {
      const tagHex = hexStr(d.slice(2, 2 + (d[1] ?? 0))).replace(/ /g, "").toUpperCase();
      if (PIV_CERT_TAGS.includes(tagHex)) continue;
    }
    if (rsp.data.length > 20 && (rsp.data[0] & 0xE0) === 0x60) {
      const issues = lintTLV(Array.from(rsp.data));
      const overreads = issues.filter(i => i.kind === "overread");
      if (overreads.length > 0) {
        threats.push({
          id: `corrupt-${ex.id}`, type: "CORRUPT_OBJECT",
          severity: "critical",
          title: "Malformed TLV in data object response",
          detail: `Exchange #${ex.id}: length field claims ${overreads[0].claimed}B but only ${overreads[0].available}B available.`,
          exchangeId: ex.id,
        });
      }
    }
  }

  // ── Deduplicate — keep most severe per type, but allow per-slot PII ──
  const seen = new Map();
  for (const t of threats) {
    const key = t.type === "PII_EXPOSURE" ? `${t.type}:${t.exchangeId}` : t.type;
    const existing = seen.get(key);
    if (!existing || (t.severity === "critical" && existing.severity !== "critical")) seen.set(key, t);
  }
  return Array.from(seen.values());
}

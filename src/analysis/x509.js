/**
 * X.509 certificate analysis for PIV slot reads and key generation.
 *
 * Uses @peculiar/x509 to parse certificates extracted from PIV data
 * objects, enabling concrete PII detection, crypto algorithm auditing,
 * and lifecycle validation. Replaces the heuristic-only detection
 * that preceded this module.
 *
 * PIV certificate data objects (5FC105, 5FC10A, etc.) wrap the DER
 * certificate in a BER-TLV tag 70 (certificate) inside a tag 53
 * (certificate data object). See SP 800-73-4 Part 1, Table 10.
 */
import { X509Certificate } from "@peculiar/x509";
import { h, hexStr } from "../decode.js";

// ── OID Labels ───────────────────────────────────────────────────────────

const SIG_ALGS = {
  "1.2.840.113549.1.1.5":  "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.113549.1.1.10": "rsassa-pss",
  "1.2.840.10045.4.3.2":   "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3":   "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4":   "ecdsa-with-SHA512",
};

const KEY_ALGS = {
  "1.2.840.113549.1.1.1":  "RSA",
  "1.2.840.10045.2.1":     "EC",
  "1.3.101.112":            "Ed25519",
  "1.3.101.113":            "Ed448",
};

const WEAK_SIG_OIDS = new Set([
  "1.2.840.113549.1.1.5",  // sha1WithRSA
  "1.2.840.113549.1.1.4",  // md5WithRSA
  "1.2.840.113549.1.1.2",  // md2WithRSA
]);

// ── PIV Data Object Unwrapping ───────────────────────────────────────────

/**
 * Extract the DER-encoded certificate from a PIV data object response.
 *
 * SP 800-73-4 wraps certs in: 53 [len] 70 [len] <DER cert> 71 01 <compress> FE 00
 * Some cards omit the outer 53 and return the 70 directly.
 *
 * @param {number[]} dataBytes - Raw response data (SW stripped)
 * @returns {Uint8Array|null} DER certificate bytes, or null if unwrap fails
 */
export function unwrapPIVCert(dataBytes) {
  if (!dataBytes?.length || dataBytes.length < 10) return null;
  let offset = 0;

  // Skip outer 53 tag if present
  if (dataBytes[offset] === 0x53) {
    offset++;
    offset = skipBERLength(dataBytes, offset);
  }

  // Look for 70 (certificate) tag
  if (dataBytes[offset] === 0x70) {
    offset++;
    const { value: certLen, newOffset } = readBERLength(dataBytes, offset);
    if (certLen > 0 && newOffset + certLen <= dataBytes.length) {
      return new Uint8Array(dataBytes.slice(newOffset, newOffset + certLen));
    }
  }

  // Fallback: try parsing the entire payload as DER
  // DER certs start with 30 (SEQUENCE)
  if (dataBytes[0] === 0x30) {
    return new Uint8Array(dataBytes);
  }

  return null;
}

/** Read a BER length field, return { value, newOffset }. */
function readBERLength(data, offset) {
  const first = data[offset];
  if (first < 0x80) return { value: first, newOffset: offset + 1 };
  const numBytes = first & 0x7F;
  let value = 0;
  for (let i = 0; i < numBytes; i++) {
    value = (value << 8) | data[offset + 1 + i];
  }
  return { value, newOffset: offset + 1 + numBytes };
}

/** Skip past a BER length field, return new offset. */
function skipBERLength(data, offset) {
  return readBERLength(data, offset).newOffset;
}

// ── Certificate Analysis ─────────────────────────────────────────────────

/**
 * Parse a DER certificate and produce structured findings.
 *
 * @param {Uint8Array} derBytes - DER-encoded X.509 certificate
 * @returns {{ subject, issuer, serial, sigAlg, keyAlg, keySize, notBefore, notAfter,
 *             piiFields: string[], weaknesses: string[] }}
 */
export function analyzeCertificate(derBytes) {
  const cert = new X509Certificate(derBytes);
  const sigAlg = cert.signatureAlgorithm?.hash
    ? `${cert.signatureAlgorithm.name} (${cert.signatureAlgorithm.hash.name})`
    : SIG_ALGS[cert.signatureAlgorithm?.algorithm] ?? cert.signatureAlgorithm?.algorithm ?? "unknown";

  const pubAlgOid = cert.publicKey?.algorithm?.name ?? "unknown";
  let keyAlg = KEY_ALGS[cert.publicKey?.algorithm?.algorithm] ?? pubAlgOid;
  let keySize = null;

  // Extract key size
  if (keyAlg === "RSA" || pubAlgOid === "RSASSA-PKCS1-v1_5" || pubAlgOid === "RSA-PSS") {
    keyAlg = "RSA";
    keySize = cert.publicKey?.algorithm?.modulusLength ?? null;
  } else if (keyAlg === "EC" || pubAlgOid === "ECDSA") {
    keyAlg = "EC";
    const curve = cert.publicKey?.algorithm?.namedCurve;
    const curveMap = { "P-256": 256, "P-384": 384, "P-521": 521 };
    keySize = curveMap[curve] ?? null;
    if (curve) keyAlg = `EC ${curve}`;
  }

  // Extract PII fields
  const piiFields = [];
  const subject = cert.subject;
  if (subject) piiFields.push(`Subject: ${subject}`);
  // Check SAN for email
  try {
    const sanExt = cert.getExtension("2.5.29.17"); // subjectAltName
    if (sanExt) piiFields.push("SubjectAltName present");
  } catch { /* no SAN */ }
  const issuer = cert.issuer;
  if (issuer) piiFields.push(`Issuer: ${issuer}`);
  piiFields.push(`Serial: ${cert.serialNumber}`);

  // Identify weaknesses
  const weaknesses = [];
  if (WEAK_SIG_OIDS.has(cert.signatureAlgorithm?.algorithm)) {
    weaknesses.push(`Deprecated signature algorithm: ${sigAlg}`);
  }
  if (keyAlg === "RSA" && keySize && keySize < 2048) {
    weaknesses.push(`Weak RSA key: ${keySize}-bit (minimum 2048)`);
  }
  const now = new Date();
  if (cert.notAfter < now) {
    weaknesses.push(`Expired: ${cert.notAfter.toISOString().split("T")[0]}`);
  }
  if (cert.notBefore > now) {
    weaknesses.push(`Not yet valid: ${cert.notBefore.toISOString().split("T")[0]}`);
  }

  return {
    subject, issuer,
    serial: cert.serialNumber,
    sigAlg, keyAlg, keySize,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    piiFields, weaknesses,
  };
}

// ── Key Template Parsing (INS 0x47 response) ─────────────────────────────

/**
 * Parse a PIV GENERATE ASYMMETRIC KEY PAIR response (7F49 template).
 *
 * The 7F49 dynamic authentication template contains:
 *   81 [len] <modulus>        (RSA)
 *   82 [len] <exponent>       (RSA)
 *   86 [len] <EC public key>  (EC)
 *
 * @param {number[]} dataBytes - Response data (SW stripped)
 * @returns {{ keyType, keySize, curve, exponent, weaknesses: string[] }} | null
 */
export function parseKeyTemplate(dataBytes) {
  if (!dataBytes?.length || dataBytes.length < 4) return null;

  let offset = 0;
  // Expect 7F49 tag
  if (dataBytes[0] === 0x7F && dataBytes[1] === 0x49) {
    offset = 2;
    const { newOffset } = readBERLength(dataBytes, offset);
    offset = newOffset;
  } else {
    return null;
  }

  const fields = {};
  while (offset < dataBytes.length - 1) {
    const tag = dataBytes[offset++];
    const { value: len, newOffset } = readBERLength(dataBytes, offset);
    offset = newOffset;
    if (offset + len > dataBytes.length) break;
    fields[tag] = dataBytes.slice(offset, offset + len);
    offset += len;
  }

  const weaknesses = [];

  // RSA key (tags 81=modulus, 82=exponent)
  if (fields[0x81]) {
    const modulusBytes = fields[0x81];
    const keySize = (modulusBytes[0] === 0x00 ? modulusBytes.length - 1 : modulusBytes.length) * 8;
    let exponent = null;
    if (fields[0x82]) {
      exponent = 0;
      for (const b of fields[0x82]) exponent = (exponent << 8) | b;
    }
    if (keySize < 2048) weaknesses.push(`RSA key too small: ${keySize}-bit`);
    if (exponent && exponent < 65537) weaknesses.push(`Weak RSA exponent: ${exponent} (should be 65537)`);
    return { keyType: "RSA", keySize, curve: null, exponent, weaknesses };
  }

  // EC key (tag 86=public key point)
  if (fields[0x86]) {
    const pubBytes = fields[0x86];
    // Uncompressed EC point: 04 || x || y. Total length determines curve.
    const curveMap = { 65: "P-256", 97: "P-384", 133: "P-521" };
    const curve = curveMap[pubBytes.length] ?? `unknown (${pubBytes.length}B)`;
    const keySize = { "P-256": 256, "P-384": 384, "P-521": 521 }[curve] ?? pubBytes.length * 4;
    return { keyType: "EC", keySize, curve, exponent: null, weaknesses };
  }

  return null;
}

/**
 * Cryptographic analysis — all client-side via Web Crypto API.
 *
 * AES-ECB emulated via AES-CBC with zero IV.
 * AES-CMAC per NIST SP 800-38B.
 * SCP03 session key derivation per NIST SP 800-108 KDF.
 * Known default key database and checker for PIV and GP.
 * No keys or card data leave the browser.
 */
// ── CRYPTO ────────────────────────────────────────────────────────────────
// All crypto runs client-side via Web Crypto API. No secrets leave the browser.
// AES-ECB emulated via AES-CBC with zero IV. AES-CMAC per NIST SP 800-38B.
// SCP03 session key derivation per NIST SP 800-108 KDF.
// Known default key database and checker for PIV and GP SCP03.
import { h, hexStr, decodeCmd, decodeRsp } from "./decode.js";
import { isAuthStep1 } from "./protocol.js";

// AES-ECB via AES-CBC with zero IV (Web Crypto doesn't expose ECB directly).
async function aesEcbEncrypt(keyBytes, blockBytes) {
  const key = await crypto.subtle.importKey("raw", new Uint8Array(keyBytes), { name: "AES-CBC" }, false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, key, new Uint8Array(blockBytes));
  return Array.from(new Uint8Array(ct).slice(0, 16));
}

async function aesEcbDecrypt(keyBytes, blockBytes) {
  const key = await crypto.subtle.importKey("raw", new Uint8Array(keyBytes), { name: "AES-CBC" }, false, ["decrypt"]);
  const padBlock = new Uint8Array(16).fill(0x10);
  const pt = await crypto.subtle.decrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, key, new Uint8Array([...blockBytes, ...padBlock]));
  return Array.from(new Uint8Array(pt).slice(0, 16));
}

// AES-CMAC (NIST SP 800-38B)
async function aesCMAC(keyBytes, messageBytes) {
  const k = Array.isArray(keyBytes) ? keyBytes : Array.from(keyBytes);
  const msg = messageBytes instanceof Uint8Array ? messageBytes : new Uint8Array(messageBytes);
  const L = new Uint8Array(await aesEcbEncrypt(k, Array(16).fill(0)));
  function shiftLeft1(b) { const o = new Uint8Array(16); for (let i = 0; i < 15; i++) o[i] = (b[i] << 1) | (b[i+1] >> 7); o[15] = b[15] << 1; return o; }
  const K1 = shiftLeft1(L);  if (L[0]  & 0x80) K1[15] ^= 0x87;
  const K2 = shiftLeft1(K1); if (K1[0] & 0x80) K2[15] ^= 0x87;
  const n = Math.max(1, Math.ceil(msg.length / 16)), lastComplete = msg.length > 0 && msg.length % 16 === 0;
  let X = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) { for (let j = 0; j < 16; j++) X[j] ^= msg[i*16+j]; X = new Uint8Array(await aesEcbEncrypt(k, Array.from(X))); }
  const last = new Uint8Array(16), ls = (n-1)*16;
  if (lastComplete) { for (let j = 0; j < 16; j++) last[j] = msg[ls+j] ^ K1[j]; }
  else { const rem = msg.length-ls; for (let j = 0; j < rem; j++) last[j] = msg[ls+j]; last[rem] = 0x80; for (let j = 0; j < 16; j++) last[j] ^= K2[j]; }
  for (let j = 0; j < 16; j++) X[j] ^= last[j];
  return Array.from(await aesEcbEncrypt(k, Array.from(X)));
}

/**
 * NIST SP 800-108 KDF (counter mode) with AES-CMAC as PRF.
 * derivConst selects the key type: 0x04=S-ENC, 0x06=S-MAC, 0x07=S-RMAC, 0x08=DEK.
 * contextBytes = hostChallenge || cardChallenge (16 bytes total).
 */
async function deriveSCP03SessionKey(staticKeyBytes, derivConst, contextBytes, keyLenBytes = 16) {
  const keyLenBits = keyLenBytes * 8, ctx = new Uint8Array(contextBytes);
  const derived = [];
  for (let counter = 1; counter <= Math.ceil(keyLenBytes / 16); counter++) {
    const input = new Uint8Array(16 + ctx.length);
    input[11] = derivConst; input[12] = 0x00; input[13] = (keyLenBits >> 8) & 0xFF; input[14] = keyLenBits & 0xFF; input[15] = counter;
    input.set(ctx, 16);
    derived.push(...await aesCMAC(staticKeyBytes, input));
  }
  return derived.slice(0, keyLenBytes);
}

async function calculateSCP03Cryptogram(smacBytes, derivConst, contextBytes) {
  const ctx = new Uint8Array(contextBytes), input = new Uint8Array(16 + ctx.length);
  input[11] = derivConst; input[12] = 0x00; input[13] = 0x00; input[14] = 0x40; input[15] = 0x01;
  input.set(ctx, 16);
  return (await aesCMAC(smacBytes, input)).slice(0, 8);
}

// ── KNOWN KEYS ────────────────────────────────────────────────────────────
// Database of publicly documented default management keys.
// Each entry cites a public source. Used by checkKnownKeys() to test
// whether the trace's authentication exchanges used a default key.
// Each entry requires a cited public source.
const KNOWN_KEYS = [
  { id: "piv-default-16",      name: "PIV standard default management key — AES-128 (16B)",     source: "NIST SP 800-73 Appendix B.2. Ships as default in YubiKey (fw 5.4.2+), SafeNet eToken Fusion NFC PIV.",  risk: "critical", alg: "aes", bytes: [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08] },
  { id: "piv-default-24",      name: "PIV standard default management key (24B, tested as AES)", source: "NIST SP 800-73 Appendix B.2 (24-byte form). Historically 3DES; modern cards (YubiKey fw 5.7+) use AES-192.",                   risk: "critical", alg: "aes", bytes: [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08] },
  { id: "gemalto-idprime",     name: "Gemalto IDPrime PIV 2.0 — default GP ISD key (ASCII: GEMXPRESSOSAMPLE)", source: "blog.rchapman.org/posts/Smart_card_installing_Hello_World_on_a_Gemalto_IDPrime_PIV_2.0_card", risk: "critical", alg: "aes", bytes: [0x47,0x45,0x4D,0x58,0x50,0x52,0x45,0x53,0x53,0x4F,0x53,0x41,0x4D,0x50,0x4C,0x45] },
  { id: "gemalto-net-zeros",   name: "Gemalto IDPrime .NET Mini-Driver — default admin key (24× 0x00)",       source: "myworldofit.net/?p=9479",                                                                    risk: "critical", alg: "aes", bytes: new Array(24).fill(0x00) },
  { id: "gemalto-net-ff",      name: "Gemalto IDPrime .NET Mini-Driver — alternate admin key (24× 0xFF)",     source: "myworldofit.net/?p=9479",                                                                    risk: "critical", alg: "aes", bytes: new Array(24).fill(0xFF) },
  { id: "gp-default-static",   name: "GlobalPlatform default static key — S-ENC / S-MAC / S-DEK",            source: "GlobalPlatform Card Spec v2.3.1 §E.2 — test key only, never production",                     risk: "critical", alg: "aes", bytes: [0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F] },
  { id: "all-zeros-16",        name: "All-zeros AES-128 key",         source: "Pervasive debug/test pattern", risk: "critical", alg: "aes", bytes: new Array(16).fill(0x00) },
  { id: "all-ff-16",           name: "All-FF AES-128 key",            source: "Common test pattern",          risk: "high",     alg: "aes", bytes: new Array(16).fill(0xFF) },
  { id: "sequential-00",       name: "Sequential 0x00..0x0F AES-128", source: "NIST AES-128 test vector",    risk: "high",     alg: "aes", bytes: [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F] },
  { id: "sequential-01",       name: "Sequential 0x01..0x10 AES-128", source: "Common PIV test pattern",     risk: "high",     alg: "aes", bytes: [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10] },
];

// ── SCP03 ─────────────────────────────────────────────────────────────────
function parseInitUpdateResponse(data) {
  if (!data || data.length < 29 || data[11] !== 0x03) return null;
  return { keyDivData: data.slice(0, 10), keyVersion: data[10], scpId: data[11], iParam: data[12], cardChallenge: data.slice(13, 21), cardCryptogram: data.slice(21, 29), seqCounter: data.length >= 32 ? data.slice(29, 32) : null };
}

function findSCP03Pairs(exchanges) {
  const pairs = [];
  for (let i = 0; i < exchanges.length; i++) {
    const ex1 = exchanges[i], cd1 = decodeCmd(ex1.cmd.bytes), rd1 = ex1.rsp ? decodeRsp(ex1.rsp.bytes) : null;
    if (!cd1 || cd1.ins !== 0x50 || !rd1 || rd1.sw !== 0x9000) continue;
    const iur = parseInitUpdateResponse(rd1.data);
    if (!iur || !cd1.data || cd1.data.length !== 8) continue;
    for (let j = i + 1; j < Math.min(i + 6, exchanges.length); j++) {
      const ex2 = exchanges[j], cd2 = decodeCmd(ex2.cmd.bytes), rd2 = ex2.rsp ? decodeRsp(ex2.rsp.bytes) : null;
      if (!cd2 || cd2.ins !== 0x82) continue;
      pairs.push({ type: "scp03", ex1Id: ex1.id, ex2Id: ex2.id, hostChallenge: Array.from(cd1.data), cardChallenge: Array.from(iur.cardChallenge), cardCryptogram: Array.from(iur.cardCryptogram), keyVersion: iur.keyVersion, succeeded: rd2?.sw === 0x9000 });
      break;
    }
  }
  return pairs;
}

/**
 * Check trace for default/known management keys using Web Crypto.
 * Tests two protocols:
 * 1. PIV GEN AUTH: tries AES-ECB encrypt/decrypt of card nonce against
 *    each known key, comparing to host cryptogram in the trace
 * 2. GP SCP03: derives session keys via SP 800-108 KDF and verifies
 *    the card cryptogram matches expected value for each known key
 * Runs entirely client-side with no network calls.
 * @returns {{ matches: KeyMatch[], testedPairs: AuthPair[] }}
 */
async function checkKnownKeys(exchanges) {
  const matches = [], testedPairs = [];
  // PIV GEN AUTH pairs
  for (let i = 0; i + 1 < exchanges.length; i++) {
    const cd1 = decodeCmd(exchanges[i].cmd.bytes), rd1 = exchanges[i].rsp ? decodeRsp(exchanges[i].rsp.bytes) : null;
    const cd2 = decodeCmd(exchanges[i+1].cmd.bytes), rd2 = exchanges[i+1].rsp ? decodeRsp(exchanges[i+1].rsp.bytes) : null;
    if (!cd1 || !isAuthStep1(cd1) || !rd1 || rd1.sw !== 0x9000) continue;
    if (!cd2 || cd2.ins !== 0x87 || cd2?.data?.[0] !== 0x7C || cd2?.data?.[2] !== 0x82) continue;
    const rsp = rd1.data;
    if (!rsp || rsp[0] !== 0x7C || rsp[2] !== 0x80) continue;
    const nonce = Array.from(rsp.slice(4, 4 + rsp[3])), cmd = cd2.data;
    if (!cmd || cmd[3] == null) continue;
    const cryptogram = Array.from(cmd.slice(4, 4 + cmd[3]));
    if ((nonce.length !== 8 && nonce.length !== 16) || nonce.length !== cryptogram.length) continue;
    const pair = { type: "piv", ex1Id: exchanges[i].id, ex2Id: exchanges[i+1].id, nonce, cryptogram, succeeded: rd2?.sw === 0x9000, p2: cd2.p2 };
    testedPairs.push(pair);
    for (const k of KNOWN_KEYS) {
      if (k.alg !== "aes") continue;
      try {
        const enc = await aesEcbEncrypt(k.bytes, nonce);
        if (enc.every((b, i) => b === cryptogram[i])) { matches.push({ ...k, ...pair, method: "AES_ECB_encrypt(K, nonce)", protocol: "PIV 9B" }); continue; }
        const dec = await aesEcbDecrypt(k.bytes, nonce);
        if (dec.every((b, i) => b === cryptogram[i])) matches.push({ ...k, ...pair, method: "AES_ECB_decrypt(K, nonce)", protocol: "PIV 9B" });
      } catch (e) { /* expected: wrong key size or algorithm mismatch */ }
    }
  }
  // GP SCP03 pairs
  for (const pair of findSCP03Pairs(exchanges)) {
    testedPairs.push(pair);
    const context = new Uint8Array([...pair.hostChallenge, ...pair.cardChallenge]);
    for (const k of KNOWN_KEYS) {
      if (k.alg !== "aes" || k.bytes.length !== 16) continue;
      try {
        const smac = await deriveSCP03SessionKey(k.bytes, 0x06, context);
        const expectedCC = await calculateSCP03Cryptogram(smac, 0x00, context);
        if (expectedCC.every((b, i) => b === pair.cardCryptogram[i])) {
          const sEnc = await deriveSCP03SessionKey(k.bytes, 0x04, context);
          matches.push({ ...k, ...pair, method: "SCP03 card cryptogram — S-MAC via NIST SP 800-108 KDF", protocol: "GP SCP03", sEnc: Array.from(sEnc), sessionStart: pair.ex1Id });
        }
      } catch (e) { /* expected: wrong key size or algorithm mismatch */ }
    }
  }
  return { matches, testedPairs };
}

async function decryptSCP03Payload(cipherTextBytes, sEncKeyBytes) {
  const key = await crypto.subtle.importKey("raw", new Uint8Array(sEncKeyBytes), { name: "AES-CBC" }, false, ["decrypt"]);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, key, new Uint8Array(cipherTextBytes));
  const plain = Array.from(new Uint8Array(plainBuf));
  for (let i = plain.length - 1; i >= 0; i--) { if (plain[i] === 0x80) return plain.slice(0, i); if (plain[i] !== 0x00) break; }
  return plain;
}

async function unwrapSCP03(dataBytes, sEncKeyBytes) {
  if (!dataBytes?.length || !sEncKeyBytes?.length) return null;
  let i = 0;
  while (i < dataBytes.length) {
    const tag = dataBytes[i++]; if (i >= dataBytes.length) break;
    let len = dataBytes[i++];
    if (len === 0x81) len = dataBytes[i++];
    else if (len === 0x82) len = ((dataBytes[i++] << 8) | dataBytes[i++]);
    const val = dataBytes.slice(i, i + len); i += len;
    if ((tag === 0x81 || tag === 0x87 || tag === 0x85) && val.length > 1) {
      try { return await decryptSCP03Payload(val.slice(1), sEncKeyBytes); } catch { return null; }
    }
  }
  return null;
}


export { aesEcbEncrypt, aesEcbDecrypt, aesCMAC };
export { deriveSCP03SessionKey, calculateSCP03Cryptogram };
export { KNOWN_KEYS };
export { parseInitUpdateResponse, findSCP03Pairs };
export { checkKnownKeys };
export { decryptSCP03Payload, unwrapSCP03 };

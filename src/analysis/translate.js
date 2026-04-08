/**
 * Translate raw APDU sessions into high-level API operations.
 *
 * Produces human-readable operation summaries like "PIV.authenticate(keySlot=9B)"
 * that appear in session headers and forensic exports.
 */
import { h, decodeCmd, decodeRsp, hexStr } from "../decode.js";

/**
 * Convert a session's exchanges into high-level PIV/GP operations.
 * @returns {{ icon, label, detail }[]}
 */
export function translateToAPI(session, protocolStates) {
  const ops = [];
  const ins = (ex) => decodeCmd(ex.cmd.bytes)?.ins;
  const sw = (ex) => ex.rsp ? decodeRsp(ex.rsp.bytes)?.sw : null;
  let i = 0;
  while (i < session.length) {
    const ex = session[i];
    const cmd = decodeCmd(ex.cmd.bytes);
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;

    // GEN AUTH challenge-response pair
    if (ins(ex) === 0x87 && cmd?.p2) {
      const slot = { 0x9A: "9A", 0x9B: "9B", 0x9C: "9C", 0x9D: "9D" }[cmd.p2] ?? h(cmd.p2);
      if (cmd.data?.[0] === 0x7C && cmd.data?.[2] === 0x81) {
        const rsp2 = session[i + 1];
        if (rsp2 && ins(rsp2) === 0x87 && sw(rsp2) === 0x9000) {
          ops.push({ icon: "🔏", label: `PIV.authenticate(keySlot=${slot})`, detail: "Challenge-response completed" });
          i += 2; continue;
        }
      }
      if (cmd.data?.[2] === 0x82) {
        const ok = sw(ex) === 0x9000;
        ops.push({ icon: ok ? "✅" : "❌", label: `PIV.verifyAuth(keySlot=${slot})`, detail: ok ? "Accepted" : "Rejected" });
        i++; continue;
      }
    }
    if (ins(ex) === 0x20 && cmd?.p2 === 0x80) { const ok = sw(ex) === 0x9000; ops.push({ icon: ok ? "🔓" : "⚠", label: "PIV.verifyPIN()", detail: ok ? "PIN accepted" : "Rejected" }); i++; continue; }
    if ((ins(ex) === 0xCB || ins(ex) === 0xCA) && sw(ex) === 0x9000 && rsp?.data?.length) {
      const d = cmd?.data;
      const tag = d?.[0] === 0x5C ? hexStr(d.slice(2, 2 + (d[1] ?? 0))).replace(/ /g, "") : null;
      const PIV_OBJ = { "5FC102": "CHUID", "5FC103": "CC", "5FC105": "X.509 Auth", "5FC10A": "X.509 Sign", "7E": "PIV Discovery" };
      ops.push({ icon: "📄", label: `card.getData(${PIV_OBJ[tag] ?? (tag ? `obj:${tag}` : "data object")})`, detail: `${rsp.data.length}B` });
      i++; continue;
    }
    if (ins(ex) === 0xDB && sw(ex) === 0x9000) { const d = cmd?.data, tag = d?.[0] === 0x5C ? hexStr(d.slice(2, 2 + (d[1] ?? 0))).replace(/ /g, "") : "?"; ops.push({ icon: "✎", label: `card.putData(${tag})`, detail: `${cmd?.lc ?? 0}B written` }); i++; continue; }
    if (ins(ex) === 0x24) { const ok = sw(ex) === 0x9000; ops.push({ icon: ok ? "🔑" : "⚠", label: "PIV.changeReferenceData()", detail: ok ? "Credential updated" : "Failed" }); i++; continue; }
    if (ins(ex) === 0x82) { const ok = sw(ex) === 0x9000; ops.push({ icon: ok ? "🔐" : "❌", label: "GP.externalAuthenticate()", detail: ok ? "Host authenticated to card" : "Rejected" }); i++; continue; }
    i++;
  }
  return ops;
}

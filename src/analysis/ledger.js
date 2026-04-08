/**
 * Data object access ledger.
 *
 * Tracks every SELECT, GET DATA, and PUT DATA by object ID,
 * building a summary of reads, writes, mutations, and access errors.
 */
import { h, hexStr, decodeCmd, decodeRsp } from "../decode.js";
import { aidLabel } from "../protocol.js";
import { lookupTag } from "../knowledge.js";

/** Extract the data object identifier from a command. */
export function extractObjectId(cmd) {
  if (!cmd) return null;
  if (cmd.ins === 0xCB || cmd.ins === 0xDB) {
    const d = cmd.data;
    if (!d || d[0] !== 0x5C || !d[1]) return null;
    return Array.from(d.slice(2, 2 + d[1])).map(b => h(b)).join(" ");
  }
  if (cmd.ins === 0xCA) {
    if (cmd.p1 === 0 && cmd.p2 === 0) return null;
    return cmd.p1 === 0 ? h(cmd.p2) : `${h(cmd.p1)} ${h(cmd.p2)}`;
  }
  if (cmd.ins === 0xA4) {
    if (!cmd.data?.length) return "3F 00";
    return Array.from(cmd.data).map(b => h(b)).join(" ");
  }
  return null;
}

/**
 * Build an object-level access ledger from the exchange stream.
 * @returns {{ id, label, type, reads, writes, classification, ... }[]}
 */
export function buildObjectLedger(exchanges, protocolStates) {
  const map = new Map();
  const entry = (id) => {
    if (!map.has(id)) map.set(id, {
      id, label: null, type: null,
      reads: { ok: 0, fail: 0, sws: new Set() },
      writes: { ok: 0, fail: 0 },
      firstEx: null, lastEx: null, firstExId: null,
      app: null, size: null, mutated: false, classification: null,
    });
    return map.get(id);
  };

  for (const ex of exchanges) {
    const cmd = decodeCmd(ex.cmd.bytes);
    const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    const ps = protocolStates?.[ex.id];
    if (!cmd) continue;
    const isRead = cmd.ins === 0xCB || cmd.ins === 0xCA;
    const isWrite = cmd.ins === 0xDB;
    const isSel = cmd.ins === 0xA4;
    if (!isRead && !isWrite && !isSel) continue;
    const id = extractObjectId(cmd);
    if (!id) continue;
    const e = entry(id);
    if (e.firstEx === null) { e.firstEx = ex.id; e.firstExId = ex.id; }
    e.lastEx = ex.id;
    e.type = isSel ? "aid" : "data-object";
    if (!e.app && ps?.selected) e.app = ps.selected;
    if (!e.label) {
      if (isSel) e.label = aidLabel(id) ?? `AID ${id.substring(0, 23)}${id.length > 23 ? "…" : ""}`;
      else {
        try {
          const tb = cmd.data?.[0] === 0x5C ? cmd.data?.slice(2, 2 + (cmd.data?.[1] ?? 0)) : null;
          const known = tb?.length > 0 ? lookupTag(tb) : null;
          e.label = known?.name ?? `Tag ${id}`;
        } catch { e.label = `Tag ${id}`; }
      }
    }
    if (isRead) {
      if (rsp?.sw === 0x9000) { e.reads.ok++; if (rsp.data?.length) e.size = rsp.data.length; }
      else if (rsp) { e.reads.fail++; if (rsp.sw) e.reads.sws.add(`${h(rsp.sw1)}${h(rsp.sw2)}`); }
    }
    if (isWrite) {
      if (rsp?.sw === 0x9000) { e.writes.ok++; e.mutated = true; }
      else if (rsp) e.writes.fail++;
    }
  }

  const EXPECTED_SWS = new Set(["6a82", "6a80", "6a81", "6881", "6d00", "6e00"]);
  for (const e of map.values()) {
    e.reads.sws = [...e.reads.sws];
    if (e.mutated) e.classification = "mutated";
    else if (e.reads.ok > 0 || e.writes.ok > 0) e.classification = "present";
    else if (e.reads.fail > 0 || e.writes.fail > 0) e.classification = e.reads.sws.every(sw => EXPECTED_SWS.has(sw.toLowerCase())) ? "expected-absent" : "access-error";
    else e.classification = "probed";
  }
  const ORDER = { mutated: 0, present: 1, "access-error": 2, "expected-absent": 3, probed: 4 };
  return [...map.values()].sort((a, b) => ((ORDER[a.classification] ?? 5) - (ORDER[b.classification] ?? 5)) || (a.firstEx - b.firstEx));
}

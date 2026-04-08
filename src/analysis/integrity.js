/**
 * Trace completeness and confidence analyzer.
 *
 * Examines the exchange sequence for signs of truncation, filtering,
 * or insufficient capture. Returns a kind/confidence assessment that
 * other modules use to calibrate their analysis.
 */
import { decodeCmd, decodeRsp, INS_MAP, h, timeToSec } from "../decode.js";

/**
 * Assess whether the trace is complete, fragmented, or filtered.
 *
 * @returns {{ kind: "complete"|"fragment"|"filtered"|"filtered-fragment"|"snippet"|"empty",
 *             confidence: "high"|"medium"|"low"|"none",
 *             sessionKind, warnings: string[], isFragment, isFiltered, isTiny }}
 */
export function analyzeIntegrity(exchanges, sessions) {
  if (!exchanges.length) return { kind: "empty", confidence: "none", warnings: [], sessionKind: "none" };
  const warnings = [];
  const firstCmd = decodeCmd(exchanges[0].cmd.bytes);
  const orphans = exchanges.filter(ex => !ex.rsp);
  if (orphans.length) warnings.push(`${orphans.length} command${orphans.length > 1 ? "s" : ""} without a response — trace may be truncated`);
  const looksLikeStart = [0xA4, 0xCB, 0x84].includes(firstCmd?.ins);
  if (!looksLikeStart && exchanges.length > 2) warnings.push(`Trace starts mid-operation with ${firstCmd ? (INS_MAP[firstCmd.ins] || `INS ${h(firstCmd.ins)}`) : "unknown"} — setup not visible`);

  let maxGap = 0, maxGapAt = null;
  for (let i = 1; i < exchanges.length; i++) {
    const gap = timeToSec(exchanges[i].cmd.ts) - timeToSec(exchanges[i - 1].cmd.ts);
    if (gap > maxGap) { maxGap = gap; maxGapAt = exchanges[i].id; }
  }
  if (maxGap > 300) warnings.push(`${Math.round(maxGap / 60)}min gap before exchange #${maxGapAt} — log may be filtered`);
  if (exchanges.length < 4) warnings.push(`Only ${exchanges.length} exchange${exchanges.length > 1 ? "s" : ""} — insufficient for session-level analysis`);

  const isFragment = !looksLikeStart || orphans.length > 0;
  const isFiltered = maxGap > 300;
  const isTiny = exchanges.length < 4;
  let kind, confidence, sessionKind;
  if (isTiny)                     { kind = "snippet";           confidence = "low";    sessionKind = "indeterminate"; }
  else if (isFragment && isFiltered) { kind = "filtered-fragment"; confidence = "low";    sessionKind = "chunks"; }
  else if (isFragment)            { kind = "fragment";          confidence = "medium"; sessionKind = "partial"; }
  else if (isFiltered)            { kind = "filtered";          confidence = "medium"; sessionKind = sessions.length > 1 ? "sessions" : "chunks"; }
  else                            { kind = "complete";          confidence = "high";   sessionKind = "sessions"; }
  return { kind, confidence, sessionKind, warnings, isFragment, isFiltered, isTiny };
}

/**
 * Count error categories: probe misses, channel errors, real failures.
 * @returns {{ misses, channelErrors, failures, total }}
 */
export function classifyErrors(exchanges) {
  let misses = 0, channelErrors = 0, failures = 0;
  for (const ex of exchanges) {
    const sw = ex.rsp ? decodeRsp(ex.rsp.bytes)?.sw : null;
    if (!sw || sw === 0x9000 || (sw >> 8) === 0x61) continue;
    if ([0x6A82, 0x6A86, 0x6D00, 0x6800].includes(sw)) misses++;
    else if ([0x6881, 0x6982].includes(sw)) channelErrors++;
    else if ([0x6983, 0x6984, 0x6A80].includes(sw)) failures++;
  }
  return { misses, channelErrors, failures, total: misses + channelErrors + failures };
}

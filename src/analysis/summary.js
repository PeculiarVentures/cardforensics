/**
 * Trace summary builder for the FindingsPanel header.
 */
import { C } from "../theme.js";

/**
 * Build a one-line summary of trace integrity for UI display.
 * @returns {{ heading, body, color }} | null
 */
export function buildTopSummary(integrity, exchangeCount = 0) {
  if (!integrity || integrity.kind === "empty") return null;
  if (integrity.kind === "snippet")
    return { heading: "Insufficient context", body: `Only ${exchangeCount} exchange${exchangeCount !== 1 ? "s" : ""} visible — per-exchange annotations are accurate.`, color: C.amber };
  if (integrity.kind === "fragment")
    return { heading: "Partial trace — context is missing", body: "Starts mid-operation. Per-exchange annotations are accurate.", color: C.amber };
  if (integrity.kind === "filtered-fragment")
    return { heading: "Filtered or fragmented trace", body: "Starts mid-operation and contains large time gaps. Per-exchange annotations are reliable.", color: C.red };
  if (integrity.kind === "filtered")
    return { heading: "Filtered trace — gaps detected", body: "Large time gaps suggest filtered capture.", color: C.amber };
  return { heading: null, body: "", color: C.green };
}

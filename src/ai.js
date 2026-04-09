/**
 * Anthropic Claude API client, prompt builders, and batch analysis.
 *
 * Uses Haiku for speed. Auth is injected by the artifact runtime.
 * Sensitive commands (VERIFY, CHANGE PIN) are redacted before sending.
 * Timeout via Promise.race (AbortSignal not cloneable in artifact env).
 */
// ── AI PIPELINE ───────────────────────────────────────────────────────────
// Anthropic Claude API client, prompt builders, and batch analysis.
// Uses Haiku for speed. Auth injected by artifact runtime or proxy.
import { isSandbox } from "./storage.js";
import { getApiConfig } from "./components/ApiConfig.jsx";
// Sensitive commands (VERIFY, CHANGE PIN) are redacted before sending.
import { h, hexStr, decodeCmd, decodeRsp, INS_MAP } from "./decode.js";
import { buildProtocolStates } from "./protocol.js";
import { autoAnnotate, classifySW, SENSITIVE_INS } from "./analysis/index.js";

const MODEL = "claude-haiku-4-5-20251001";
const SESSION_MODEL = "claude-sonnet-4-20250514";

function sanitizeDataForAI(cd) {
  if (!cd?.data?.length) return null;
  if (SENSITIVE_INS.has(cd.ins)) return `[${cd.lc}B REDACTED — credential data]`;
  return hexStr(cd.data).substring(0, 30) + (cd.data.length > 10 ? "…" : "");
}

function compactExchange(ex) {
  const cd = decodeCmd(ex.cmd.bytes), rd = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
  const ins = cd ? (INS_MAP[cd.ins] ?? `INS:${h(cd.ins)}`) : "?", sw = rd ? h(rd.sw1) + h(rd.sw2) : "—";
  const data = sanitizeDataForAI(cd);
  return `[${ex.id}] ${ins} CLA=${h(cd?.cla)} P1=${h(cd?.p1)} P2=${h(cd?.p2)}${data ? ` [${data}]` : ""} → ${sw}${rd?.data?.length ? ` ← ${rd.data.length}B` : ""}`;
}

function buildExchangePrompt(ex, exchanges, protocolState) {
  const cd = decodeCmd(ex.cmd.bytes), rd = ex.rsp ? decodeRsp(ex.rsp.bytes) : null, ann = autoAnnotate(ex, protocolState);
  const ctx = exchanges.slice(Math.max(0, ex.id - 5), ex.id).map(compactExchange).join("\n");
  const stateStr = protocolState ? `Channel ${protocolState.chNum} · ${protocolState.selected ?? "none"} · ${protocolState.authenticated ? `${protocolState.scp} authenticated` : "unauthenticated"}` : "unknown";
  return `Smart card APDU trace. Protocol state: ${stateStr}\n\nContext:\n${ctx || "(trace start)"}\n\nCurrent [${ex.id}]:\nCMD: ${cd ? `INS=${INS_MAP[cd.ins]??h(cd.ins)} CLA=${h(cd.cla)} P1=${h(cd.p1)} P2=${h(cd.p2)}${cd.lc!=null?` Lc=${cd.lc}`:""} Data=${sanitizeDataForAI(cd)??"(none)"}` : ex.cmd.hex.substring(0,30)}\nRSP: ${rd ? `SW=${h(rd.sw1)}${h(rd.sw2)}${rd.data?.length?` Data:${hexStr(rd.data).substring(0,40)}`:""}`:"(none)"}\nRules note: ${ann?.note??"none"}\n\nIn 2–3 sentences explain what this exchange does, why it's here, and flag anomalies. Expert audience.`;
}

function isKeyEvent(ex, protocolState) {
  const cd = decodeCmd(ex.cmd.bytes), rd = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
  if (!cd) return false;
  if ([0xA4, 0x87, 0x82, 0x84, 0x50, 0x2C, 0x20].includes(cd.ins)) return true;
  if (cd.ins === 0xDB && (cd.lc ?? 0) > 10) return true;
  const ann = autoAnnotate(ex, protocolState);
  if (ann?.flag === "bug" || ann?.flag === "key") return true;
  if (rd?.sw === 0x9000 && (rd.data?.length ?? 0) > 4 && (cd.ins === 0xCB || cd.ins === 0xCA)) return true;
  if (rd && rd.sw !== 0x9000) { const cls = classifySW(rd.sw, cd, protocolState); return cls === "anomaly" || cls === "notable"; }
  return false;
}

/**
 * Build the session-level AI summary prompt. Includes key events from each
 * session plus any existing per-exchange AI notes as enriched context.
 * Called AFTER batch annotation completes so the prompt benefits from
 * per-exchange analysis. Response format: JSON with card, finding, sessions[].
 */
function buildSessionPrompt(sessions, exchanges, aiCache, keyCheck) {
  const protocolStates = buildProtocolStates(exchanges);
  const blocks = sessions.map((session, si) => {
    const keyExs = session.filter(ex => isKeyEvent(ex, protocolStates[ex.id]));
    const probeMisses = session.filter(ex => { const cd = decodeCmd(ex.cmd.bytes), rd = ex.rsp ? decodeRsp(ex.rsp.bytes) : null; if (!rd || rd.sw === 0x9000) return false; return classifySW(rd.sw, cd, protocolStates[ex.id]) === "expected"; });
    const lines = keyExs.map(ex => {
      const cd = decodeCmd(ex.cmd.bytes), rd = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
      const ann = autoAnnotate(ex, protocolStates?.[ex.id]), ai = aiCache?.current?.get(ex.id);
      const cls = rd && rd.sw !== 0x9000 ? ` [${classifySW(rd.sw, cd, protocolStates[ex.id])}]` : "";
      const parts = [compactExchange(ex) + cls];
      if (ann?.note) parts.push(`  annotation: ${ann.note}`);
      if (ai) parts.push(`  ai_note: ${ai}`);
      return parts.join("\n");
    }).join("\n");
    return `=== Session ${si + 1} | ${session.length} exchanges | ${keyExs.length} key events ===\n${probeMisses.length > 0 ? `(${probeMisses.length} expected probe misses omitted)` : ""}\n${lines || "(no key events)"}`;
  }).join("\n\n");

  // Include deterministic key check results so AI doesn't guess the algorithm
  let keyCheckNote = "";
  if (keyCheck?.matches?.length) {
    const methods = [...new Set(keyCheck.matches.map(m => `${m.method} (${m.name})`))];
    keyCheckNote = `\n\nDETERMINISTIC KEY CHECK: Default management key matched via ${methods.join("; ")}. The algorithm is AES — do NOT describe it as 3DES.\n`;
  }

  return `Analyze this smart card APDU trace (macOS CryptoTokenKit). 6A82/6A80/6881/6D00 during discovery are expected probe misses, NOT bugs.\nRespond ONLY with raw JSON. No markdown, no backticks, no preamble.\n${keyCheckNote}\n${blocks}\n\nRequired JSON:\n{"card":"card model or null","protocol":"protocol summary","finding":"Executive narrative: synthesize the entire trace into a coherent story. What was the operator trying to accomplish across all sessions, what was the outcome, and what is the state of the card now? Mention key findings (lockouts, provisioning gaps, credential exposure) in context. Write for someone who will read only this paragraph. 3-4 sentences.","sessions":[{"label":"short descriptive title","summary":"3-4 sentence technical analysis of this session: what commands ran, what succeeded/failed, and what changed on the card."}]}\n\nStart with { end with }.`;
}

function buildBatchPrompt(chunk, protocolStates) {
  const ps0 = protocolStates[chunk[0].id];
  const stateStr = ps0 ? `ch${ps0.chNum} · ${ps0.selected ?? "no app"} · ${ps0.authenticated ? (ps0.scp ?? "SCP") + " active (inferred)" : "unauthenticated"} · ${ps0.phase ?? "unknown"}` : "unknown";
  const lines = chunk.map(ex => {
    const cd = decodeCmd(ex.cmd.bytes), rd = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
    const ann = autoAnnotate(ex, protocolStates?.[ex.id]);
    let line = `[${ex.id}] ${cd ? (INS_MAP[cd.ins] ?? `INS ${h(cd.ins)}`) : "?"} CLA=${h(cd?.cla)} P1=${h(cd?.p1)} P2=${h(cd?.p2)}${cd?.data?.length ? ` data:[${hexStr(cd.data).substring(0,24)}${cd.data.length>8?"…":""}]` : ""} → ${rd ? h(rd.sw1)+h(rd.sw2) : "—"}${rd?.data?.length ? ` rsp:${rd.data.length}B` : ""}`;
    if (ann?.note) line += `\n  note: ${ann.note}`;
    return line;
  }).join("\n");
  return `Smart card APDU exchanges. State at start: ${stateStr}.\n\n${lines}\n\nReturn ONLY a JSON array:\n[{"id":N,"text":"1-sentence expert explanation"}]`;
}

/**
 * Extract first complete JSON object or array from potentially noisy LLM
 * response. Strips markdown fences, handles truncated arrays gracefully.
 * @returns {string|null} Raw JSON string or null
 */
function extractJSON(text) {
  if (!text) return null;
  let s = text.replace(/```json\s*/gi, "").replace(/```/g, "").replace(/^json\s*/i, "").trim();
  const start = Math.min(s.indexOf("{") === -1 ? Infinity : s.indexOf("{"), s.indexOf("[") === -1 ? Infinity : s.indexOf("["));
  if (start === Infinity) return null;
  const open = s[start], close = open === "{" ? "}" : "]";
  let depth = 0, lastComplete = -1;
  for (let i = start; i < s.length; i++) {
    if (s[i] === open) depth++;
    else if (s[i] === close) { depth--; if (depth === 0) return s.slice(start, i + 1); if (depth === 1) lastComplete = i; }
  }
  return (open === "[" && lastComplete > start) ? s.slice(start, lastComplete + 1) + "]" : null;
}

/**
 * Call Anthropic Messages API with retry on rate-limit (429) and overload (529/503).
 * The artifact runtime injects auth via the anthropic-dangerous-direct-browser-access
 * header. Timeout is 90s via Promise.race (AbortSignal cannot be cloned
 * across the artifact postMessage boundary).
 * @param {string} prompt - User message content
 * @param {string|null} system - System prompt (null = none)
 * @param {number} maxTokens - Max response tokens
 * @param {string} model - Model ID (default: Haiku)
 * @param {number} _retries - Internal retry counter
 * @returns {Promise<string|null>} Cleaned response text
 */
async function callClaude(prompt, system, maxTokens = 300, model = MODEL, _retries = 3) {
  const config = !isSandbox() ? getApiConfig() : null;
  const provider = config?.provider ?? "anthropic";
  const apiKey = config?.apiKey ?? null;

  // Standalone mode without API key: skip AI gracefully
  if (!isSandbox() && !apiKey) {
    throw new Error(`API key required. Configure in the settings panel on the drop page.`);
  }

  // Override model if config specifies one (standalone mode)
  if (config && model === MODEL) model = config.batchModel ?? model;
  if (config && model === SESSION_MODEL) model = config.sessionModel ?? model;

  let fetchPromise;

  if (provider === "anthropic") {
    const body = { model, max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] };
    if (system) body.system = system;
    const headers = { "Content-Type": "application/json", "anthropic-version": "2023-06-01" };
    if (!isSandbox()) {
      headers["anthropic-dangerous-direct-browser-access"] = "true";
      if (apiKey) headers["x-api-key"] = apiKey;
    }
    fetchPromise = fetch("https://api.anthropic.com/v1/messages", { method: "POST", headers, body: JSON.stringify(body) });
  } else if (provider === "openai") {
    const messages = [];
    if (system) messages.push({ role: "system", content: system });
    messages.push({ role: "user", content: prompt });
    fetchPromise = fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
      body: JSON.stringify({ model, max_tokens: maxTokens, messages }),
    });
  } else if (provider === "gemini") {
    const body = { contents: [{ role: "user", parts: [{ text: system ? `${system}\n\n${prompt}` : prompt }] }], generationConfig: { maxOutputTokens: maxTokens } };
    fetchPromise = fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
  } else {
    throw new Error(`Unknown provider: ${provider}`);
  }

  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("Request timed out after 60s")), 60000)
  );

  let r;
  try {
    r = await Promise.race([fetchPromise, timeoutPromise]);
  } catch (e) { throw new Error(e.message.includes("timed out") ? e.message : "Network error: " + e.message); }
  if ((r.status === 429 || r.status === 529 || r.status === 503) && _retries > 0) { await new Promise(res => setTimeout(res, r.status === 529 ? 8000 : (4 - _retries) * 3000)); return callClaude(prompt, system, maxTokens, model, _retries - 1); }
  const data = await r.json();
  if (!r.ok || data.error) {
    const msg = data?.error?.message ?? `API error ${r.status}`, type = data?.error?.type ?? "";
    throw new Error(type === "overloaded" || r.status === 529 ? "API overloaded — will retry" : type === "rate_limit_error" ? "Rate limited — will retry" : `${r.status}: ${msg}`);
  }

  // Extract text from provider-specific response format
  let raw = null;
  if (provider === "openai") raw = data.choices?.[0]?.message?.content;
  else if (provider === "gemini") raw = data.candidates?.[0]?.content?.parts?.[0]?.text;
  else raw = data.content?.[0]?.text;

  if (data.stop_reason === "max_tokens" || data.choices?.[0]?.finish_reason === "length")
    console.warn("API response truncated (max_tokens). Increase token limit or shorten prompt.");
  return raw ? raw.replace(/^json\s*/i, "").trim() : null;
}

/** Annotate a chunk of exchanges via AI. Results stored in aiCache ref. */
async function analyzeBatch(chunk, protocolStates, aiCache) {
  const text = await callClaude(buildBatchPrompt(chunk, protocolStates), "You are an expert in ISO 7816-4, GlobalPlatform, PIV (NIST SP 800-73), and SCP03. Never repeat hex values — interpret meaning. 1 sentence per exchange.", chunk.length * 80 + 200);
  if (!text) return;
  try {
    const results = JSON.parse(extractJSON(text));
    if (!Array.isArray(results)) return;
    for (const r of results) if (r?.id != null && r?.text) aiCache.current.set(r.id, r.text);
  } catch (e) { console.warn("AI batch parse failed:", e.message); }
}


export { MODEL, SESSION_MODEL, sanitizeDataForAI, compactExchange };
export { buildExchangePrompt, isKeyEvent, buildSessionPrompt, buildBatchPrompt };
export { callClaude, extractJSON, analyzeBatch };

/**
 * useAIBatching — AI annotation pipeline.
 *
 * Manages the batch annotation loop, session-level analysis,
 * and persistent cache (localStorage or sandbox storage).
 *
 * Resets automatically when trace changes.
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { storage, isSandbox } from "../storage.js";
import { traceHash } from "../decode.js";
import { getApiConfig } from "../components/ApiConfig.jsx";
import { buildSessionPrompt, callClaude, extractJSON, analyzeBatch, SESSION_MODEL } from "../ai.js";

export default function useAIBatching(trace, exchanges, sessions, protocolStatesRef, keyCheck) {
  const aiCache = useRef(new Map());
  const [aiSessions, setAiSessions]             = useState(null);
  const [aiSessionsLoading, setAiSessionsLoading] = useState(false);
  const [aiSessionsError, setAiSessionsError]   = useState(null);
  const [aiSessionsWarning, setAiSessionsWarning] = useState(null);
  const [aiTraceMeta, setAiTraceMeta]           = useState(null);
  const [lazyDone, setLazyDone]                 = useState(0);
  const [batchComplete, setBatchComplete]       = useState(false);
  const lazyRef = useRef({ running: false, aborted: false });

  // Cache keys derived from trace
  const cacheKey      = trace ? traceHash(trace.log) : null;
  const STORAGE_CACHE = cacheKey ? `apdu-cache-${cacheKey}` : null;
  const STORAGE_META  = cacheKey ? `apdu-meta-${cacheKey}`  : null;

  const aiAvailable = isSandbox() || (getApiConfig()?.apiKey?.length > 0);

  // ── Reset + cache restore when trace changes ──
  useEffect(() => {
    aiCache.current.clear();
    setAiSessions(null);
    setAiSessionsWarning(null);
    setAiTraceMeta(null);
    setAiSessionsError(null);
    lazyRef.current.aborted = true;
    setBatchComplete(false);
    setLazyDone(0);

    if (!trace || !STORAGE_CACHE || !STORAGE_META) return;
    (async () => {
      try {
        const cached = await storage.get(STORAGE_CACHE).catch(() => null);
        if (cached?.value) {
          const data = JSON.parse(cached.value);
          for (const [id, text] of Object.entries(data)) {
            aiCache.current.set(Number(id), text);
          }
        }
        const meta = await storage.get(STORAGE_META).catch(() => null);
        if (meta?.value) {
          const { sessions: s, traceMeta } = JSON.parse(meta.value);
          if (s) setAiSessions(s);
          if (traceMeta) setAiTraceMeta(traceMeta);
        }
      } catch (e) {
        console.debug("Cache restore failed:", e);
      }
    })();
  }, [trace]);

  // ── Batch AI annotation loop ──
  useEffect(() => {
    if (!exchanges.length || !sessions.length) return;
    lazyRef.current = { running: true, aborted: false };
    setLazyDone(0);
    setBatchComplete(false);

    if (!aiAvailable) {
      setBatchComplete(true);
      setAiSessionsError(!isSandbox() ? "AI disabled — add an API key on the drop page to enable" : null);
      return;
    }

    const CHUNK = 20;
    const chunks = sessions.flatMap(session => {
      const c = [];
      for (let i = 0; i < session.length; i += CHUNK) c.push(session.slice(i, i + CHUNK));
      return c;
    });
    let chunkIdx = 0;

    const processNext = async () => {
      while (chunkIdx < chunks.length) {
        if (lazyRef.current.aborted) return;
        const chunk = chunks[chunkIdx++];
        const uncached = chunk.filter(ex => !aiCache.current.has(ex.id));
        if (uncached.length) {
          try {
            await analyzeBatch(uncached, protocolStatesRef.current, aiCache);
            if (STORAGE_CACHE) {
              const snap = Object.fromEntries(aiCache.current);
              storage.set(STORAGE_CACHE, JSON.stringify(snap))
                .catch(e => console.debug("Cache write failed:", e));
            }
          } catch (err) {
            console.warn("Batch analysis failed:", err);
          }
        }
        setLazyDone(d => d + chunk.length);
        if (chunkIdx < chunks.length) {
          await new Promise(res => setTimeout(res, 800));
        }
      }
    };

    Promise.all([processNext()]).then(() => {
      if (!lazyRef.current.aborted) {
        setBatchComplete(true);
        triggerSessionAnalysis();
      }
    });
  }, [exchanges, sessions]);

  // ── Session-level analysis ──
  const triggerSessionAnalysis = useCallback(() => {
    if (!sessions.length || !aiAvailable) return;
    setAiSessionsLoading(true);
    setAiSessionsError(null);
    setAiSessionsWarning(null);

    const hasCached = (aiSessions?.length ?? 0) > 0;
    const slowTimer = hasCached
      ? null
      : setTimeout(() => setAiSessionsWarning("Taking longer than usual — API may be busy…"), 30000);

    let prompt;
    try {
      prompt = buildSessionPrompt(sessions, exchanges, aiCache, keyCheck);
    } catch (e) {
      setAiSessionsError("Failed to build prompt: " + e.message);
      setAiSessionsLoading(false);
      if (slowTimer) clearTimeout(slowTimer);
      return;
    }

    callClaude(prompt, null, 4096, SESSION_MODEL, 2)
      .then(text => {
        if (!text) {
          setAiSessionsError("No response from AI");
          return;
        }
        try {
          const raw = extractJSON(text);
          if (!raw) {
            setAiSessionsError("No JSON in response. Check browser console for raw text.");
            console.warn("Full AI response (no JSON found):", text);
            return;
          }
          const parsed = JSON.parse(raw);
          const sessionData = parsed?.sessions && Array.isArray(parsed.sessions)
            ? parsed.sessions
            : Array.isArray(parsed) ? parsed : null;
          if (!sessionData) {
            setAiSessionsError("Unexpected response format");
            return;
          }
          setAiSessions(sessionData);
          const meta = {
            card: parsed.card ?? null,
            protocol: parsed.protocol ?? null,
            finding: parsed.finding ?? null,
          };
          setAiTraceMeta(meta);
          if (STORAGE_META) {
            storage.set(STORAGE_META, JSON.stringify({ sessions: sessionData, traceMeta: meta }))
              .catch(e => console.debug("Meta write failed:", e));
          }
        } catch (e) {
          setAiSessionsError("Parse error: " + e.message);
        }
      })
      .catch(e => {
        setAiSessionsError(e.message ?? "Request failed");
      })
      .finally(() => {
        if (slowTimer) clearTimeout(slowTimer);
        setAiSessionsWarning(null);
        setAiSessionsLoading(false);
      });
  }, [sessions, exchanges, keyCheck, STORAGE_META]);

  // Trigger initial session analysis when sessions are ready (if no cached content)
  useEffect(() => {
    if (!sessions.length || aiSessionsLoading) return;
    if (aiSessions?.length) return;
    triggerSessionAnalysis();
  }, [sessions]);

  return {
    aiCache, aiSessions, aiSessionsLoading, aiSessionsError, aiSessionsWarning,
    aiTraceMeta, lazyDone, batchComplete, triggerSessionAnalysis,
  };
}

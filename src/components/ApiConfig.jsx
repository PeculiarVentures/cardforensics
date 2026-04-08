/** API configuration panel for standalone mode (outside artifact sandbox). */
import { useState, useEffect } from "react";
import { isSandbox } from "../storage.js";
import { C, BTN } from "../theme.js";

const PROVIDERS = {
  anthropic: { name: "Anthropic Claude", models: ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001"] },
  openai:    { name: "OpenAI",           models: ["gpt-4o", "gpt-4o-mini"] },
  gemini:    { name: "Google Gemini",     models: ["gemini-2.5-flash", "gemini-2.5-pro"] },
};

function loadConfig() {
  try {
    const stored = localStorage.getItem("cf-api-config");
    if (stored) return JSON.parse(stored);
  } catch {}
  return { provider: "anthropic", apiKey: "", batchModel: "claude-haiku-4-5-20251001", sessionModel: "claude-sonnet-4-20250514" };
}

function saveConfig(cfg) {
  try { localStorage.setItem("cf-api-config", JSON.stringify(cfg)); } catch {}
}

/** Exported for use by callClaude. */
export function getApiConfig() {
  if (isSandbox()) return null;
  return loadConfig();
}

const s = {
  wrap: { marginTop: 20, padding: "12px 16px", background: "#0d1117", borderRadius: 6, border: `1px solid ${C.border}`, maxWidth: 620, width: "100%", textAlign: "left" },
  label: { fontSize: 9, color: C.muted, marginBottom: 3, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.5px" },
  row: { marginBottom: 10 },
  input: { width: "100%", padding: "6px 8px", fontSize: 11, fontFamily: "monospace", background: "#080b11", color: C.text, border: `1px solid ${C.border}`, borderRadius: 4, outline: "none", boxSizing: "border-box" },
  select: { padding: "5px 8px", fontSize: 11, fontFamily: "monospace", background: "#080b11", color: C.text, border: `1px solid ${C.border}`, borderRadius: 4, outline: "none" },
  note: { fontSize: 9, color: C.dim, marginTop: 4, lineHeight: 1.5 },
};

function ApiConfig() {
  const [cfg, setCfg] = useState(loadConfig);
  const [saved, setSaved] = useState(false);

  if (isSandbox()) return null;

  const provider = PROVIDERS[cfg.provider];
  const update = (field, value) => {
    const next = { ...cfg, [field]: value };
    // Reset models when provider changes
    if (field === "provider") {
      const p = PROVIDERS[value];
      next.batchModel = p.models[p.models.length - 1];
      next.sessionModel = p.models[0];
    }
    setCfg(next);
  };

  const handleSave = () => { saveConfig(cfg); setSaved(true); setTimeout(() => setSaved(false), 2000); };

  return (
    <div style={s.wrap}>
      <div style={{ ...s.label, marginBottom: 8, color: C.teal }}>API Configuration (standalone mode)</div>

      <div style={s.row}>
        <div style={s.label}>Provider</div>
        <div style={{ display: "flex", gap: 6 }}>
          {Object.entries(PROVIDERS).map(([key, p]) => (
            <button key={key} onClick={() => update("provider", key)}
              style={{ ...BTN, fontSize: 10, color: cfg.provider === key ? C.teal : C.dim, borderColor: cfg.provider === key ? C.teal + "66" : C.border }}>
              {p.name}
            </button>
          ))}
        </div>
      </div>

      <div style={s.row}>
        <div style={s.label}>API Key</div>
        <input type="password" value={cfg.apiKey} onChange={e => update("apiKey", e.target.value)}
          placeholder={`${provider.name} API key`} style={s.input} />
      </div>

      <div style={{ display: "flex", gap: 12 }}>
        <div style={{ ...s.row, flex: 1 }}>
          <div style={s.label}>Batch annotation model (fast)</div>
          <select value={cfg.batchModel} onChange={e => update("batchModel", e.target.value)} style={s.select}>
            {provider.models.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
        <div style={{ ...s.row, flex: 1 }}>
          <div style={s.label}>Session analysis model (smart)</div>
          <select value={cfg.sessionModel} onChange={e => update("sessionModel", e.target.value)} style={s.select}>
            {provider.models.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <button onClick={handleSave} style={{ ...BTN, fontSize: 10, color: C.teal, borderColor: C.teal + "66" }}>
          {saved ? "Saved" : "Save"}
        </button>
        <span style={s.note}>
          {cfg.provider !== "anthropic" && "Only Anthropic Claude is fully supported. Other providers may produce parsing errors."}
        </span>
      </div>
    </div>
  );
}

export default ApiConfig;

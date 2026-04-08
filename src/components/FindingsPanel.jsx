/** Security findings with severity filtering, threat aggregation, and key check results. */
import { useState } from "react";
import { h } from "../decode.js";
import { buildTopSummary, PIV_CERT_SLOT_TAGS } from "../analysis/index.js";
import { KNOWN_KEYS } from "../crypto.js";
import { C, BG } from "../theme.js";
import CopyBtn from "./CopyBtn.jsx";

const SEV_ORDER = { critical: 0, warn: 1, info: 2, pass: 3 };
const SEV_COLORS = { critical: C.red, warn: C.amber, info: C.teal, pass: C.green };
const SEV_LABELS = { critical: "Critical", warn: "Warning", info: "Info", pass: "Pass" };

const styles = {
  container: { background: BG.findings, borderBottom: `1px solid ${C.border}`, fontSize: 11 },
  header: {
    padding: "8px 12px", display: "flex", alignItems: "center", gap: 8,
    cursor: "pointer", userSelect: "none",
  },
  filterBtn: (active, color) => ({
    fontSize: 9, padding: "1px 6px", borderRadius: 3, cursor: "pointer",
    fontFamily: "monospace", border: `1px solid ${active ? color : C.border}`,
    background: active ? color + "22" : "transparent",
    color: active ? color : C.muted,
  }),
  findingRow: (color) => ({
    padding: "6px 12px", borderLeft: `3px solid ${color}`,
    borderBottom: `1px solid ${C.border}`, lineHeight: 1.5,
  }),
  section: {
    padding: "6px 12px", borderBottom: `1px solid ${C.border}`, lineHeight: 1.5,
  },
};

function FindingsPanel({ integrity, keyCheck, aiSessions, aiTraceMeta, aiSessionsLoading, aiSessionsError, lazyDone, exchangeCount, exchanges, protocolStates, certProvision, cardId, securityScore, complianceProfile, activeThreats, onSelectExchange }) {
  const [collapsed, setCollapsed] = useState(false);
  const [sevFilter, setSevFilter] = useState(null);
  const topSummary = buildTopSummary(integrity, exchangeCount);

  const threats = (activeThreats ?? [])
    .filter(t => !sevFilter || t.severity === sevFilter)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header} onClick={() => setCollapsed(c => !c)}>
        <span style={{ color: C.teal, fontWeight: 700 }}>🔍 Findings</span>
        {securityScore && <span style={{ color: securityScore.color, fontWeight: 700, fontSize: 12 }}>{securityScore.score}</span>}
        {securityScore && <span style={{ color: C.muted }}>{securityScore.label}</span>}
        {activeThreats?.length > 0 && <span style={{ color: C.red, fontWeight: 700 }}>{activeThreats.filter(t => t.severity === "critical").length} critical</span>}
        <span style={{ marginLeft: "auto", color: C.dim }}>{collapsed ? "▶" : "▼"}</span>
      </div>

      {!collapsed && (
        <div>
          {/* Integrity summary */}
          {topSummary?.heading && (
            <div style={{ ...styles.section, borderLeft: `3px solid ${topSummary.color}` }}>
              <div style={{ fontWeight: 700, color: topSummary.color }}>{topSummary.heading}</div>
              <div style={{ color: C.muted }}>{topSummary.body}</div>
            </div>
          )}

          {/* Key check results */}
          {keyCheck && keyCheck.matches.length > 0 && (() => {
            // Deduplicate by key id — show each matched key once
            const uniqueKeys = new Map();
            for (const m of keyCheck.matches) {
              if (!uniqueKeys.has(m.id)) uniqueKeys.set(m.id, { ...m, count: 1 });
              else uniqueKeys.get(m.id).count++;
            }
            return (
              <div style={{ ...styles.section, borderLeft: `3px solid ${C.red}` }}>
                <div style={{ fontWeight: 700, color: C.red, marginBottom: 6 }}>Default Management Key Detected</div>
                {[...uniqueKeys.values()].map((m, i) => (
                  <div key={i} style={{ marginBottom: 8 }}>
                    <div style={{ color: C.text, fontWeight: 600, fontSize: 11 }}>{m.name}</div>
                    <div style={{ color: "#8899bb", fontSize: 10, marginTop: 2 }}>Method: {m.method} ({m.count} match{m.count > 1 ? "es" : ""})</div>
                    <div style={{ color: "#8899bb", fontSize: 10, marginTop: 1 }}>Source: {m.source}</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 3 }}>
                      <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{m.bytes.map(b => h(b)).join(" ")}</span>
                      <CopyBtn value={m.bytes.map(b => h(b)).join(" ")} label="key" />
                    </div>
                  </div>
                ))}
              </div>
            );
          })()}

          {/* Cert provisioning */}
          {certProvision?.probed.length > 0 && (
            <div style={{ ...styles.section, borderLeft: `3px solid ${certProvision.allEmpty ? C.red : certProvision.partial ? C.amber : C.green}` }}>
              <div style={{ fontWeight: 700, color: certProvision.allEmpty ? C.red : certProvision.partial ? C.amber : C.green }}>
                PIV Certificates: {certProvision.populated.length}/{certProvision.probed.length} populated
              </div>
              {certProvision.probed.map(tag => {
                const slot = PIV_CERT_SLOT_TAGS[tag];
                const info = certProvision.slotDetails[tag];
                const exId = info?.populatedExId ?? info?.exchangeId;
                const clickable = exId != null && onSelectExchange;
                return (
                  <div key={tag}
                    onClick={clickable ? () => onSelectExchange(exchanges.find(ex => ex.id === exId)) : undefined}
                    style={{ color: info?.populated ? C.green : C.red, fontSize: 10, marginTop: 2, cursor: clickable ? "pointer" : "default", display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ flex: 1 }}>
                      {info?.populated ? "+" : "-"} {slot?.name ?? tag} (slot {slot?.slot ?? "?"}) {info?.populated ? `${info.size}B` : "empty"}
                    </span>
                    {clickable && <span style={{ color: C.dim, fontSize: 9 }}>#{exId}</span>}
                  </div>
                );
              })}
            </div>
          )}

          {/* Severity filter */}
          {activeThreats?.length > 0 && (
            <div style={{ padding: "4px 12px", display: "flex", gap: 4, alignItems: "center", borderBottom: `1px solid ${C.border}` }}>
              <span style={{ color: C.muted, fontSize: 9 }}>Filter:</span>
              {["critical", "warn", "info", "pass"].map(sev => {
                const count = activeThreats.filter(t => t.severity === sev).length;
                if (!count) return null;
                return (
                  <button key={sev} onClick={() => setSevFilter(f => f === sev ? null : sev)}
                    style={styles.filterBtn(sevFilter === sev, SEV_COLORS[sev])}>
                    {SEV_LABELS[sev]} ({count})
                  </button>
                );
              })}
            </div>
          )}

          {/* Threat list */}
          {threats.map((t, i) => {
            const clickable = t.exchangeId != null && onSelectExchange;
            return (
              <div key={i} style={{ ...styles.findingRow(SEV_COLORS[t.severity] ?? C.dim), cursor: clickable ? "pointer" : "default" }}
                onClick={clickable ? () => onSelectExchange(exchanges.find(ex => ex.id === t.exchangeId)) : undefined}>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontWeight: 600, color: SEV_COLORS[t.severity] ?? C.text, flex: 1 }}>
                    {t.title}
                  </span>
                  {clickable && <span style={{ color: C.dim, fontSize: 9, flexShrink: 0 }}>#{t.exchangeId}</span>}
                </div>
                <div style={{ color: C.muted, fontSize: 10, marginTop: 2 }}>{t.detail}</div>
                {t.cred && <CopyBtn value={t.cred} label="credential" />}
              </div>
            );
          })}

          {/* Compliance */}
          {complianceProfile && (
            <div style={styles.section}>
              <div style={{ color: C.muted }}>
                Compliance: {complianceProfile.standardPct}% standard, {complianceProfile.proprietaryPct}% proprietary
                {complianceProfile.proprietaryInsCodes.length > 0 && <span style={{ color: C.dim }}> (INS: {complianceProfile.proprietaryInsCodes.join(", ")})</span>}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default FindingsPanel;

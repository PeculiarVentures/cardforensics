/** AI analysis panel with executive summary, session breakdowns, and score/compliance overview. */
import { useState } from "react";
import { C, SESSION_COLORS, BG } from "../theme.js";

const styles = {
  panel: { background: BG.aiPanel, borderBottom: `1px solid ${C.border}`, fontSize: 12 },
  header: { padding: "8px 12px", display: "flex", alignItems: "center", gap: 8, cursor: "pointer", userSelect: "none" },
  badge: (color) => ({ fontSize: 9, color, background: color + "18", border: `1px solid ${color}44`, borderRadius: 3, padding: "1px 6px", fontFamily: "monospace" }),
  statRow: { padding: "6px 12px", display: "flex", gap: 16, fontSize: 10, color: C.muted, borderBottom: `1px solid ${C.border}`, flexWrap: "wrap", alignItems: "center" },
  finding: { padding: "8px 12px", color: C.text, fontSize: 11, lineHeight: 1.7, borderBottom: `1px solid ${C.border}` },
  sessionBlock: (color) => ({
    borderLeft: `3px solid ${color}`, background: BG.aiSection, marginBottom: 1,
  }),
  sessionHeader: (color) => ({
    padding: "6px 10px", display: "flex", alignItems: "center", gap: 10,
    cursor: "pointer", userSelect: "none",
  }),
  sessionBody: { padding: "4px 10px 8px", color: C.text, fontSize: 11, lineHeight: 1.6 },
};

function AISessionSummary({ aiSessions, aiSessionsLoading, aiSessionsError, aiSessionsWarning, aiTraceMeta, onRetry, batchProgress, securityScore, complianceProfile, onSelectSession }) {
  const [collapsed, setCollapsed] = useState(false);
  const [collapsedSessions, setCollapsedSessions] = useState({});
  const hasContent = aiSessions?.length > 0 || aiSessionsLoading || batchProgress;

  if (!hasContent && !aiSessionsError) return null;

  const toggleSession = (i) => setCollapsedSessions(prev => ({ ...prev, [i]: !prev[i] }));

  return (
    <div style={styles.panel}>
      <div style={styles.header} onClick={() => setCollapsed(c => !c)}>
        <span style={{ color: C.teal, fontWeight: 700 }}>AI Analysis</span>
        {aiSessionsLoading && <span style={styles.badge(C.purple)}>analyzing...</span>}
        {batchProgress && !aiSessions?.length && <span style={styles.badge(C.purple)}>annotating {batchProgress.done}/{batchProgress.total}</span>}
        {aiSessionsError && <span style={styles.badge(C.red)}>error</span>}
        {aiSessionsWarning && <span style={styles.badge(C.amber)}>slow</span>}
        <span style={{ flex: 1 }} />
        {securityScore && <span style={{ color: securityScore.color, fontWeight: 700, fontSize: 11, fontFamily: "monospace" }}>{securityScore.score}</span>}
        {securityScore && <span style={{ color: C.muted, fontSize: 9 }}>{securityScore.label}</span>}
        <span style={{ color: C.dim }}>{collapsed ? "\u25B6" : "\u25BC"}</span>
      </div>

      {!collapsed && (
        <div>
          {aiSessionsError && (
            <div style={{ padding: "6px 12px", color: C.red, fontSize: 11 }}>
              {aiSessionsError}
              {onRetry && <button onClick={onRetry} style={{ marginLeft: 8, fontSize: 10, color: C.teal, background: "transparent", border: `1px solid ${C.teal}44`, borderRadius: 3, padding: "1px 6px", cursor: "pointer" }}>retry</button>}
            </div>
          )}

          {/* Score + compliance overview */}
          {/* Executive finding */}
          {aiTraceMeta?.finding && (
            <div style={styles.finding}>{aiTraceMeta.finding}</div>
          )}

          {/* Per-session breakdowns — styled like exchange list session blocks */}
          {aiSessions?.map((s, i) => {
            const color = SESSION_COLORS[i % SESSION_COLORS.length];
            const isCollapsed = collapsedSessions[i];
            return (
              <div key={i} style={styles.sessionBlock(color)}>
                <div style={styles.sessionHeader(color)} onClick={() => toggleSession(i)}>
                  <div style={{ width: 3, height: 16, background: color, borderRadius: 2, flexShrink: 0 }} />
                  <span style={{ color, fontWeight: 700, fontSize: 11, fontFamily: "monospace" }}>Session {i + 1}</span>
                  <span style={{ color: C.text, fontSize: 11, flex: 1 }}>{s.label || "Analysis"}</span>
                  {onSelectSession && <span onClick={(e) => { e.stopPropagation(); onSelectSession(i); }} style={{ color: C.dim, fontSize: 9, cursor: "pointer" }}>go to</span>}
                  <span style={{ color: C.dim, fontSize: 11 }}>{isCollapsed ? "\u25B6" : "\u25BC"}</span>
                </div>
                {!isCollapsed && (
                  <div style={styles.sessionBody}>{s.summary}</div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default AISessionSummary;

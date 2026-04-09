#!/usr/bin/env node
/**
 * CardForensics dashboard renderer.
 *
 * Takes analyzer JSON (stdin or file) and writes a self-contained
 * React artifact (.jsx) to stdout or a file.
 *
 * Usage:
 *   npx vite-node skill/scripts/analyze.js trace.log | npx vite-node skill/scripts/render.js
 *   npx vite-node skill/scripts/render.js --input analysis.json --output /mnt/user-data/outputs/dashboard.jsx
 */
import { readFileSync, writeFileSync } from "fs";

const args = process.argv.slice(2);
const inputIdx = args.indexOf("--input");
const outputIdx = args.indexOf("--output");

let json;
if (inputIdx >= 0 && args[inputIdx + 1]) {
  json = readFileSync(args[inputIdx + 1], "utf-8");
} else {
  json = readFileSync("/dev/stdin", "utf-8");
}

const data = JSON.parse(json);

const jsx = `import { useState } from "react";

const DATA = ${JSON.stringify(data, null, 2)};

const C = {
  bg: "#0b0e14", surface: "#141820", border: "#1e2636",
  text: "#c8d0e0", dim: "#5a6580", muted: "#8899bb",
  teal: "#4ad8c7", green: "#34d399", amber: "#fbbf24",
  red: "#f87171", blue: "#4a9eff", purple: "#a78bfa",
};

const Badge = ({ color, children }) => (
  <span style={{ fontSize: 10, fontWeight: 600, color, border: \`1px solid \${color}44\`, borderRadius: 4, padding: "2px 8px", letterSpacing: 0.5 }}>{children}</span>
);

const Field = ({ label, value, mono, color }) => (
  <div style={{ display: "flex", gap: 8, lineHeight: 1.8 }}>
    <span style={{ color: C.dim, minWidth: 100, flexShrink: 0, fontSize: 11 }}>{label}</span>
    <span style={{ color: color || C.text, fontFamily: mono ? "monospace" : "inherit", fontSize: mono ? 11 : 12, wordBreak: "break-all" }}>{value ?? "—"}</span>
  </div>
);

const Section = ({ title, badge, children, defaultOpen = true }) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ borderBottom: \`1px solid \${C.border}\` }}>
      <div onClick={() => setOpen(!open)} style={{ padding: "10px 16px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ color: C.dim, fontSize: 10, width: 14 }}>{open ? "▼" : "▶"}</span>
        <span style={{ fontWeight: 600, color: C.text, fontSize: 13, flex: 1 }}>{title}</span>
        {badge}
      </div>
      {open && <div style={{ padding: "0 16px 14px 40px" }}>{children}</div>}
    </div>
  );
};

const CertSlot = ({ tag, populated }) => {
  const names = { "5FC105": "Auth (9A)", "5FC10A": "Sig (9C)", "5FC10B": "KeyMgmt (9D)", "5FC101": "CardAuth (9E)" };
  return (
    <div style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 4, border: \`1px solid \${populated ? C.green : C.red}33\`, background: \`\${populated ? C.green : C.red}0a\`, marginRight: 6, marginBottom: 6 }}>
      <span style={{ fontSize: 12, color: populated ? C.green : C.red }}>{populated ? "●" : "○"}</span>
      <span style={{ fontSize: 11, color: C.text }}>{names[tag] || tag}</span>
    </div>
  );
};

const Severity = ({ level }) => {
  const colors = { critical: C.red, high: "#ff6b6b", medium: C.amber, low: C.blue };
  return <Badge color={colors[level] || C.dim}>{level.toUpperCase()}</Badge>;
};

export default function CardForensicsDashboard() {
  const d = DATA;
  const card = d.card_identification;
  const token = d.token_identity;
  const chuid = token?.chuid;
  const score = d.security_score;
  const certs = d.cert_provisioning;
  const threats = d.threats || [];
  const sessions = d.sessions || [];
  const annotations = d.all_annotations || d.notable_annotations || [];
  const keyCheck = d.key_check;

  const scoreColor = score?.score >= 90 ? C.green : score?.score >= 70 ? C.amber : C.red;

  return (
    <div style={{ fontFamily: "'IBM Plex Sans', 'SF Pro Text', system-ui, sans-serif", background: C.bg, color: C.text, minHeight: "100vh", maxWidth: 720 }}>
      {/* Header */}
      <div style={{ padding: "20px 16px 14px", borderBottom: \`1px solid \${C.border}\`, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 36, height: 36, borderRadius: 8, background: \`linear-gradient(135deg, \${C.teal}33, \${C.purple}33)\`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>🔍</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 15, color: "#fff", letterSpacing: 0.5 }}>CardForensics</div>
          <div style={{ fontSize: 11, color: C.dim }}>{d.exchange_count} exchanges · {d.session_count} sessions</div>
        </div>
        {score && <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 24, fontWeight: 700, color: scoreColor, lineHeight: 1 }}>{score.score}</div>
          <div style={{ fontSize: 9, color: C.dim, letterSpacing: 1 }}>{score.label?.toUpperCase()}</div>
        </div>}
      </div>

      {/* Card Identity */}
      <Section title="Card Identity" badge={card && <Badge color={C.teal}>{card.confidence}%</Badge>}>
        {card ? <>
          <Field label="Card" value={card.name} />
          <Field label="Vendor" value={card.vendor} />
          {token?.serial && <Field label="Serial" value={token.serial} mono />}
          {token?.version && <Field label="Firmware" value={token.version} mono />}
          {card.signals?.length > 0 && <div style={{ marginTop: 6 }}>
            {card.signals.map((s, i) => <div key={i} style={{ fontSize: 10, color: C.muted, lineHeight: 1.6 }}>· {s}</div>)}
          </div>}
        </> : <div style={{ color: C.dim, fontSize: 12 }}>Card not identified</div>}
      </Section>

      {/* CHUID */}
      {chuid && <Section title="CHUID — Credential Identity">
        <Field label="GUID" value={chuid.guid} mono />
        {chuid.fascn && <Field label="FASC-N" value={chuid.fascn} mono />}
        <Field label="Expiration" value={chuid.expiration} />
        <Field label="Signed" value={chuid.hasSignature ? \`Yes (\${chuid.signatureLength}B)\` : "No"} color={chuid.hasSignature ? C.green : C.amber} />
        {chuid.cardholderUUID && <Field label="Cardholder UUID" value={chuid.cardholderUUID} mono />}
      </Section>}

      {/* Certificate Slots */}
      {certs && <Section title="Certificate Provisioning" badge={<Badge color={certs.required_populated ? C.green : C.red}>{certs.populated?.length || 0}/{certs.probed?.length || 0}</Badge>}>
        <div style={{ display: "flex", flexWrap: "wrap", marginBottom: 6 }}>
          {(certs.probed || []).map(tag => <CertSlot key={tag} tag={tag} populated={(certs.populated || []).includes(tag)} />)}
        </div>
        {certs.all_empty && <div style={{ fontSize: 11, color: C.amber }}>All certificate slots are empty — card is unprovisioned</div>}
      </Section>}

      {/* Threats */}
      <Section title="Threats" badge={<Badge color={threats.length > 0 ? C.red : C.green}>{threats.length}</Badge>} defaultOpen={threats.length > 0}>
        {threats.length === 0
          ? <div style={{ fontSize: 12, color: C.green }}>No threats detected</div>
          : threats.map((t, i) => (
            <div key={i} style={{ marginBottom: 10, padding: "8px 10px", borderRadius: 4, border: \`1px solid \${C.border}\`, background: C.surface }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                <Severity level={t.severity} />
                <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{t.title}</span>
              </div>
              <div style={{ fontSize: 11, color: C.muted, lineHeight: 1.5 }}>{t.detail}</div>
            </div>
          ))}
      </Section>

      {/* Key Check */}
      <Section title="Management Key Check" badge={<Badge color={keyCheck?.matches?.length > 0 ? C.red : C.green}>{keyCheck?.matches?.length > 0 ? "DEFAULT KEY" : "OK"}</Badge>} defaultOpen={keyCheck?.matches?.length > 0}>
        <Field label="Keys tested" value={keyCheck?.keys_tested} />
        <Field label="Pairs found" value={keyCheck?.pairs_tested} />
        {keyCheck?.matches?.length > 0
          ? keyCheck.matches.map((m, i) => <div key={i} style={{ color: C.red, fontSize: 12, fontWeight: 600 }}>MATCH: {m.name} (exchange {m.exchange})</div>)
          : <div style={{ fontSize: 11, color: C.green }}>No default keys detected</div>}
      </Section>

      {/* Compliance */}
      {d.compliance && <Section title="Compliance" defaultOpen={false}>
        <div style={{ display: "flex", gap: 4, height: 8, borderRadius: 4, overflow: "hidden", marginBottom: 8 }}>
          <div style={{ width: \`\${d.compliance.standard_pct}%\`, background: C.teal }} />
          <div style={{ width: \`\${d.compliance.proprietary_pct}%\`, background: C.purple }} />
        </div>
        <Field label="Standard" value={\`\${d.compliance.standard_pct}%\`} />
        <Field label="Proprietary" value={\`\${d.compliance.proprietary_pct}% (\${(d.compliance.proprietary_ins || []).join(", ")})\`} />
      </Section>}

      {/* Sessions */}
      <Section title="Sessions" defaultOpen={false}>
        {sessions.map((s, i) => (
          <div key={i} style={{ marginBottom: 8, padding: "6px 10px", borderRadius: 4, border: \`1px solid \${C.border}\`, background: C.surface }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: C.text }}>Session {s.index}</span>
              <span style={{ fontSize: 10, color: C.dim }}>{s.exchange_count} exchanges</span>
            </div>
            {s.operations?.slice(0, 8).map((op, j) => (
              <div key={j} style={{ fontSize: 10, color: C.muted, fontFamily: "monospace", lineHeight: 1.5 }}>{op.label}</div>
            ))}
            {(s.operations?.length || 0) > 8 && <div style={{ fontSize: 10, color: C.dim }}>... +{s.operations.length - 8} more</div>}
          </div>
        ))}
      </Section>

      {/* Annotations */}
      {annotations.length > 0 && <Section title={\`Annotations (\${annotations.length})\`} defaultOpen={false}>
        {annotations.map((a, i) => (
          <div key={i} style={{ display: "flex", gap: 8, lineHeight: 1.6, fontSize: 11 }}>
            <span style={{ color: C.dim, fontFamily: "monospace", minWidth: 24, textAlign: "right" }}>{a.exchange}</span>
            {a.flag && <span style={{ color: a.flag === "bug" ? C.red : a.flag === "warn" ? C.amber : a.flag === "key" ? C.purple : C.dim, fontSize: 9, fontWeight: 700, minWidth: 36 }}>{a.flag}</span>}
            <span style={{ color: a.flag === "bug" ? C.red : C.muted, flex: 1 }}>{a.note}</span>
          </div>
        ))}
      </Section>}

      {/* Integrity */}
      <div style={{ padding: "10px 16px", fontSize: 10, color: C.dim, display: "flex", gap: 16 }}>
        <span>Integrity: {d.integrity?.kind}</span>
        {d.atr && <span>ATR: {d.atr.parse?.summary || d.atr.hex?.substring(0, 20) + "..."}</span>}
      </div>
    </div>
  );
}`;

if (outputIdx >= 0 && args[outputIdx + 1]) {
  writeFileSync(args[outputIdx + 1], jsx);
  console.error(`Dashboard written to ${args[outputIdx + 1]}`);
} else {
  console.log(jsx);
}

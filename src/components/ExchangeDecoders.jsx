/** Inline decoders for structured APDU responses: CPLC, GP key sets, CCC, CHUID, YubiKey version, credentials. */
import { C } from "../theme.js";
import { decodeExchange } from "../analysis/decoders.js";

const styles = {
  container: { padding: "6px 10px", background: "#0e1218", borderTop: `1px solid ${C.border}`, fontSize: 11 },
  label: { color: C.teal, fontWeight: 600, marginBottom: 4, display: "block" },
  row: { display: "flex", gap: 8, color: C.muted, lineHeight: 1.6 },
  key: { color: C.dim, minWidth: 140, flexShrink: 0 },
  value: { color: C.text, fontFamily: "monospace" },
  redacted: { color: C.red, fontFamily: "monospace" },
};

function ExchangeDecoders({ ex }) {
  const result = decodeExchange(ex);
  if (!result) return null;

  return (
    <div style={styles.container}>
      <span style={styles.label}>{result.title}</span>
      {result.fields.map((f, i) => (
        <div key={i} style={styles.row}>
          <span style={styles.key}>{f.label}</span>
          <span style={f.warn ? styles.redacted : styles.value}>{f.value}</span>
        </div>
      ))}
    </div>
  );
}

export default ExchangeDecoders;

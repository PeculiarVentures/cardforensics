/** Clipboard copy button with visual feedback. */
import { useState } from "react";
import { C } from "../theme.js";

function CopyBtn({ value, label }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard?.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); };
  return (
    <button onClick={copy} title={`Copy ${label ?? "value"}`}
      style={{
        background: copied ? C.green + "22" : "transparent",
        border: `1px solid ${copied ? C.green : C.border}`,
        borderRadius: 3, padding: "1px 6px", cursor: "pointer",
        fontSize: 9, fontFamily: "monospace",
        color: copied ? C.green : C.muted,
        transition: "all 0.2s",
      }}>
      {copied ? "✓ copied" : `⎘ ${label ?? "copy"}`}
    </button>
  );
}

export default CopyBtn;

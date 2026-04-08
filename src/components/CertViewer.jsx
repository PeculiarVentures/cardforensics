/**
 * X.509 certificate viewer using @peculiar/certificates-viewer.
 * Lazy-loads and mounts the PV component only on expand click,
 * using raw DOM to keep it outside React's reconciler.
 */
import { useState, useRef, useEffect, useMemo } from "react";
import { decodeCmd, decodeRsp, hexStr } from "../decode.js";
import { unwrapPIVCert, analyzeCertificate } from "../analysis/index.js";
import { C } from "../theme.js";

const PIV_CERT_TAGS = new Set(["5FC105", "5FC10A", "5FC10B", "5FC101"]);
const SLOT_NAMES = {
  "5FC105": "PIV Authentication (9A)",
  "5FC10A": "Digital Signature (9C)",
  "5FC10B": "Key Management (9D)",
  "5FC101": "Card Authentication (9E)",
};

const PV_VARS = [
  ["--pv-color-black","#c8d3e8"],["--pv-color-white","#0e1218"],["--pv-color-base","#0e1218"],
  ["--pv-color-gray-1","#0e1218"],["--pv-color-gray-2","#111620"],["--pv-color-gray-3","#151b28"],
  ["--pv-color-gray-4","#1e2940"],["--pv-color-gray-5","#2a3654"],["--pv-color-gray-6","#3a4560"],
  ["--pv-color-gray-7","#1e2940"],["--pv-color-gray-8","#4a5568"],["--pv-color-gray-9","#8899bb"],
  ["--pv-color-gray-10","#c8d3e8"],["--pv-color-primary","#5eead4"],
  ["--pv-color-primary-contrast","#0e1218"],
  ["--pv-color-secondary","#a78bfa"],["--pv-color-success","#34d399"],
  ["--pv-color-wrong","#f87171"],["--pv-color-attention","#fbbf24"],
  ["--pv-font-family","'SF Mono',Menlo,Monaco,monospace"],
  ["--pv-size-base","3px"],
  ["--pv-text-b1-size","11px"],["--pv-text-b2-size","10px"],["--pv-text-b3-size","9px"],
  ["--pv-text-h4-size","12px"],["--pv-text-h5-size","11px"],
  ["--pv-text-s1-size","10px"],["--pv-text-s2-size","9px"],
  ["--pv-shadow-dark-hight","none"],["--pv-shadow-dark-medium","none"],
  ["--pv-shadow-light-hight","none"],["--pv-shadow-light-low","none"],
  ["--pv-shadow-light-medium","none"],
];

// Static import ensures PV component code is bundled (dynamic import gets
// tree-shaken in singlefile builds, losing the entire Stencil runtime).
// Registration is deferred to first expand click.
import { defineCustomElement as pvDefine } from "@peculiar/certificates-viewer/components/peculiar-certificate-viewer.js";

let pvRegistered = false;
function ensurePV() {
  if (!pvRegistered) {
    try { pvDefine(); pvRegistered = true; } catch (e) { console.warn("PV registration failed:", e); }
  }
  return pvRegistered;
}

function CertViewer({ ex }) {
  const [expanded, setExpanded] = useState(true);
  const slotRef = useRef(null);

  // Determine cert eligibility before any hooks that depend on it,
  // so hook count is stable regardless of exchange type (fixes #310).
  const cmd = decodeCmd(ex.cmd.bytes);
  const rsp = ex.rsp ? decodeRsp(ex.rsp.bytes) : null;
  const isCertRsp = cmd && rsp && rsp.sw === 0x9000 && rsp.data?.length >= 50
    && (cmd.ins === 0xCB || cmd.ins === 0xCA) && cmd.data?.[0] === 0x5C;
  const d = isCertRsp ? cmd.data : null;
  const tagHex = d ? hexStr(d.slice(2, 2 + (d[1] ?? 0))).replace(/ /g, "").toUpperCase() : "";
  const isCertTag = PIV_CERT_TAGS.has(tagHex);

  const parsed = useMemo(() => {
    if (!isCertRsp || !isCertTag) return null;
    try {
      const der = unwrapPIVCert(Array.from(rsp.data));
      if (!der) return { error: "Could not unwrap certificate" };
      const info = analyzeCertificate(der);
      info.b64 = btoa(String.fromCharCode(...der));
      return info;
    } catch (e) { return { error: String(e.message ?? e).substring(0, 200) }; }
  }, [ex.id, isCertRsp, isCertTag]);

  // Register PV custom element and mount viewer when expanded
  useEffect(() => {
    if (!expanded || !slotRef.current || !parsed?.b64) return;
    const slot = slotRef.current;
    if (!ensurePV()) return;
    slot.innerHTML = "";
    const viewer = document.createElement("peculiar-certificate-viewer");
    PV_VARS.forEach(([k, v]) => viewer.style.setProperty(k, v));
    viewer.certificate = parsed.b64;
    slot.appendChild(viewer);
    return () => { slot.innerHTML = ""; };
  }, [expanded, parsed?.b64]);

  // Early returns AFTER all hooks
  if (!parsed) return null;

  if (parsed.error) {
    return (
      <div style={{ padding: "6px 10px", background: "#1a0800", borderTop: `1px solid ${C.border}`, fontSize: 11, color: C.red }}>
        {String(SLOT_NAMES[tagHex] ?? tagHex)}: {String(parsed.error)}
      </div>
    );
  }
  if (!parsed.b64) return null;

  const summary = [parsed.subject, parsed.keyAlg + (parsed.keySize ? ` ${parsed.keySize}` : ""), parsed.selfSigned ? "self-signed" : parsed.issuer].filter(Boolean).join(" | ");

  return (
    <div style={{ borderTop: `1px solid ${C.border}` }}>
      <div onClick={() => setExpanded(e => !e)} style={{ padding: "4px 10px", background: "#0e1218", fontSize: 11, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer" }}>
        <span style={{ color: C.teal, fontWeight: 600 }}>{"X.509 Certificate \u2014 " + String(SLOT_NAMES[tagHex] ?? tagHex)}</span>
        <span style={{ color: "#8899bb", fontSize: 11, userSelect: "none" }}>{expanded ? "\u25BC" : "\u25B6"}</span>
      </div>
      <div style={{ padding: "2px 10px 4px", background: "#0b0f16", fontSize: 10, color: "#8899bb" }}>{String(summary)}</div>
      {expanded && <div ref={slotRef} style={{ overflow: "auto", maxHeight: 500, background: "#0b0f16" }} />}
    </div>
  );
}

export default CertViewer;

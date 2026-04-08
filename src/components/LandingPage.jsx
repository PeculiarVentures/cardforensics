/**
 * Landing page with Matrix-style APDU rain and centered card.
 * Rain uses a canvas for performance, card is React JSX.
 */
import { useEffect, useRef } from "react";
import ApiConfig from "./ApiConfig.jsx";

// APDU hex fragments for the rain
const APDU_HEX = [
  "00A4040007A000000308000010","00A4040008A0000001510000","00CA006E00","00CA004F00",
  "00CB3FFF055C035FC102","0020008008","8050000008","8482330010","00C000001A",
  "00870011047C028100","0047000005AC003060B","80E400800084","80CA9F7F",
  "6F1A840E325041592E5359532E4444463031","9000","6A82","6982","63C2","6D00","6A80",
  "3BF813000081318E","7F490806072A8648CE3D","80F2100002","84E20000",
];
const LABELS = [
  "SELECT","VERIFY","AUTH","SCP03","PIV","GP","9000","6A82","TLV","AID","MAC",
  "APDU","ATR","X.509","RSA","ECDSA","P-256","AES","SHA2","INS","CLA",
];
const BYTES = [];
for (const f of APDU_HEX) for (let i = 0; i < f.length - 1; i += 2) BYTES.push(f.substring(i, i + 2).toUpperCase());
const rb = () => BYTES[Math.floor(Math.random() * BYTES.length)];
const rl = () => LABELS[Math.floor(Math.random() * LABELS.length)];

const EXAMPLES = [
  { file: "yubico_piv.log", label: "YubiKey PIV", desc: "5 sessions · provisioning + verification" },
  { file: "safenet_etoken.log", label: "SafeNet eToken 5110", desc: "PIV enumeration · vendor commands" },
  { file: "safenet_fusion.log", label: "SafeNet Fusion NFC", desc: "Card init · GP key sets" },
];

export default function LandingPage({ onLoadTrace, onBrowse }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let raf;

    const resize = () => { canvas.width = canvas.parentElement.clientWidth; canvas.height = canvas.parentElement.clientHeight; };
    resize();
    window.addEventListener("resize", resize);

    const fontSize = 13;
    const cols = Math.floor(canvas.width / 18);
    const drops = Array.from({ length: cols }, () => -Math.floor(Math.random() * 40));
    const speeds = Array.from({ length: cols }, () => 0.3 + Math.random() * 0.7);
    const acc = Array.from({ length: cols }, () => 0);

    function draw() {
      ctx.fillStyle = "rgba(0, 0, 0, 0.06)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${fontSize}px 'SF Mono', Menlo, Monaco, monospace`;

      for (let i = 0; i < cols; i++) {
        acc[i] += speeds[i];
        if (acc[i] < 1) continue;
        acc[i] -= 1;

        const text = Math.random() < 0.06 ? rl() : rb();
        const x = i * 18;
        const y = drops[i] * fontSize;

        // Head glow
        ctx.fillStyle = "#fff";
        ctx.shadowColor = "#0f0";
        ctx.shadowBlur = 12;
        ctx.fillText(text, x, y);
        ctx.shadowBlur = 0;

        // Trail
        ctx.fillStyle = `rgba(0, ${160 + Math.floor(Math.random() * 95)}, 0, 0.8)`;
        ctx.fillText(Math.random() < 0.06 ? rl() : rb(), x, y - fontSize);

        drops[i]++;
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = -Math.floor(Math.random() * 10);
          speeds[i] = 0.3 + Math.random() * 0.7;
        }
      }
      raf = requestAnimationFrame(draw);
    }
    raf = requestAnimationFrame(draw);

    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, []);

  const loadExample = (file) => {
    fetch(`./traces/${file}`).then(r => {
      if (!r.ok) throw new Error(r.status);
      return r.text();
    }).then(text => {
      if (text.includes("APDU")) onLoadTrace({ name: file, log: text });
      else throw new Error("No APDU data");
    }).catch(() => {
      alert("Example traces are available on the hosted version:\nhttps://peculiarventures.github.io/cardforensics");
    });
  };

  return (
    <div style={{ flex: 1, position: "relative", overflow: "hidden", background: "#000" }}>
      <canvas ref={canvasRef} style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }} />

      {/* Center card */}
      <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 2,
        background: "radial-gradient(ellipse 50% 55% at center, rgba(0,0,0,0.5), rgba(0,0,0,0.85))" }}>
        <div style={{ textAlign: "center", maxWidth: 460, padding: "28px 32px", background: "rgba(0,0,0,0.75)",
          borderRadius: 10, border: "1px solid rgba(0,255,65,0.12)", backdropFilter: "blur(16px)", WebkitBackdropFilter: "blur(16px)" }}>

          <div style={{ fontSize: 40, marginBottom: 10 }}>💳</div>
          <div style={{ fontSize: 20, color: "#e0ffe8", fontWeight: 700, fontFamily: "monospace", letterSpacing: 1, marginBottom: 4 }}>CardForensics</div>
          <div style={{ fontSize: 11, color: "#4ade80", marginBottom: 20, letterSpacing: 0.7, lineHeight: 1.7 }}>
            APDU Trace Analyzer · ISO 7816 · GlobalPlatform · PIV · SCP03
          </div>

          {/* Browse + drag */}
          <button onClick={onBrowse} style={{
            display: "inline-flex", alignItems: "center", gap: 8, padding: "10px 22px", borderRadius: 6,
            cursor: "pointer", background: "#16a34a", border: "none", color: "#fff", fontSize: 13,
            fontWeight: 600, fontFamily: "monospace", marginBottom: 8,
          }}>Browse for log file</button>
          <div style={{ fontSize: 11, color: "#3a7a48", marginBottom: 16 }}>or drag a file anywhere on this window</div>

          {/* Example traces */}
          <div style={{ fontSize: 10, color: "#4ade80", marginBottom: 8, letterSpacing: 0.5 }}>EXAMPLE TRACES</div>
          <div style={{ display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap", marginBottom: 16 }}>
            {EXAMPLES.map(ex => (
              <button key={ex.file} onClick={() => loadExample(ex.file)} style={{
                padding: "7px 14px", borderRadius: 5, cursor: "pointer", textAlign: "left",
                background: "rgba(0,20,5,0.7)", border: "1px solid rgba(0,255,65,0.15)",
                color: "#6ee77a", fontSize: 11, fontFamily: "monospace", minWidth: 130,
              }}>
                <div style={{ fontWeight: 700, marginBottom: 2 }}>{ex.label}</div>
                <div style={{ fontSize: 9, color: "#3a7a48", fontWeight: 400 }}>{ex.desc}</div>
              </button>
            ))}
          </div>

          {/* Capture instructions */}
          <div style={{ background: "rgba(0,20,5,0.7)", border: "1px solid rgba(0,255,65,0.12)", borderRadius: 6,
            padding: "10px 14px", textAlign: "left", fontSize: 11 }}>
            <div style={{ color: "#bbf7d0", fontFamily: "monospace", fontSize: 11, fontWeight: 700, marginBottom: 6 }}>Capture APDU traces on macOS:</div>
            {[
              { label: "1. Enable APDU logging", cmd: "sudo defaults write /Library/Preferences/com.apple.security.smartcard Logging -bool true" },
              { label: "2. Export recent traces", cmd: "log show --predicate 'eventMessage CONTAINS[c] \"APDU\"' --last 5m > trace.txt" },
              { label: "3. Disable when done", cmd: "sudo defaults delete /Library/Preferences/com.apple.security.smartcard Logging" },
            ].map((step, i) => (
              <div key={i} style={{ marginBottom: i < 2 ? 6 : 0 }}>
                <div style={{ fontSize: 9, color: "#3a7a48", marginBottom: 2, fontFamily: "monospace" }}>{step.label}</div>
                <div style={{ display: "flex", borderRadius: 4, border: "1px solid rgba(0,255,65,0.1)", overflow: "hidden" }}>
                  <pre style={{ flex: 1, margin: 0, padding: "5px 8px", fontSize: 10, color: "#4ade80", fontFamily: "'SF Mono',Menlo,Monaco,monospace",
                    background: "rgba(0,0,0,0.4)", whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.5 }}>{step.cmd}</pre>
                  <button onClick={(e) => { navigator.clipboard?.writeText(step.cmd); const b = e.currentTarget; b.textContent = "✓"; setTimeout(() => b.textContent = "⎘", 1500); }}
                    style={{ padding: "0 10px", background: "rgba(0,20,5,0.8)", border: "none", borderLeft: "1px solid rgba(0,255,65,0.1)",
                      color: "#3a7a48", cursor: "pointer", fontSize: 13, flexShrink: 0 }}
                    title="Copy to clipboard">⎘</button>
                </div>
              </div>
            ))}
          </div>

          <div style={{ marginTop: 12 }}>
            <ApiConfig />
          </div>
        </div>
      </div>
    </div>
  );
}

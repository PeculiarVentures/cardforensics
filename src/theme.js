/**
 * Theme constants for CardForensics UI.
 *
 * All colors, shared style objects, and semantic tokens live here.
 * Components import from this file instead of using hard-coded hex values.
 */

/** Core color palette. Referenced as C.bg, C.teal, etc. */
export const C = {
  // Backgrounds
  bg:       "#0b0e13",
  surface:  "#111620",
  panel:    "#0d1117",
  overlay:  "#080b11",

  // Borders
  border:   "#1e2535",
  borderHi: "#2a3550",

  // Text
  text:     "#c8d3e8",
  muted:    "#4a5568",
  dim:      "#2d3748",

  // Accents
  blue:     "#4a9eff",
  green:    "#2dd4a0",
  red:      "#ff5f6a",
  amber:    "#ffb347",
  purple:   "#a78bfa",
  teal:     "#38bdf8",
};

/**
 * Semantic backgrounds for annotation/threat severity rows.
 * Use instead of hard-coded hex in component JSX.
 */
export const BG = {
  error:       "#1a0800",
  key:         "#0f1a0f",
  warn:        "#1a1500",
  neutral:     "#111820",
  selected:    "#1a2440",
  errorRow:    "#1a1015",
  aiPanel:     "#0a0f1a",
  aiSection:   "#08101a",
  session:     "#0c0f18",
  sessionOk:   "#0c160c",
  sessionWarn: "#141008",
  findings:    "#090c14",
};

/** Map status word severity string to accent color. */
export const swColor = (severity) =>
  severity === "ok"   ? C.green :
  severity === "err"  ? C.red   :
  severity === "warn" ? C.amber : C.teal;

/** Ordered session badge colors (session 0, 1, 2, ...). */
export const SESSION_COLORS = [C.teal, C.amber, C.green];

/** Shared monospace button style. */
export const BTN = {
  padding: "3px 8px",
  background: "transparent",
  border: `1px solid ${C.border}`,
  borderRadius: 4,
  color: C.text,
  cursor: "pointer",
  fontSize: 11,
  fontFamily: "monospace",
};

/** HOST / CARD actor boxes in the sequence replay diagram. */
export const ACTOR = {
  width: 72, height: 68,
  display: "flex", flexDirection: "column",
  alignItems: "center", justifyContent: "center",
  background: C.surface,
  border: "1px solid",
  borderRadius: 5,
  flexShrink: 0,
  textAlign: "center",
  gap: 2,
};

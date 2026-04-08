/** Exchange list filter controls. */
import { C, BTN } from "../theme.js";

function FilterBar({ filters, onFilters }) {
  return (
    <div style={{ position: "sticky", top: 0, zIndex: 20, background: C.bg, borderBottom: `1px solid ${C.border}`, padding: "3px 10px", display: "flex", gap: 5, alignItems: "center", flexShrink: 0 }}>
      <button onClick={() => onFilters(f => ({ ...f, errorsOnly: !f.errorsOnly }))}
        style={{ ...BTN, fontSize: 9, padding: "2px 7px", background: filters.errorsOnly ? C.red + "22" : "transparent", border: `1px solid ${filters.errorsOnly ? C.red : C.border}`, color: filters.errorsOnly ? C.red : C.muted, whiteSpace: "nowrap" }}>
        ⚠ errors only
      </button>
      <button onClick={() => onFilters(f => ({ ...f, hideGetData: !f.hideGetData }))}
        style={{ ...BTN, fontSize: 9, padding: "2px 7px", background: filters.hideGetData ? C.amber + "22" : "transparent", border: `1px solid ${filters.hideGetData ? C.amber : C.border}`, color: filters.hideGetData ? C.amber : C.muted, whiteSpace: "nowrap" }}>
        hide GET DATA
      </button>
      <input value={filters.search} onChange={e => onFilters(f => ({ ...f, search: e.target.value }))}
        placeholder="filter by tag, INS, annotation…"
        style={{ flex: 1, background: C.panel, border: `1px solid ${C.border}`, borderRadius: 4, color: C.text, padding: "2px 7px", fontSize: 10, fontFamily: "monospace", outline: "none" }} />
      {(filters.errorsOnly || filters.hideGetData || filters.search) &&
        <button onClick={() => onFilters(() => ({ errorsOnly: false, hideGetData: false, search: "" }))} style={{ ...BTN, fontSize: 10, color: C.muted }}>✕ clear</button>
      }
    </div>
  );
}

export default FilterBar;

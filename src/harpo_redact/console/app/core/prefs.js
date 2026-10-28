// The only module that touches localStorage: versioned, whitelisted, non-sensitive UI preferences.
// Never prompts, findings, keys, documents or anything a request contained (see docs/DESIGN.md).
const STORE = "harpo.ui.v1";
const ALLOWED = new Set(["theme", "compact", "density", "panes", "views", "favorites", "columns", "tour", "recents", "dismissed"]);
let state = {};
try {
  const v = JSON.parse(localStorage.getItem(STORE) || "{}");
  if (v && typeof v === "object" && !Array.isArray(v)) state = Object.fromEntries(Object.entries(v).filter(([k]) => ALLOWED.has(k)));
} catch { state = {}; }
for (const [old, key, map] of [["pai.theme", "theme", (v) => v], ["pai.compact", "compact", (v) => v === "1"]]) {
  try { const v = localStorage.getItem(old); if (v != null) { if (!(key in state)) state[key] = map(v); localStorage.removeItem(old); } } catch { /* storage unavailable */ }
}
const save = () => { try { localStorage.setItem(STORE, JSON.stringify(state)); } catch { /* private mode: preferences just do not persist */ } };
save();
export const prefs = {
  get(key, fallback) { return key in state ? state[key] : fallback; },
  set(key, value) { if (!ALLOWED.has(key)) throw new Error(`"${key}" is not a UI preference`); state[key] = value; save(); },
  reset(keys = [...ALLOWED]) { for (const k of keys) delete state[k]; save(); },
};

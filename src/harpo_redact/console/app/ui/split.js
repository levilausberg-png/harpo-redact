// Resizable panes for a three-column workspace grid. Desktop only (the grid collapses below 1281 px).
// Widths and focus mode are UI preferences (prefs "panes"); nothing about content is stored.
import { prefs } from "../core/prefs.js";

const DEFAULT = [1.1, 0.78, 1.12];
const MIN = 0.32;

export function splitGrid(grid, key) {
  const saved = (prefs.get("panes", {}) || {})[key] || {};
  let fr = Array.isArray(saved.fr) && saved.fr.length === 3 && saved.fr.every((v) => v >= MIN) ? [...saved.fr] : [...DEFAULT];
  let focus = ["split", "input", "egress"].includes(saved.focus) ? saved.focus : "split";
  const apply = () => { ["a", "b", "c"].forEach((n, i) => grid.style.setProperty(`--pg-${n}`, `${fr[i].toFixed(3)}fr`)); grid.dataset.focus = focus; };
  const save = () => prefs.set("panes", { ...(prefs.get("panes", {}) || {}), [key]: { fr: fr.map((v) => +v.toFixed(3)), focus } });
  const panes = () => [...grid.querySelectorAll(":scope > [data-pane]")];
  for (const old of grid.querySelectorAll(":scope > .gutter")) old.remove();
  const gutters = [0, 1].map((i) => {
    const g = document.createElement("div");
    g.className = "gutter"; g.tabIndex = 0; g.dataset.i = String(i);
    g.setAttribute("role", "separator"); g.setAttribute("aria-orientation", "vertical");
    g.setAttribute("aria-label", i ? "Resize the pipeline and egress panes" : "Resize the input and pipeline panes");
    g.title = "Drag to resize · arrow keys · double-click to reset";
    grid.appendChild(g);
    return g;
  });
  const place = () => {
    const box = grid.getBoundingClientRect(), ps = panes();
    gutters.forEach((g, i) => { const r = ps[i]?.getBoundingClientRect(); if (r) g.style.left = `${r.right - box.left}px`; g.setAttribute("aria-valuenow", String(Math.round((fr[i] / fr.reduce((a, b) => a + b, 0)) * 100))); });
  };
  const moveBoundary = (i, dxPx) => {
    const ws = panes().map((p) => p.getBoundingClientRect().width), pair = ws[i] + ws[i + 1];
    const a = Math.max(pair * 0.18, Math.min(pair * 0.82, ws[i] + dxPx));
    const scale = fr.reduce((s, v) => s + v, 0) / ws.reduce((s, v) => s + v, 0);
    ws[i] = a; ws[i + 1] = pair - a;
    fr = ws.map((w) => Math.max(MIN, w * scale));
    apply(); place();
  };
  for (const g of gutters) {
    const i = +g.dataset.i;
    g.onpointerdown = (e) => {
      e.preventDefault(); g.setPointerCapture(e.pointerId); g.classList.add("drag");
      let last = e.clientX;
      g.onpointermove = (m) => { moveBoundary(i, m.clientX - last); last = m.clientX; };
      g.onpointerup = () => { g.onpointermove = null; g.classList.remove("drag"); save(); };
    };
    g.ondblclick = () => { fr = [...DEFAULT]; apply(); place(); save(); };
    g.onkeydown = (e) => {
      const step = grid.getBoundingClientRect().width * 0.03;
      if (e.key === "ArrowLeft" || e.key === "ArrowRight") { e.preventDefault(); moveBoundary(i, e.key === "ArrowLeft" ? -step : step); save(); }
      if (e.key === "Home") { e.preventDefault(); fr = [...DEFAULT]; apply(); place(); save(); }
    };
  }
  new ResizeObserver(() => requestAnimationFrame(place)).observe(grid);
  apply(); requestAnimationFrame(place);
  return { setFocus(f) { focus = f; apply(); save(); requestAnimationFrame(place); }, get focus() { return focus; } };
}

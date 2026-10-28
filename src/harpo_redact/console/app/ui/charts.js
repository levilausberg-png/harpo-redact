import { $, esc, fmt } from "../core/dom.js";

const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
function ticks(max) {
  const raw = Math.max(1, max) / 4, p = 10 ** Math.floor(Math.log10(raw)), f = raw / p;
  const step = (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
  return { step, top: Math.ceil(Math.max(1, max) / step) * step };
}
function smooth(p) {
  if (p.length < 2) return "";
  const lo = Math.min(...p.map((q) => q[1])), hi = Math.max(...p.map((q) => q[1])), cl = (v) => Math.max(lo, Math.min(hi, v));
  let d = `M${p[0][0].toFixed(1)} ${p[0][1].toFixed(1)}`;
  for (let i = 0; i < p.length - 1; i++) {
    const a = p[i - 1] || p[i], b = p[i], c = p[i + 1], e = p[i + 2] || c;
    d += ` C${(b[0] + (c[0] - a[0]) / 6).toFixed(1)} ${cl(b[1] + (c[1] - a[1]) / 6).toFixed(1)}, ${(c[0] - (e[0] - b[0]) / 6).toFixed(1)} ${cl(c[1] - (e[1] - b[1]) / 6).toFixed(1)}, ${c[0].toFixed(1)} ${c[1].toFixed(1)}`;
  }
  return d;
}
const synced = new Set();  // live charts that mirror the hovered timestamp
function broadcast(t, origin) {
  for (const c of [...synced]) {
    if (!c.el.isConnected) { synced.delete(c); continue; }
    if (c !== origin) c.mirror(t);
  }
}
/** Multi-series telemetry line chart. series: [{label, color: "--ch-1", values}], times: epoch seconds per point.
 * Hovering shows the same moment on every chart on the page; onPick({from, to}) makes a point open its requests. */
export function lineChart(el, { series, times, height = 200, fill = 0, onPick = null }) {
  if (!el) return;
  const W = Math.max(280, el.clientWidth - 24), H = height, P = { l: 30, r: 6, t: 8, b: 20 }, n = times.length;
  const { step, top } = ticks(Math.max(...series.flatMap((s) => s.values)));
  const x = (i) => P.l + (i / Math.max(1, n - 1)) * (W - P.l - P.r), y = (v) => P.t + (1 - v / top) * (H - P.t - P.b);
  const grid = Array.from({ length: Math.round(top / step) + 1 }, (_, k) => k * step).map((v) => `<line class="gl" x1="${P.l}" x2="${W - P.r}" y1="${y(v)}" y2="${y(v)}"/><text class="ax" x="${P.l - 6}" y="${y(v) + 3}" text-anchor="end">${fmt(v)}</text>`).join("");
  const span = n ? times[n - 1] - times[0] : 0, bucket = n > 1 ? (times[n - 1] - times[0]) / (n - 1) : 60;
  const lab = (i) => (i === n - 1 ? "now" : `-${Math.round((span * (1 - i / (n - 1))) / 60)}m`);
  const xl = [0, Math.round((n - 1) / 2), n - 1].map((i) => `<text class="ax" x="${x(i)}" y="${H - 4}" text-anchor="${i === 0 ? "start" : i === n - 1 ? "end" : "middle"}">${lab(i)}</text>`).join("");
  const paths = series.map((s, k) => {
    const pts = s.values.map((v, i) => [x(i), y(v)]), d = smooth(pts), col = cssVar(s.color);
    const area = k === fill ? `<path d="${d} L${x(n - 1)} ${y(0)} L${x(0)} ${y(0)} Z" fill="url(#lg${k})"/>` : "";
    return `<defs><linearGradient id="lg${k}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${col}" stop-opacity=".26"/><stop offset="1" stop-color="${col}" stop-opacity="0"/></linearGradient></defs>${area}<path class="ln" d="${d}" stroke="${col}" fill="none"/>`;
  }).join("");
  const label = `${series.map((s) => s.label).join(", ")} over time${onPick ? ". Arrow keys move, Enter opens the requests at that moment" : ""}`;
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" tabindex="0" class="${onPick ? "pick" : ""}" aria-label="${esc(label)}">${grid}${xl}${paths}<line class="cur" y1="${P.t}" y2="${H - P.b}" x1="-9" x2="-9"/></svg><div class="tip" role="status"></div>`;
  const svg = el.querySelector("svg"), tip = el.querySelector(".tip"), cur = el.querySelector(".cur");
  let at = n - 1;
  const show = (i, withTip) => {
    at = i; cur.setAttribute("x1", x(i)); cur.setAttribute("x2", x(i)); cur.classList.toggle("sync", !withTip);
    if (!withTip) { tip.classList.remove("on"); return; }
    tip.innerHTML = `<b>${new Date(times[i] * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</b>${series.map((s) => `<div><span>${esc(s.label)}</span><span>${fmt(s.values[i])}</span></div>`).join("")}${onPick ? '<div class="tip-hint">click for these requests</div>' : ""}`;
    tip.classList.add("on");
    const r = svg.getBoundingClientRect();
    tip.style.left = `${Math.min((x(i) / W) * r.width + 16, r.width - 160)}px`; tip.style.top = "10px";
  };
  const hide = () => { tip.classList.remove("on"); cur.setAttribute("x1", -9); cur.setAttribute("x2", -9); };
  const self = { el, mirror: (t) => { if (t == null) return hide(); let best = 0; for (let i = 1; i < n; i++) if (Math.abs(times[i] - t) < Math.abs(times[best] - t)) best = i; show(best, false); } };
  synced.add(self);
  const index = (ev) => { const r = svg.getBoundingClientRect(); return Math.max(0, Math.min(n - 1, Math.round(((((ev.clientX - r.left) / r.width) * W - P.l) / (W - P.l - P.r)) * (n - 1)))); };
  const pick = (i) => onPick?.({ from: Math.floor(times[i] - bucket), to: Math.ceil(times[i]) });
  svg.onmousemove = (ev) => { const i = index(ev); show(i, true); broadcast(times[i], self); };
  svg.onmouseleave = () => { hide(); broadcast(null, self); };
  if (onPick) svg.onclick = (ev) => pick(index(ev));
  svg.onkeydown = (ev) => {
    if (ev.key === "ArrowLeft" || ev.key === "ArrowRight") { ev.preventDefault(); show(Math.max(0, Math.min(n - 1, at + (ev.key === "ArrowLeft" ? -1 : 1))), true); broadcast(times[at], self); }
    if (ev.key === "Enter" && onPick) pick(at);
  };
  svg.onblur = () => { hide(); broadcast(null, self); };
}
export function sparkline(values, color = "--ch-1") {
  const w = 84, h = 24, max = Math.max(1, ...values), n = Math.max(2, values.length);
  const d = values.map((v, i) => `${i ? "L" : "M"}${((i / (n - 1)) * w).toFixed(1)} ${(h - 2 - (v / max) * (h - 5)).toFixed(1)}`).join(" ");
  const col = cssVar(color);
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><path d="${d}" fill="none" stroke="${col}" stroke-width="1.4" stroke-linejoin="round"/></svg>`;
}
export const hbars = (entries, { label = (k) => esc(k), cls = () => "", val = (v) => fmt(v), flow = false } = {}) => {
  const max = Math.max(1e-9, ...entries.map((e) => e[1]));
  return `<div class="bars">${entries.map(([k, v]) => `<div class="bar-row ${cls(k)}"><span>${label(k)}</span><span class="val">${val(v)}</span><div class="bar${flow ? " flow" : ""}"><i data-w="${(v / max) * 100}"></i></div></div>`).join("")}</div>`;
};

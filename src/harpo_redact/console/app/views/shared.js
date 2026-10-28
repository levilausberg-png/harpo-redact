import { esc, tcol, tlabel } from "../core/dom.js";

export const ROUTE = { "/v1/chat/completions": "chat", "/v1/messages": "messages", "/v1/messages/count_tokens": "count tokens", "/v1/scan": "scan", "/v1/documents/redact": "document" };
const DECISION = { forwarded: ["ok", "forwarded"], blocked: ["bad", "blocked"], scanned: ["info", "scanned"], upstream_error: ["warn", "provider error"] };
export const decision = (d) => { const [k, l] = DECISION[d] || ["", d || "—"]; return `<span class="st ${k}">${esc(l)}</span>`; };
export const types = (counts, max = 3) => {
  const e = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]);
  if (!e.length) return '<span class="t3">—</span>';
  return e.slice(0, max).map(([t, n]) => `<span class="ent ${tcol(t)}">${esc(tlabel(t))}${n > 1 ? ` ×${n}` : ""}</span>`).join(" ") + (e.length > max ? ` <span class="t3">+${e.length - max}</span>` : "");
};
export const total = (counts) => Object.values(counts || {}).reduce((a, b) => a + b, 0);
export async function bench(ctx) { if (!ctx.bench) ctx.bench = await (await fetch("/console/leakbench.json", { cache: "no-store" })).json(); return ctx.bench; }

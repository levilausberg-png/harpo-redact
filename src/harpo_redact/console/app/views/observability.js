import { api } from "../core/api.js";
import { $, esc, fmt, ms, paint } from "../core/dom.js";
import { head, panel, stats, table } from "../ui/kit.js";
import { lineChart, hbars } from "../ui/charts.js";
import { ROUTE } from "./shared.js";

export default async function observability(view, ctx) {
  const draw = async () => {
    const s = await api("/v1/stats");
    if (ctx.route !== "observability") return;
    const stages = ["normalize", "patterns", "ner", "slm", "render", "total"].map((k) => ({ k, ...(s.stages?.[k] || {}) }));
    view.innerHTML = `${head("Observability", `Content-free telemetry from this gateway process, ${s.scope === "all" ? "all keys" : "this key only"}. Prometheus metrics are also served at <code>/metrics</code> when <code>server.metrics</code> is on.`, `<span class="tag">window ${Math.round(s.window_s / 60)} min</span>`, "SHIELD")}
      ${panel("Traffic", `${stats([{ k: "Requests", v: fmt(s.totals.requests) }, { k: "Forwarded", v: fmt(s.totals.forwarded) }, { k: "Blocked", v: fmt(s.totals.blocked) }, { k: "Errors", v: fmt(s.totals.errors) }, { k: "Overhead p95", v: s.latency_ms.p95 ?? "—", u: s.latency_ms.p95 == null ? "" : "ms" }])}<div class="chart" id="obs-chart"></div><div class="chart" id="obs-chart2"></div>`, { cls: "elev" })}
      <div class="grid g2 mt">${panel("Pipeline latency by stage", '<div id="obs-stages"></div>', { r: "per request" })}${panel("Upstreams", '<div id="obs-ups"></div>')}</div>
      <div class="grid g3 mt">
        ${panel("Security outcomes", Object.keys(s.by_reason).length ? `<div class="pb">${hbars(Object.entries(s.by_reason), { label: (k) => esc(k.replace(/_/g, " ")) })}</div>` : '<p class="pb t3">No blocks in this window.</p>', { r: "blocks by reason" })}
        ${panel("Routes and decisions", `<div class="pb">${hbars(Object.entries(s.routes), { label: (k) => esc(ROUTE[k] || k) })}</div><div class="pb">${hbars(Object.entries(s.decisions), { label: (k) => esc(k.replace(/_/g, " ")) })}</div>`)}
        ${panel("SLM and documents", `${stats([{ k: "Document jobs", v: fmt(s.documents.jobs) }, { k: "Refused", v: fmt(s.documents.failed) }, { k: "Doc p95", v: s.documents.p95 ? Math.round(s.documents.p95) : "—", u: s.documents.p95 ? "ms" : "" }])}<div class="pb">${Object.keys(s.slm_states).length ? hbars(Object.entries(s.slm_states), { label: (k) => `SLM ${esc(k)}` }) : '<p class="t3">No SLM activity: the local model is optional.</p>'}</div>`)}
      </div>`;
    paint(view);
    lineChart($("#obs-chart"), { onPick: (r) => ctx.go(`activity?from=${r.from}&to=${r.to}`), times: s.series.map((x) => x.t), series: [{ label: "requests", color: "--ch-1", values: s.series.map((x) => x.requests) }, { label: "blocked", color: "--ch-3", values: s.series.map((x) => x.blocked) }], height: 180 });
    lineChart($("#obs-chart2"), { onPick: (r) => ctx.go(`activity?from=${r.from}&to=${r.to}`), times: s.series.map((x) => x.t), series: [{ label: "blocked", color: "--ch-3", values: s.series.map((x) => x.blocked) }, { label: "errors", color: "--ch-4", values: s.series.map((x) => x.errors || 0) }], height: 110 });
    table($("#obs-stages"), { rows: stages, cols: [{ k: "k", l: "Stage", f: (r) => `<span class="mono">${esc(r.k)}</span>` }, { k: "p50", l: "p50", r: true, f: (r) => ms(r.p50) }, { k: "p95", l: "p95", r: true, f: (r) => ms(r.p95) }, { k: "count", l: "Samples", r: true, f: (r) => fmt(r.count) }] });
    table($("#obs-ups"), { rows: Object.entries(s.upstreams).map(([name, u]) => ({ name, ...u })), sort: ["requests", "desc"], emptyHtml: '<p class="pb t3">No provider traffic in this window.</p>', cols: [{ k: "name", l: "Upstream" }, { k: "requests", l: "Requests", r: true, f: (u) => fmt(u.requests) }, { k: "errors", l: "Errors", r: true, f: (u) => fmt(u.errors) }, { k: "blocked", l: "Blocked", r: true, f: (u) => fmt(u.blocked) }, { k: "p50", l: "p50", r: true, f: (u) => ms(u.p50) }, { k: "p95", l: "p95", r: true, f: (u) => ms(u.p95) }] });
  };
  await draw();
  ctx.poll = setInterval(() => draw().catch(() => null), 5000);
}

import { openMenu } from "../ui/menu.js";
import { download, toCSV, stamp } from "../core/exports.js";
import { stream } from "../core/stream.js";
import { prefs } from "../core/prefs.js";
// Request explorer: content-free records only. Prompts and replies are never stored, so they cannot be shown (INV-05).
import { api } from "../core/api.js";
import { $, $$, esc, icon, ms, paint, tlabel, copy, clock, toast } from "../core/dom.js";
import { head, panel, table, drawer, kv, seg, empty } from "../ui/kit.js";
import { ROUTE, decision, types, total } from "./shared.js";

const EXPORT = [[(e) => new Date(e.ts * 1000).toISOString(), "time"], ["request_id", "request_id"], ["route", "route"], ["upstream", "provider"], ["model", "model"], ["key_id", "key"],
  ["decision", "decision"], ["risk", "risk"], [(e) => (e.reasons || []).join(" "), "reasons"], [(e) => total(e.redactions), "redacted"], ["redactions", "redactions_by_type"],
  ["total_ms", "total_ms"], ["upstream_ms", "provider_ms"], ["egress", "egress"], ["egress_ms", "egress_ms"], ["response_scan", "response_scan"], ["stream", "streamed"]];
const FIELDS = [["decision", "decision"], ["route", "route"], ["upstream", "provider"], ["model", "model"], ["key", "key"], ["type", "entity"], ["q", "q"]];
const STAGES = [["normalize", "Normalization", "det", ""], ["patterns", "Identifiers & secrets", "det", "detection"], ["ner", "Named entities", "prob", "detection"],
  ["slm", "Local SLM", "prob", "detection"], ["render", "Policy & redaction", "det", "policy"]];

export function trace(e) {
  const t = e.timings_ms || {}, rows = [];
  let at = 0;
  const add = (n, d, kind, o = {}) => { rows.push({ n, d, kind, start: at, ...o }); if (d > 0) at += d; };
  add("Request received", 0, "det", { state: "ok", v: ROUTE[e.route] || e.route || "" });
  for (const [k, n, kind, href] of STAGES) {
    if (k === "slm" && !(t.slm > 0)) { add(n, 0, kind, { state: "off", v: e.slm ? String(e.slm).replace(/_/g, " ") : "not used", href }); continue; }
    if (t[k] == null) continue;
    add(n, t[k], kind, { state: "ok", href });
  }
  if (e.decision === "blocked") add("Blocked before egress", 0, "bad", { state: "bad", v: (e.reasons || []).join(", ") || "policy", href: "policy" });
  else if (e.egress) add("Egress verification", e.egress_ms || 0, "ver", { state: e.egress === "verified" ? "ok" : "warn", v: e.egress === "verified" ? "outgoing body re-scanned" : "off by configuration", href: "guarantees" });
  if (e.upstream_ms != null) add(`Provider · ${e.upstream || "upstream"}`, e.upstream_ms, "info", { state: e.status >= 500 ? "bad" : "ok", v: e.stream ? "streamed" : `HTTP ${e.status}`, href: "providers" });
  if (e.response_scan) add("Response scan", 0, "ver", { state: e.response_scan === "not_scanned_stream" ? "warn" : "ok", v: e.response_scan === "not_scanned_stream" ? "streamed replies are not scanned" : e.response_scan });
  return { rows, total: Math.max(e.total_ms || 0, at, 0.001) };
}
export function receipt(e, version) {
  return { kind: "harpo.request-receipt", schema: 1, gateway_version: version, request_id: e.request_id || null, time: new Date(e.ts * 1000).toISOString(),
    route: e.route || null, provider: e.upstream || null, model: e.model || null, key_id: e.key_id || null, decision: e.decision || null, risk: e.risk || null,
    reasons: e.reasons || [], redactions: e.redactions || {}, egress_verification: e.egress || null, response_scan: e.response_scan || null, slm: e.slm || null,
    mode: e.mode || null, streamed: !!e.stream, timings_ms: { ...(e.timings_ms || {}), egress_verify: e.egress_ms ?? null, provider: e.upstream_ms ?? null, total: e.total_ms ?? null },
    content: "none: prompts and replies are never stored" };
}

export default async function activity(view, ctx) {
  const Q = ctx.query;
  const F = Object.fromEntries(FIELDS.map(([k, q]) => [k, Q.get(q) || (k === "decision" ? "all" : "")]));
  F.from = +Q.get("from") || 0; F.to = +Q.get("to") || 0;
  const L = { paused: false, pending: 0, open: null };
  let events = [], rows = [];
  const sync = () => ctx.setQuery({ ...Object.fromEntries(FIELDS.map(([k, q]) => [q, F[k]])), from: F.from ? String(F.from) : "", to: F.to ? String(F.to) : "" }, L.open ? ["request", L.open] : []);
  const opts = (k, f = (x) => x) => [...new Set(events.map((e) => (k === "type" ? Object.keys(e.redactions || {}) : [e[k]])).flat().filter(Boolean))].sort().map((v) => `<option value="${esc(v)}" ${F[k === "key_id" ? "key" : k] === v ? "selected" : ""}>${esc(f(v))}</option>`).join("");
  const chips = () => FIELDS.filter(([k]) => F[k] && F[k] !== "all").map(([k, q]) => `<button class="chip-x" data-clear="${k}" aria-label="Remove filter ${q}">${esc(q)}: <b>${esc(k === "type" ? tlabel(F[k]) : k === "route" ? ROUTE[F[k]] || F[k] : F[k])}</b>${icon("x", "sm")}</button>`).join("") + (F.from ? `<button class="chip-x" data-clear="time" aria-label="Remove the time filter">time: <b>${esc(clock(F.from))}–${esc(clock(F.to))}</b>${icon("x", "sm")}</button>` : "");
  const draw = () => {
    if (ctx.route !== "activity") return;
    rows = events.filter((e) => (F.decision === "all" || e.decision === F.decision) && (!F.route || e.route === F.route) && (!F.upstream || e.upstream === F.upstream)
      && (!F.model || e.model === F.model) && (!F.key || e.key_id === F.key) && (!F.type || (e.redactions || {})[F.type]) && (!F.q || (e.request_id || "").includes(F.q)) && (!F.from || (e.ts >= F.from && e.ts <= F.to)));
    view.innerHTML = `${head("Activity", "Every request the gateway handled, by outcome. Metadata only: prompts and replies are never stored or shown.", `<button class="btn" id="live-t" aria-pressed="${!L.paused}">${icon(L.paused ? "play" : "clock", "sm")} ${L.paused ? `Resume${L.pending ? ` · ${L.pending} new` : ""}` : "Live"}</button><button class="btn" id="views-btn" aria-haspopup="menu">${icon("bookmark", "sm")} Views</button><button class="btn" id="cols-btn" aria-haspopup="menu">${icon("columns-3", "sm")} Columns</button><button class="btn" id="exp-btn" aria-haspopup="menu">${icon("download", "sm")} Export</button><span class="tag">${events.length} in memory</span>`, "SHIELD")}
      <div class="panel pg-bar">${seg("f-dec", [["all", "All"], ["forwarded", "Forwarded"], ["blocked", "Blocked"], ["scanned", "Scanned"], ["upstream_error", "Errors"]], F.decision)}
        <label class="sr" for="f-route">Route</label><select class="select" id="f-route" data-f="route"><option value="">Any route</option>${opts("route", (r) => ROUTE[r] || r)}</select>
        <label class="sr" for="f-up">Provider</label><select class="select" id="f-up" data-f="upstream"><option value="">Any provider</option>${opts("upstream")}</select>
        <label class="sr" for="f-model">Model</label><select class="select" id="f-model" data-f="model"><option value="">Any model</option>${opts("model")}</select>
        <label class="sr" for="f-type">Entity type</label><select class="select" id="f-type" data-f="type"><option value="">Any entity</option>${opts("type", tlabel)}</select>
        <label class="sr" for="f-key">Key</label><select class="select" id="f-key" data-f="key"><option value="">Any key</option>${opts("key_id")}</select>
        <label class="sr" for="f-q">Request id</label><input class="input mono-in" id="f-q" type="search" placeholder="request id" value="${esc(F.q)}"></div>
      ${chips() ? `<div class="chips-row">${chips()}<button class="btn ghost" id="clear-all">Clear all</button></div>` : ""}
      ${panel(`${rows.length} request${rows.length === 1 ? "" : "s"}`, '<div id="rows"></div>', { r: "J / K to move · Enter for the trace" })}`;
    for (const sel of $$("select[data-f]", view)) { sel.style.width = "auto"; sel.onchange = () => { F[sel.dataset.f] = sel.value; sync(); draw(); }; }
    $("#f-q").style.width = "150px";
    $("#f-q").onchange = (e) => { F.q = e.target.value.trim(); sync(); draw(); };
    $("#f-dec").onclick = (e) => { const b = e.target.closest("button"); if (b) { F.decision = b.dataset.v; sync(); draw(); } };
    $("#live-t").onclick = () => { L.paused = !L.paused; if (!L.paused && pending.length) { for (const e of pending) fresh.add(e.seq); events = [...pending, ...events].slice(0, 500); pending.length = 0; } L.pending = 0; draw(); };
    view.querySelector(".chips-row")?.addEventListener("click", (e) => { const b = e.target.closest("[data-clear]"); if (b) { if (b.dataset.clear === "time") F.from = F.to = 0; else F[b.dataset.clear] = b.dataset.clear === "decision" ? "all" : ""; } if (e.target.id === "clear-all") { for (const [k] of FIELDS) F[k] = k === "decision" ? "all" : ""; F.from = F.to = 0; } if (b || e.target.id === "clear-all") { sync(); draw(); } });
    const hidden = new Set((prefs.get("columns", {}) || {}).activity || []);
    const ALL = [
      { k: "ts", l: "Time", f: (e) => `<span class="mono t2">${new Date(e.ts * 1000).toLocaleTimeString()}</span>` },
      { k: "request_id", l: "Request", f: (e) => `<span class="mono t3">${esc((e.request_id || "—").slice(0, 12))}</span>` },
      { k: "route", l: "Route", f: (e) => esc(ROUTE[e.route] || e.route) },
      { k: "upstream", l: "Provider", f: (e) => esc(e.upstream || "—") },
      { k: "model", l: "Model", f: (e) => `<span class="mono">${esc(e.model || "—")}</span>` },
      { k: "decision", l: "Decision", f: (e) => decision(e.decision) },
      { k: "risk", l: "Risk", f: (e) => `<span class="st ${e.risk === "red" ? "bad" : e.risk === "yellow" ? "warn" : "ok"}">${esc(e.risk || "—")}</span>` },
      { k: "redactions", l: "Redacted", v: (e) => total(e.redactions), f: (e) => types(e.redactions, 2) },
      { k: "reasons", l: "Reasons", v: (e) => (e.reasons || []).join(), f: (e) => `<span class="mono t3">${esc((e.reasons || []).join(", ") || "—")}</span>` },
      { k: "key_id", l: "Key", f: (e) => `<span class="mono t3">${esc(e.key_id || "—")}</span>` },
      { k: "total_ms", l: "Total", r: true, f: (e) => ms(e.total_ms) },
      { k: "upstream_ms", l: "Provider ms", r: true, f: (e) => ms(e.upstream_ms) },
      { k: "egress", l: "Egress", f: (e) => `<span class="t3">${esc(e.egress || "—")}</span>` },
    ];
    COLS = ALL;
    table($("#rows"), { rows, sort: ["ts", "desc"], onRow: open, emptyHtml: empty("NO MATCHING REQUESTS", "The most recent requests are kept in memory and cleared on restart. Nothing about their content is kept at all."), cols: ALL.filter((c) => c.k === "ts" || !hidden.has(c.k)) });
    $("#rows").classList.toggle("dense", prefs.get("density") === "compact");
    for (const tr of $$("#rows tbody tr.click")) if (fresh.has(rows[+tr.dataset.i]?.seq)) tr.classList.add("fresh");
    fresh.clear();
    $("#views-btn").onclick = (e) => viewsMenu(e.currentTarget);
    $("#cols-btn").onclick = (e) => colsMenu(e.currentTarget);
    $("#exp-btn").onclick = (e) => openMenu(e.currentTarget, [
      { label: `CSV · ${rows.length} request${rows.length === 1 ? "" : "s"}`, icon: "table-2", run: () => download(`harpo-activity-${stamp()}.csv`, toCSV(rows, EXPORT), "text/csv") },
      { label: "JSON", icon: "file-code", run: () => download(`harpo-activity-${stamp()}.json`, JSON.stringify(rows.map(({ seq: _s, ...e }) => e), null, 2)) },
    ], { label: "Export" });
  };
  const open = (e) => {
    const list = [...rows].sort((a, b) => b.ts - a.ts);
    const show = (rec) => {
      L.open = rec.request_id || null; sync();
      const { rows: tr, total: tt } = trace(rec);
      const overhead = rec.total_ms != null && rec.upstream_ms != null && !rec.stream ? rec.total_ms - rec.upstream_ms : null;
      const layer = drawer(`Request ${esc((rec.request_id || "").slice(0, 12))}`, `${esc(ROUTE[rec.route] || rec.route)} · ${new Date(rec.ts * 1000).toLocaleString()} · metadata only`,
        `<div class="trace-sum">${[["Total", ms(rec.total_ms)], ["Gateway", ms(overhead)], ["Provider", ms(rec.upstream_ms)], ["Redacted", String(total(rec.redactions))]].map(([k, v]) => `<div><span>${k}</span><b class="num">${v}</b></div>`).join("")}</div>
         <div><h5>TRACE</h5><div class="wf" role="table" aria-label="Request timing waterfall">${tr.map((s) => `<div class="wf-row ${s.state}" role="row"><span class="wf-n" role="cell">${s.href ? `<a href="#/${s.href}">${esc(s.n)}</a>` : esc(s.n)}${s.v ? `<small>${esc(s.v)}</small>` : ""}</span>
           <span class="wf-track" role="cell" aria-label="${esc(s.n)} ${s.d > 0 ? ms(s.d) : ""}">${s.d > 0 ? `<i class="wf-bar k-${s.kind}" data-l="${(s.start / tt) * 100}" data-w="${Math.max(0.8, (s.d / tt) * 100)}"></i>` : `<i class="wf-dot k-${s.kind}" data-l="${(s.start / tt) * 100}"></i>`}</span>
           <span class="wf-d num" role="cell">${s.d > 0 ? ms(s.d) : ""}</span></div>`).join("")}</div></div>
         <div class="panel">${kv([["Decision", decision(rec.decision)], ["Risk", esc(rec.risk || "—")], ["Reasons", (rec.reasons || []).length ? `<a href="#/policy">${esc(rec.reasons.join(", "))}</a>` : "none"], ["Provider", esc(rec.upstream || "—")], ["Model", esc(rec.model || "—")],
           ["Key", esc(rec.key_id || "—")], ["Mode", esc(rec.mode || "—")], ["Streamed", rec.stream ? "yes" : "no"], ["Response scan", esc(rec.response_scan || "—")], ["Request id", `<span class="mono">${esc(rec.request_id || "—")}</span>`]])}</div>
         <div><h5>REDACTED VALUES BY TYPE</h5><div class="panel pb">${types(rec.redactions, 20)}</div></div>
         <div class="row-btns"><button class="btn" id="cp-id">${icon("copy", "sm")} Copy request id</button><button class="btn" id="cp-link">${icon("external-link", "sm")} Copy link</button><button class="btn" id="cp-rec">${icon("file-text", "sm")} Copy receipt</button><button class="btn" id="dl-rec">${icon("download", "sm")} Download receipt</button></div>
         <p class="t3">[ and ] step through the list. Prompt and reply content is not stored, so it cannot be shown (INV-05).</p>`);
      paint(layer);
      const rid = rec.request_id || "";
      $("#cp-id").onclick = () => copy(rid, "Request id copied");
      $("#cp-link").onclick = () => copy(ctx.link(`activity/request/${encodeURIComponent(rid)}`), "Link copied");
      $("#cp-rec").onclick = () => copy(JSON.stringify(receipt(rec, ctx.policy.version), null, 2), "Receipt copied");
      $("#dl-rec").onclick = () => { const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([JSON.stringify(receipt(rec, ctx.policy.version), null, 2)], { type: "application/json" })), download: `harpo-receipt-${rid.slice(0, 12) || "request"}.json` }); a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); };
      layer.onkeydown = (ev) => { const i = list.indexOf(rec); if (ev.key === "]" && i < list.length - 1) show(list[i + 1]); if (ev.key === "[" && i > 0) show(list[i - 1]); };
      new MutationObserver((_, obs) => { if (!layer.innerHTML) { obs.disconnect(); L.open = null; if (ctx.route === "activity") sync(); } }).observe(layer, { childList: true });
    };
    show(e);
  };
  const fresh = new Set(), pending = [];
  let COLS = [];
  const viewsMenu = (btn) => {
    const views = prefs.get("views", []).filter((v) => v.page === "activity");
    openMenu(btn, [{ label: "Save this view…", icon: "bookmark", run: saveView }, ...(views.length ? ["-", { head: "SAVED VIEWS" }] : []),
      ...views.map((v) => ({ label: v.name, icon: v.favorite ? "star" : "list-filter", run: () => { location.hash = `#/activity${v.query ? `?${v.query}` : ""}`; } })),
      ...(views.length ? ["-", { label: "Manage views…", icon: "sliders-horizontal", run: manageViews }] : [])], { label: "Saved views" });
  };
  const saveView = () => {
    const layer = $("#layer");
    layer.innerHTML = `<div class="palette-back" id="sv"><div class="palette glass small-dialog" role="dialog" aria-label="Save view"><div class="pb"><h2>Save this view</h2><p class="t3">Stores the filters only, in this browser.</p>
      <label class="field"><label for="sv-name">Name</label><input class="input" id="sv-name" value="${esc(chipsText() || "All requests")}"></label>
      <div class="row-btns"><button class="btn pri" id="sv-ok">Save view</button><button class="btn" id="sv-x">Cancel</button></div></div></div></div>`;
    const ok = () => { const name = $("#sv-name").value.trim(); if (!name) return; prefs.set("views", [...prefs.get("views", []), { id: Date.now().toString(36), name, page: "activity", query: ctx.query.toString(), favorite: false }]); layer.innerHTML = ""; toast("View saved"); };
    $("#sv-ok").onclick = ok; $("#sv-x").onclick = () => { layer.innerHTML = ""; };
    $("#sv-name").onkeydown = (e) => { if (e.key === "Enter") ok(); };
    $("#sv").onclick = (e) => { if (e.target.id === "sv") layer.innerHTML = ""; };
    $("#sv-name").select();
  };
  const manageViews = () => {
    const draw2 = () => {
      const views = prefs.get("views", []).filter((v) => v.page === "activity");
      const layer = drawer("Saved views", "Filters only, stored in this browser", views.length ? `<div class="views-list">${views.map((v) => `<div class="view-row" data-id="${esc(v.id)}">
        <label class="sr" for="vn-${esc(v.id)}">Name</label><input class="input" id="vn-${esc(v.id)}" value="${esc(v.name)}">
        <button class="btn ghost ic" data-fav aria-pressed="${v.favorite}" aria-label="${v.favorite ? "Remove from favorites" : "Add to favorites"}">${icon("star", "sm")}</button>
        <button class="btn ghost" data-del>Delete</button><small class="t3 mono">${esc(v.query || "no filters")}</small></div>`).join("")}</div>` : '<p class="t3">No saved views.</p>');
      layer.onchange = (e) => { const row = e.target.closest("[data-id]"); if (!row) return; prefs.set("views", prefs.get("views", []).map((v) => (v.id === row.dataset.id ? { ...v, name: e.target.value.trim() || v.name } : v))); ctx.renderFavs?.(); };
      layer.onclick = (e) => {
        const row = e.target.closest("[data-id]"); if (!row) return;
        const all = prefs.get("views", []), v = all.find((x) => x.id === row.dataset.id), href = `#/activity${v.query ? `?${v.query}` : ""}`;
        if (e.target.closest("[data-del]")) { prefs.set("views", all.filter((x) => x.id !== v.id)); prefs.set("favorites", prefs.get("favorites", []).filter((f) => f.href !== href)); ctx.renderFavs?.(); draw2(); }
        if (e.target.closest("[data-fav]")) { prefs.set("views", all.map((x) => (x.id === v.id ? { ...x, favorite: !x.favorite } : x))); const favs = prefs.get("favorites", []).filter((f) => f.href !== href); prefs.set("favorites", v.favorite ? favs : [...favs, { label: v.name, href, icon: "bookmark" }]); ctx.renderFavs?.(); draw2(); }
      };
    };
    draw2();
  };
  const colsMenu = (btn) => {
    const cols = prefs.get("columns", {}) || {}, hidden = new Set(cols.activity || []);
    const save = () => { prefs.set("columns", { ...cols, activity: [...hidden] }); draw(); };
    openMenu(btn, [{ head: "COLUMNS" }, ...COLS.filter((c) => c.k !== "ts").map((c) => ({ label: c.l, checked: !hidden.has(c.k), keep: true, run: () => { if (hidden.has(c.k)) hidden.delete(c.k); else hidden.add(c.k); save(); } })),
      "-", { label: "Compact rows", checked: prefs.get("density") === "compact", keep: true, run: () => { prefs.set("density", prefs.get("density") === "compact" ? "comfortable" : "compact"); draw(); } },
      { label: "Reset columns", icon: "refresh-cw", run: () => { hidden.clear(); save(); } }], { label: "Columns" });
  };
  const chipsText = () => FIELDS.filter(([k]) => F[k] && F[k] !== "all").map(([k]) => (k === "type" ? tlabel(F[k]) : F[k])).join(" · ");
  const rowMenu = (e, at) => openMenu(at, [
    { label: "Inspect trace", icon: "waypoints", kbd: "Enter", run: () => open(e) },
    { label: "Copy request id", icon: "copy", run: () => copy(e.request_id || "", "Request id copied") },
    { label: "Copy link", icon: "external-link", run: () => copy(ctx.link(`activity/request/${encodeURIComponent(e.request_id || "")}`), "Link copied") },
    "-",
    ...(e.upstream ? [{ label: `Filter by provider: ${e.upstream}`, icon: "filter", run: () => { F.upstream = e.upstream; sync(); draw(); } }] : []),
    ...(e.model ? [{ label: `Filter by model: ${e.model}`, icon: "filter", run: () => { F.model = e.model; sync(); draw(); } }] : []),
    { label: `Filter by decision: ${e.decision}`, icon: "filter", run: () => { F.decision = e.decision; sync(); draw(); } },
    ...(e.upstream ? ["-", { label: "Open providers", icon: "route", run: () => ctx.go("providers") }] : []),
  ], { label: "Request actions" });
  view.oncontextmenu = (ev) => { const tr = ev.target.closest("#rows tbody tr.click"); if (!tr) return; ev.preventDefault(); rowMenu(rows[+tr.dataset.i], { x: ev.clientX, y: ev.clientY }); };
  view.onkeydown = (ev) => { if ((ev.key === "ContextMenu" || (ev.shiftKey && ev.key === "F10")) && ev.target.matches?.("#rows tbody tr.click")) { ev.preventDefault(); rowMenu(rows[+ev.target.dataset.i], ev.target); } };
  ctx.cleanups.push(stream.on((type, e) => {
    if (type !== "request") return;
    if (L.paused) { pending.unshift(e); L.pending = pending.length; const b = $("#live-t"); if (b) b.innerHTML = `${icon("play", "sm")} Resume · ${L.pending} new`; return; }
    events.unshift(e); fresh.add(e.seq); if (events.length > 500) events.length = 500;
    clearTimeout(L.t); L.t = setTimeout(() => { if (!$("#layer").innerHTML && !/^(SELECT|INPUT)$/.test(document.activeElement?.tagName || "")) draw(); }, 250);
  }), () => clearTimeout(L.t));
  const load = async () => {
    const fresh = (await api("/v1/stats?recent=500")).recent || [];
    if (fresh.length && events.length && fresh[0]?.ts > events[0]?.ts) ctx.pulse();
    if (L.paused && events.length) { L.pending = fresh.filter((x) => x.ts > events[0].ts).length; const b = $("#live-t"); if (b) b.innerHTML = `${icon("play", "sm")} Resume${L.pending ? ` · ${L.pending} new` : ""}`; return; }
    events = fresh; draw();
  };
  await load();
  if (ctx.params[0] === "request" && ctx.params[1]) { const hit = events.find((x) => (x.request_id || "").startsWith(ctx.params[1])); if (hit) open(hit); }
  ctx.poll = setInterval(() => { if (stream.state === "live") return; if (!document.hidden && !$("#layer").innerHTML && !/^(SELECT|INPUT)$/.test(document.activeElement?.tagName || "")) load().catch(() => null); }, 5000);
}

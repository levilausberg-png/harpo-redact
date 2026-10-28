import { prefs } from "../core/prefs.js";
import { stream } from "../core/stream.js";
import { api } from "../core/api.js";
import { $, esc, icon, fmt, ms, paint, tlabel, tcol, copy, clock } from "../core/dom.js";
import { head, panel, stats, mx, tag, empty, pipe, table } from "../ui/kit.js";
import { lineChart, hbars } from "../ui/charts.js";
import { ROUTE, decision, types, total, bench } from "./shared.js";

export default async function overview(view, ctx) {
  view.innerHTML = '<div class="skel"></div>';
  await bench(ctx).catch(() => null);
  const draw = async () => {
    const [s, sys] = await Promise.all([api("/v1/stats"), ctx.admin ? api("/v1/system").catch(() => null) : null]);
    if (ctx.route !== "overview") return;
    if (sys) ctx.system = sys;
    const prev = ctx._ovTotals;
    ctx._ovTotals = s.totals;
    render(view, ctx, s, sys);
    if (prev) flow(view, ctx, s.totals.forwarded - prev.forwarded, s.totals.blocked - prev.blocked);
  };
  await draw();
  ctx.poll = setInterval(() => draw().catch(() => null), 5000);
  ctx.cleanups.push(stream.on((type) => {
    if (type === "request" || type === "posture") { clearTimeout(ctx._ovT); ctx._ovT = setTimeout(() => draw().catch(() => null), 600); }
  }), () => clearTimeout(ctx._ovT));
}

function render(view, ctx, s, sys) {
  const p = ctx.policy, t = s.totals, lat = s.latency_ms, ups = p.upstreams || [];
  const ready = sys ? sys.readiness.status === "ready" : null;
  const failing = sys ? Object.entries(sys.readiness.checks).filter(([, v]) => v !== "ok") : [];
  const egress = p.egress_verification === "full";
  const upStats = Object.values(s.upstreams || {});
  const providerP95 = upStats.length ? Math.max(...upStats.map((u) => u.p95 || 0)) : null;
  const upErrors = upStats.reduce((a, u) => a + u.errors, 0);
  const held = s.by_reason?.egress_verification || 0;
  const topReason = Object.keys(s.by_reason || {})[0];
  const def = ctx.bench?.configs?.["default-image"];
  const title = sys ? (ready ? 'Gateway <span class="grad-text">healthy</span>' : "Gateway not ready") : 'Policy <span class="grad-text">enforced</span>';
  const lead = !sys ? "Connect with an admin key to see gateway health and readiness."
    : ready && egress ? "All enforced boundaries operational. Every outgoing request is verified before it leaves."
    : [!ready && `Not ready: ${failing.map(([k, v]) => `${k} ${v}`).join(", ")}.`, !egress && "Egress verification is off."].filter(Boolean).join(" ");
  const st = ctx.selftest;
  const chips = [
    tag(`${ups.length} upstream${ups.length === 1 ? "" : "s"} protected`, "ver"),
    tag(`egress verification ${egress ? "on" : "off"}`, egress ? "ok" : "warn"),
    tag(`unknown fields ${p.unknown_fields}`, p.unknown_fields === "reject" ? "det" : "warn"),
    tag(`images ${p.unsupported_content}`, "det"),
    def ? tag(`LeakBench ${def.raw_identifier_escapes} escapes / ${fmt(ctx.bench.corpus.secrets)}`, "prob") : "",
    st ? tag(`self-test ${st.passed ? "passed" : "failed"} ${st.results.filter((r) => r.status === "pass").length}/${st.results.length}`, st.passed ? "ok" : "bad") : "",
  ].join("");
  const stages = [
    { n: "Applications", icon: "bot", v: `${fmt(t.requests)} requests`, v2: `${fmt(t.forwarded)} forwarded`, state: t.requests ? "ok" : "off" },
    { n: "Gateway", icon: "lock-keyhole", v: `p95 ${ms(lat.p95)}`, v2: sys ? (ready ? "ready" : "not ready") : "live", state: sys && !ready ? "bad" : "ok" },
    { n: "Detection", icon: "scan-search", v: `${fmt(t.redactions)} values`, v2: `${Object.keys(s.by_type).length} kinds`, state: "ok" },
    { n: "Policy", icon: "shield-check", v: `${fmt(t.blocked)} blocked`, v2: topReason ? topReason.replace(/_/g, " ") : "nothing blocked", state: "ok" },
    { n: "Egress verification", icon: "badge-check", v: egress ? "every request" : "off", v2: `${held} held back`, state: egress ? "ok" : "warn" },
    { n: "Providers", icon: "globe", v: `${ups.length} upstream${ups.length === 1 ? "" : "s"}`, v2: providerP95 ? `p95 ${ms(providerP95)}` : "no traffic", state: upErrors ? "warn" : "ok" },
  ];
  const det = sys?.detection;
  const layers = [
    { icon: "binary", kind: "det", n: "Normalization", d: "Unicode NFKC, full-width digits, look-alike letters, escapes, line joins", s: '<span class="st ok">on</span>' },
    { icon: "fingerprint", kind: "det", n: "Identifiers", d: "cards, IBANs, phones, national IDs, crypto, devices: checksums and validation", s: '<span class="st ok">on</span>' },
    { icon: "key-round", kind: "det", n: "Secrets", d: det ? `${det.secret_rules} rules plus passwords, Basic auth, seed phrases` : "rule library and prompt rules", s: '<span class="st ok">on</span>' },
    { icon: "languages", kind: "prob", n: "Named entities (NER)", d: det ? (det.ner.enabled ? `${["en", ...Object.keys(det.ner.language_models)].join(", ")} · ${det.ner.other_languages} fallback` : "off") : p.ner?.model || "", s: (det ? det.ner.enabled : p.ner?.enabled) ? '<span class="st prob">on</span>' : '<span class="st">off</span>' },
    { icon: "cpu", kind: "prob", n: "Local SLM", d: det?.slm.enabled ? `${det.slm.model} · ${det.slm.on_failure.replace("_", " ")}` : "optional, off", s: det?.slm.enabled ? `<span class="st ${det.slm.reachable === "ok" ? "prob" : "bad"}">${det.slm.reachable === "ok" ? "healthy" : "unreachable"}</span>` : '<span class="st">off</span>' },
    { icon: "badge-check", kind: "ver", n: "Egress verification", d: "the whole outgoing body is scanned again before it leaves", s: egress ? '<span class="st ok">enforced</span>' : '<span class="st warn">off</span>' },
    { icon: "scan-text", kind: "ver", n: "Response scanning", d: "deterministic check of non-streamed answers", s: p.response_scan === "off" ? '<span class="st">off</span>' : `<span class="st ok">${esc(p.response_scan)}</span>` },
    { icon: "route", kind: "det", n: "Adapter validation", d: `${Object.keys(p.adapters || {}).length} adapters · undeclared fields ${p.unknown_fields === "reject" ? "refused" : "scanned"}`, s: '<span class="st ok">on</span>' },
    { icon: "file-lock", kind: "ver", n: "Documents", d: p.documents?.enabled ? "rebuilt and re-verified before release" : "off", s: p.documents?.enabled ? '<span class="st ok">on</span>' : '<span class="st">off</span>' },
  ];
  const stage = (k) => s.stages?.[k]?.count ? ms(s.stages[k].p95) : "—";
  view.innerHTML = `${tourInvite(ctx)}
    <section class="panel elev lumen posture">
      <div class="posture-top"><div><div class="eyebrow">PROTECTION POSTURE</div><h1>${title}</h1><p class="lead">${esc(lead)}</p><div class="chips">${chips}</div></div>
        <div class="side-stats">${stats([{ k: `Requests · ${Math.round(s.window_s / 60)} min`, v: fmt(t.requests) }, { k: "Values redacted", v: fmt(t.redactions) }, { k: "Blocked", v: fmt(t.blocked) }, { k: "Overhead p95", v: lat.p95 == null ? "—" : Math.round(lat.p95), u: lat.p95 == null ? "" : "ms" }])}</div></div>
      ${pipe(stages)}
    </section>
    ${t.requests ? "" : `<section class="panel mt">${empty("NO TRAFFIC YET", `Point an application at <code>${esc(location.origin)}/v1</code> (OpenAI-compatible) or <code>${esc(location.origin)}</code> (Anthropic). Counts, types and timings appear here; content never does.`,
      `<button class="btn" id="cp-base">${icon("copy", "sm")} Copy base URL</button><a class="btn" href="#/integrations">${icon("blocks", "sm")} Browse integrations</a><a class="btn" href="#/playground">${icon("scan-text", "sm")} Inspect a request</a>`)}</section>`}
    <div class="grid g3 mt">
      ${panel("Traffic", stats([{ k: "Requests", v: fmt(t.requests) }, { k: "Forwarded", v: fmt(t.forwarded) }, { k: "Blocked", v: fmt(t.blocked), tone: t.blocked ? "bad" : "" }, { k: "Scans", v: fmt(t.scanned) }, { k: "Documents", v: fmt(s.documents.jobs) }, { k: "Errors", v: fmt(t.errors), tone: t.errors ? "warn" : "" }]), { r: `last ${Math.round(s.window_s / 60)} min` })}
      ${panel("Privacy", stats([{ k: "Values redacted", v: fmt(t.redactions) }, { k: "Kinds", v: fmt(Object.keys(s.by_type).length) }, { k: "Response findings", v: fmt(s.response_findings) }, { k: "Egress held", v: fmt(held), tone: held ? "bad" : "" }]) + `<div class="pb">${Object.keys(s.by_type).length ? hbars(Object.entries(s.by_type).slice(0, 5), { label: (k) => `<span class="ent ${tcol(k)}">${esc(tlabel(k))}</span>` }) : '<p class="t3">Nothing redacted in this window.</p>'}</div>`)}
      ${panel("Performance", stats([{ k: "Overhead p50", v: lat.p50 == null ? "—" : lat.p50, u: lat.p50 == null ? "" : "ms" }, { k: "p95", v: lat.p95 == null ? "—" : lat.p95, u: lat.p95 == null ? "" : "ms" }, { k: "p99", v: lat.p99 == null ? "—" : lat.p99, u: lat.p99 == null ? "" : "ms" }, { k: "Provider p95", v: providerP95 ? Math.round(providerP95) : "—", u: providerP95 ? "ms" : "" }])
        + `<div class="pb">${hbars([["normalize", s.stages?.normalize?.p95 || 0], ["patterns", s.stages?.patterns?.p95 || 0], ["ner", s.stages?.ner?.p95 || 0], ["slm", s.stages?.slm?.p95 || 0], ["render", s.stages?.render?.p95 || 0]], { label: (k) => `${k} <span class="t3">p95</span>`, val: (v) => (v ? ms(v) : "—"), flow: true })}</div>`)}
    </div>
    <div class="grid g-main mt">
      ${panel("Request flow", `<div class="chart" id="chart"></div>`, { r: '<span class="legend"><span><i data-bg="var(--ch-1)"></i>requests</span><span><i data-bg="var(--ch-2)"></i>values redacted</span><span><i data-bg="var(--ch-3)"></i>blocked</span></span>', cls: "elev" })}
      ${panel("Protection layers", mx(layers), { r: `<a class="btn ghost" href="#/detection">Detection ${icon("arrow-right", "sm")}</a>` })}
    </div>
    ${timeline(ctx)}${panel("Recent requests", '<div id="recent"></div>', { cls: "mt", r: `<a class="btn ghost" href="#/activity">Explorer ${icon("arrow-right", "sm")}</a>` })}`;
  paint(view);
  const LINKS = ["integrations", "system", "detection", "policy", "guarantees", "providers"];
  view.querySelectorAll(".posture .pipe .stage").forEach((el, i) => {
    el.setAttribute("role", "link"); el.tabIndex = 0; el.title = `Open ${LINKS[i]}`;  // the visible text stays the accessible name
    el.onclick = () => ctx.go(LINKS[i]); el.onkeydown = (e) => { if (e.key === "Enter") ctx.go(LINKS[i]); };
  });
  $("#cp-base")?.addEventListener("click", () => copy(`${location.origin}/v1`, "Base URL copied"));
  lineChart($("#chart"), { onPick: (r) => ctx.go(`activity?from=${r.from}&to=${r.to}`), times: s.series.map((x) => x.t), series: [{ label: "requests", color: "--ch-1", values: s.series.map((x) => x.requests) }, { label: "values redacted", color: "--ch-2", values: s.series.map((x) => x.redactions) }, { label: "blocked", color: "--ch-3", values: s.series.map((x) => x.blocked) }], height: 196 });
  table($("#recent"), { rows: s.recent.slice(0, 8), sort: ["ts", "desc"], emptyHtml: '<p class="pb t3">No requests yet.</p>', cols: [
    { k: "ts", l: "Time", f: (e) => `<span class="mono t2">${new Date(e.ts * 1000).toLocaleTimeString()}</span>` },
    { k: "request_id", l: "Request", f: (e) => `<span class="mono t3">${esc((e.request_id || "").slice(0, 10))}</span>` },
    { k: "route", l: "Route", f: (e) => esc(ROUTE[e.route] || e.route) },
    { k: "model", l: "Model", f: (e) => `<span class="mono">${esc(e.model || "—")}</span>` },
    { k: "decision", l: "Decision", f: (e) => decision(e.decision) },
    { k: "redactions", l: "Redacted", v: (e) => total(e.redactions), f: (e) => types(e.redactions) },
    { k: "total_ms", l: "Overhead", r: true, f: (e) => ms(e.total_ms) },
  ] });
}

/** The request path reacts to real traffic between two polls and is still otherwise: forwarded requests travel the
 * whole path, blocked ones stop at Policy. Aggregated per poll, so heavy traffic never creates one element per request. */
function flow(view, ctx, forwarded, blocked) {
  if (forwarded <= 0 && blocked <= 0) return;
  ctx.pulse?.();
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const pipe = view.querySelector(".posture .pipe");
  if (!pipe) return;
  pipe.style.setProperty("--flow-i", String(Math.min(1, 0.45 + (forwarded + blocked) / 25)));
  if (forwarded > 0) pipe.insertAdjacentHTML("beforeend", '<i class="flow-run" aria-hidden="true"></i>');
  if (blocked > 0) { pipe.insertAdjacentHTML("beforeend", '<i class="flow-run halt" aria-hidden="true"></i>'); pipe.children[3]?.classList.add("hit"); }
}

function timeline(ctx) {
  const t = ctx.attention?.timeline || [];
  if (!ctx.admin || !t.length) return "";
  return panel("Posture timeline", `<ol class="ptl pb">${t.slice(0, 6).map((x) => `<li><span class="mono t3">${clock(x.ts)}</span><span class="st ${x.state === "healthy" ? "ok" : x.state === "degraded" ? "warn" : "bad"}">${esc(x.state)}</span><span>${esc(x.reason)}</span></li>`).join("")}</ol>`,
    { cls: "mt", r: `<button class="btn ghost" data-act="attention">${icon("bell", "sm")} Attention</button>` });
}

function tourInvite(ctx) {
  if (!ctx.admin || prefs.get("tour") != null) return "";
  return `<div class="tour-invite" data-tour>${icon("sparkles", "sm")}<span>New here? A five-step tour shows what the gateway does and where to look.</span><button class="btn" data-act="tour">Take the tour</button><button class="btn ghost ic" data-act="tour-dismiss" aria-label="Dismiss the tour suggestion">${icon("x", "sm")}</button></div>`;
}

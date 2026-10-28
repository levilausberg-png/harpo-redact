// Self-test center: subsystem suites, each labelled with what it actually exercises.
import { api } from "../core/api.js";
import { $, $$, esc, icon, ms, toast } from "../core/dom.js";

const KIND = { local: ["Local logic", "det"], live: ["Live dependency", "prob"], config: ["Configuration", "ver"] };
const SUITES = [["gateway", "Gateway", "config"], ["detection", "Detection", "local"], ["secrets", "Secrets", "local"], ["egress", "Egress", "local"], ["adapters", "Adapters", "local"],
  ["headers", "Security headers", "local"], ["configuration", "Configuration", "config"], ["documents", "Documents", "live"], ["providers", "Providers", "live"], ["slm", "Local SLM", "live"]];
const tone = (s) => (s === "pass" ? "ok" : s === "fail" ? "bad" : s === "running" ? "warn" : "");

export function suitesPanel(ctx) {
  const R = (ctx.suites ||= {});
  return `<section class="panel suites mt"><div class="ph"><h3>Self-test center</h3><div class="r"><button class="btn pri" id="suites-all">${icon("badge-check", "sm")} Run all suites</button></div></div>
    <div class="suite-grid">${SUITES.map(([id, name, kind]) => { const r = R[id] || {}, st = r.running ? "running" : r.status || "not run"; return `<div class="suite ${tone(st)}">
      <div class="sh"><b>${esc(name)}</b><span class="tag ${KIND[kind][1]}">${KIND[kind][0]}</span></div>
      <div class="sm"><span class="st ${tone(st)}">${esc(st)}</span>${r.ms != null && !r.running ? `<span class="t3 num">${ms(r.ms)}</span>` : ""}<button class="btn ghost" data-run="${id}"${r.running ? " disabled" : ""} aria-label="Run the ${esc(name)} suite">${icon("play", "sm")} Run</button></div>
      ${r.tests && !r.running ? `<details${r.status === "fail" ? " open" : ""}><summary>${r.tests.length} check${r.tests.length === 1 ? "" : "s"}</summary><ul>${r.tests.map((t) => `<li><span class="st ${tone(t.status)}">${esc(t.status)}</span><span>${esc(t.name)}<small>${esc(t.detail)}</small></span></li>`).join("")}</ul></details>` : ""}</div>`; }).join("")}</div>
    <p class="pf t3">Local logic suites run synthetic canaries through this gateway's code; nothing is sent to a provider. Live dependency suites contact the real dependency: the document worker, each provider, the local model.</p></section>`;
}
export function bindSuites(view, ctx, redraw) {
  const R = (ctx.suites ||= {});
  const run = async (ids) => {
    for (const id of ids) R[id] = { ...(R[id] || {}), running: true };
    redraw();
    for (const id of ids) {
      try { R[id] = { ...(await api("/v1/selftest/suites", { method: "POST", body: { suites: [id] } })).suites[0], running: false }; }
      catch (e) { R[id] = { status: "fail", tests: [{ name: "suite request", status: "fail", detail: e.message }], running: false }; }
      if (ctx.route === "guarantees") redraw();
    }
    if (ctx.route !== "guarantees") { const failed = ids.filter((id) => R[id].status === "fail").length; toast(failed ? `Self-test finished: ${failed} suite(s) failed` : "Self-test finished: all suites passed", !!failed); }
  };
  $("#suites-all", view)?.addEventListener("click", () => run(SUITES.map(([id]) => id)));
  for (const b of $$("[data-run]", view)) b.onclick = () => run([b.dataset.run]);
}

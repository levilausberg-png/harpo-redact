import { suitesPanel, bindSuites } from "../ui/suites.js";
import { api } from "../core/api.js";
import { $, esc, icon } from "../core/dom.js";
import { head, panel, kv, st } from "../ui/kit.js";

const INV = [
  ["INV-01", "No raw blocked value crosses the boundary", "Detection and policy on every declared surface; egress verification rescans the whole outgoing body", "test_invariants.py · test_conformance.py"],
  ["INV-02", "No reverse pseudonymization map outlives a request", "Placeholders numbered per request; no store, no resolver; NER cache holds offsets only", "test_invariants.py (reachability walk)"],
  ["INV-03", "Probabilistic layers cannot authorize egress", "NER and SLM only add findings; SLM output verified verbatim; verification is deterministic", "test_invariants.py · test_slm_hardening.py"],
  ["INV-04", "Uninspectable content is never silently forwarded", "Images, audio, provider files, unknown parts and remote MCP blocked or dropped with a marker", "test_invariants.py"],
  ["INV-05", "Prompt content never appears in telemetry", "Logs, audit, metrics and errors carry codes, counts and field paths only", "test_invariants.py · test_logging.py"],
  ["INV-06", "Overrides never restore raw values", "Override releases the request with values redacted; some blocks cannot be overridden", "test_invariants.py"],
  ["INV-07", "Every adapter declares its privacy-relevant surfaces", "adapters.py declarations; coverage walk on every request", "test_conformance.py"],
  ["INV-08", "Unsupported fields fail by explicit policy", "policy.unknown_fields: refuse with the field path, or scan as text", "test_invariants.py"],
  ["INV-09", "Documents are verified before release", "Rebuilt files are re-opened and re-scanned; PDF boxes checked opaque", "test_invariants.py (sabotage tests)"],
  ["INV-10", "Images stay blocked rather than weakly inspected", "No OCR path; pictures refused or blanked by policy", "test_invariants.py"],
  ["INV-11", "Keys are always redacted", "API keys, tokens, passwords and private keys become placeholders and the request goes on; no policy, override, live change or switch lets a key pass or go unscanned", "test_keys_always_redacted.py"],
];
export default async function guarantees(view, ctx) {
  const draw = () => {
    const live = Object.fromEntries((ctx.selftest?.results || []).map((r) => [r.id, r]));
    const sys = ctx.system;
    view.innerHTML = `${head("Security guarantees", "Eleven invariants, the mechanism that enforces each, and the evidence: tests in CI, and a live self-test that runs canaries through this gateway's real request path.",
      ctx.admin ? `<button class="btn pri" id="st-run">${icon("badge-check", "sm")} Run live self-test</button>` : "", "PROOF")}
      ${ctx.selftest ? `<section class="panel ${ctx.selftest.passed ? "lumen assure" : "lumen danger"} pb"><div class="eyebrow">LIVE SELF-TEST · ${esc(new Date(ctx.selftest.ran_at).toLocaleString())}</div><b>${ctx.selftest.passed ? "All live checks passed." : "A live check failed."}</b> <span class="t2">${ctx.selftest.results.filter((r) => r.status === "pass").length} of ${ctx.selftest.results.length} checks passed. Canaries went through the real sanitize path; nothing was sent or counted as traffic.</span></section>` : ""}
      ${ctx.admin ? suitesPanel(ctx) : ""}
      ${panel("Invariants", INV.map(([id, title, mech, tests]) => { const r = live[id]; return `<div class="inv"><code>${id}</code><div><h4>${esc(title)}</h4><p>Enforced by: ${esc(mech)}</p><div class="by">Verified by: <span class="mono">${esc(tests)}</span>${r ? ` · live: ${esc(r.detail)}` : ""}</div></div>
        <div class="status">${r ? st(r.status === "pass" ? "ok" : r.status === "skipped" ? "warn" : "bad", r.status === "pass" ? "pass · live" : r.status) : st("info", "tested in CI")}</div></div>`; }).join(""), { cls: "mt" })}
      <div class="grid g2 mt">${panel("Further assurance", kv([["Adapter conformance", "canary in every field, unknown fields, wrong types: tests/test_conformance.py"], ["Document verification", "every release re-opened and re-scanned"], ["LeakBench regression gate", "tests/test_leakbench.py fails on more escapes"], ["Dependencies", "hash-pinned (requirements.lock), SBOM via tools/make_sbom.py"]]))}
        ${panel("This gateway", sys ? kv([["Version", esc(sys.version)], ["Readiness", sys.readiness.status === "ready" ? st("ok", "ready") : st("bad", "not ready")], ["SLM model digest", sys.detection.slm.enabled ? (sys.detection.slm.digest_pinned ? st("ok", "pinned") : st("warn", "not pinned")) : '<span class="t3">no SLM</span>'], ["Egress verification", esc(ctx.policy.egress_verification)]]) : '<p class="pb t3">Connect with an admin key for runtime details.</p>')}</div>`;
    bindSuites(view, ctx, draw);
    $("#st-run")?.addEventListener("click", async (e) => { e.target.disabled = true; e.target.textContent = "Running…"; ctx.selftest = await api("/v1/selftest", { method: "POST" }); draw(); });
  };
  draw();
}

import { api } from "../core/api.js";
import { $, esc, fmt, bytes, dur, icon, copy } from "../core/dom.js";
import { head, panel, kv, table, st, drawer } from "../ui/kit.js";

export default async function system(view, ctx) {
  if (!ctx.admin) return ctx.needAdmin(view, "System status");
  const s = (ctx.system = await api("/v1/system")), d = s.documents;
  view.innerHTML = `${head("System", "This gateway process: readiness, models, workers, upstreams and limits. Provider keys are reported as present or missing, never shown.", `<button class="btn" id="diag">${icon("download", "sm")} Diagnostic bundle</button><span class="tag">${esc(s.environment)}</span><span class="tag">v${esc(s.version)}</span>`, "PROOF")}
    <div class="grid g3">
      ${panel("Gateway", kv([["Readiness", s.readiness.status === "ready" ? st("ok", "ready") : st("bad", "not ready")], ...Object.entries(s.readiness.checks).map(([k, v]) => [`check: ${k.replace(/_/g, " ")}`, v === "ok" ? st("ok", "ok") : st("bad", v)]), ["Uptime", dur(s.uptime_s)], ["Workers", fmt(s.workers)], ["Python", esc(s.python)]]))}
      ${panel("Document workers", kv([["Active jobs", fmt(d.active)], ["Waiting", fmt(d.waiting)], ["Queue capacity", fmt(d.queue_capacity)], ["Concurrent workers", fmt(d.max_concurrent)], ["Worker memory", `${fmt(d.worker_memory_mb)} MB`], ["Worker CPU", `${fmt(d.worker_cpu_s)} s`], ["Timeout", `${fmt(d.timeout_s)} s`], ["Images", esc(d.images)]]))}
      ${panel("Limits", kv(Object.entries(s.limits).map(([k, v]) => [k.replace(/_/g, " "), /bytes/.test(k) ? bytes(v) : fmt(v)])))}
    </div>
    <div class="grid g2 mt">${panel("Detection models", '<div id="sys-models"></div>', { r: `${fmt(s.detection.secret_rules)} secret rules` })}${panel("Upstreams", '<div id="sys-ups"></div>')}</div>`;
  table($("#sys-models"), { rows: s.detection.ner.models, cols: [{ k: "name", l: "Model", f: (m) => `<span class="mono">${esc(m.name)}</span>` }, { k: "version", l: "Version", f: (m) => (m.version ? `<span class="mono">${esc(m.version)}</span>` : st("bad", "not installed")) }, { k: "license", l: "Licence", f: (m) => esc(m.license || "—") }], emptyHtml: '<p class="pb t3">NER is off.</p>' });
  table($("#sys-ups"), { rows: s.upstreams, cols: [{ k: "name", l: "Upstream", f: (u) => `<b>${esc(u.name)}</b>` }, { k: "style", l: "Protocol" }, { k: "base_url", l: "Endpoint", f: (u) => `<span class="mono t2">${esc(u.base_url)}</span>` }, { k: "key_env", l: "Key", f: (u) => (u.key_env ? `<span class="mono">${esc(u.key_env)}</span> ${u.key_present ? st("ok", "set") : st("bad", "missing")}` : '<span class="t3">none</span>') }] });
  $("#diag").onclick = async () => {
    const b = await api("/v1/diagnostics"), json = JSON.stringify(b, null, 2);
    const layer = drawer("Diagnostic bundle", "Content-free. Review it before you attach it to an issue.", `<div class="panel">${kv([["Includes", b.includes.map(esc).join("<br>")], ["Excludes", b.excludes.map(esc).join("<br>")], ["Size", bytes(json.length)]])}</div>
      <div class="code"><pre>${esc(json.slice(0, 80000))}</pre></div><div class="row-btns"><button class="btn pri" id="diag-dl">${icon("download", "sm")} Download JSON</button><button class="btn" id="diag-cp">${icon("copy", "sm")} Copy</button></div>`);
    $("#diag-cp", layer).onclick = () => copy(json, "Bundle copied");
    $("#diag-dl", layer).onclick = () => { const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([json], { type: "application/json" })), download: `harpo-diagnostics-${b.generated_at.slice(0, 19).replace(/[:T]/g, "-")}.json` }); a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); };
  };
}

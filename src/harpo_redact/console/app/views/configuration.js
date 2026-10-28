import { api } from "../core/api.js";
import { $, $$, esc, icon, copy } from "../core/dom.js";
import { head, panel, kv, seg, banner } from "../ui/kit.js";

const CRIT = new Set(["auth.enabled", "policy.unknown_fields", "policy.remote_mcp", "policy.override", "policy.egress_verification", "policy.unsupported_content", "server.allowed_hosts", "server.tls_certfile", "detection.slm.on_failure", "documents.images", "environment"]);
const val = (v) => (typeof v === "boolean" ? (v ? "on" : "off") : Array.isArray(v) ? esc(v.length ? v.map((x) => (typeof x === "object" ? x.name || x.id || "…" : x)).join(", ") : "—") : v && typeof v === "object" ? esc(Object.keys(v).length ? `${Object.keys(v).length} entries` : "—") : esc(v ?? "—"));

export default async function configuration(view, ctx) {
  if (!ctx.admin) return ctx.needAdmin(view, "The configuration studio");
  const eff = await api("/v1/config/effective");
  const A = await api("/v1/config/analysis").catch(() => null);
  const C = (ctx.cfg ||= { tab: "guided", text: eff.yaml, result: null });
  const section = (title, path, obj) => panel(title, kv(Object.entries(obj || {}).filter(([, v]) => !(v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length > 6)).map(([k, v]) => [k.replace(/_/g, " "), val(v), CRIT.has(`${path}${k}`)])));
  const draw = () => {
    const c = eff.config;
    view.innerHTML = `${head("Configuration", "The running configuration, and a studio to stage and validate changes. Key hashes and registry contents stay masked.", seg("cfg-tab", [["guided", "Guided"], ["yaml", "YAML"]], C.tab), "VAULT")}
      ${banner("info", "<b>Staged only.</b> The gateway reads its configuration at start. Nothing here is saved or applied: validate, review the diff, then export the file and restart.")}
      ${C.tab === "guided" ? `${analysis(A)}<div class="grid g3 mt">${section("Environment & server", "server.", { environment: c.environment, ...c.server })}${section("Policy", "policy.", c.policy)}${section("Documents", "documents.", c.documents)}
        ${section("NER", "detection.ner.", c.detection?.ner)}${section("Local SLM", "detection.slm.", c.detection?.slm)}${section("Access", "auth.", { enabled: c.auth?.enabled, keys: c.auth?.keys })}
        ${panel("Upstreams", kv((c.upstreams || []).map((u) => [u.name, `${esc(u.style)} · ${esc(u.base_url)}`])))}${section("Logging", "logging.", c.logging)}${section("Detection", "detection.", { phone_regions: c.detection?.phone_regions, encoded_max_depth: c.detection?.encoded_max_depth })}</div>`
      : `<div class="grid g-main mt">${panel("Staged configuration", `<div class="cfg inset"><div class="gutter" id="gut"></div><textarea id="cfg-text" spellcheck="false" aria-label="Staged YAML"></textarea></div>
          <div class="pf"><button class="btn pri" id="cfg-val">${icon("list-checks", "sm")} Validate</button><button class="btn" id="cfg-reset">${icon("history", "sm")} Reset to running</button><button class="btn" id="cfg-copy">${icon("copy", "sm")} Copy</button><a class="btn" id="cfg-export" download="gateway.staged.yaml">${icon("download", "sm")} Export</a></div>`, { r: "masked values mean unchanged" })}
        <div>${panel("Validation", `<div class="pb" id="cfg-res"></div>`)}${panel("Diff against running", '<div id="cfg-diff"></div>', { cls: "mt" })}</div></div>`}`;
    $("#cfg-tab").onclick = (e) => { const b = e.target.closest("button"); if (b) { C.tab = b.dataset.v; draw(); } };
    for (const b of $$("[data-setting]", view)) b.onclick = () => {
      C.tab = "yaml"; draw();
      const ta = $("#cfg-text"), leaf = b.dataset.setting.split(".").pop().replace(/\[.*$/, "");
      const at = ta.value.search(new RegExp(`^\\s*${leaf}:`, "m"));
      if (at >= 0) { ta.focus(); ta.setSelectionRange(at, ta.value.indexOf("\n", at)); }
    };
    if (C.tab !== "yaml") return;
    const ta = $("#cfg-text"), gut = $("#gut");
    ta.value = C.text;
    const errLines = new Set((C.result?.errors || []).map((e) => e.line).filter(Boolean));
    const lines = () => { gut.innerHTML = ta.value.split("\n").map((_, i) => (errLines.has(i + 1) ? `<span class="err">${i + 1}</span>` : i + 1)).join("\n"); };
    const exportLink = () => { const a = $("#cfg-export"); if (a.dataset.url) URL.revokeObjectURL(a.dataset.url); a.dataset.url = URL.createObjectURL(new Blob([ta.value], { type: "text/yaml" })); a.href = a.dataset.url; };
    lines(); exportLink();
    ta.oninput = () => { C.text = ta.value; lines(); exportLink(); };
    ta.onscroll = () => { gut.scrollTop = ta.scrollTop; };
    $("#cfg-reset").onclick = () => { C.text = eff.yaml; C.result = null; draw(); };
    $("#cfg-copy").onclick = () => copy(ta.value, "Staged configuration copied");
    $("#cfg-val").onclick = async () => { C.result = await api("/v1/config/validate", { method: "POST", body: { yaml: ta.value } }); draw(); };
    const r = C.result;
    $("#cfg-res").innerHTML = !r ? '<p class="t3">Validate to check the staged file against the gateway\'s schema and production guards.</p>'
      : r.valid ? `<p><span class="st ok">valid</span> <span class="t3">· not saved</span></p>${r.problems.length ? `<div class="mt">${banner("warn", `<b>Production guards would refuse to start:</b><br>${r.problems.map(esc).join("<br>")}`)}</div>` : '<p class="t3 mt-s">Passes the production guards.</p>'}`
      : `<p><span class="st bad">${r.errors.length} error${r.errors.length === 1 ? "" : "s"}</span></p><div class="errlist mt-s">${r.errors.map((e) => `<button data-line="${e.line || ""}"><code>${e.line ? `line ${e.line}` : "—"}</code><span><span class="mono t2">${esc(e.path || "file")}</span> ${esc(e.message)}</span></button>`).join("")}</div>`;
    for (const b of $$("[data-line]", view)) b.onclick = () => { const n = +b.dataset.line; if (!n) return; const all = ta.value.split("\n"); const start = all.slice(0, n - 1).join("\n").length + (n > 1 ? 1 : 0); ta.focus(); ta.setSelectionRange(start, start + (all[n - 1] || "").length); };
    const diff = r?.diff;
    $("#cfg-diff").innerHTML = !r?.valid ? '<p class="pb t3">A diff appears after a successful validation.</p>' : !diff ? '<p class="pb t3">No changes from the running configuration.</p>'
      : `<div class="code inset diff"><pre>${diff.split("\n").map((l) => `<span class="${l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : l.startsWith("@@") || l.startsWith("+++") || l.startsWith("---") ? "hdr" : ""}">${esc(l)}</span>`).join("\n")}</pre></div>`;
  };
  draw();
}

const LEVEL = { required: "Required", recommended: "Recommended", info: "Informational" };
const show = (v) => (v == null ? "unset" : typeof v === "object" ? JSON.stringify(v) : String(v));
function analysis(A) {
  if (!A) return "";
  const c = A.counts;
  return `<section class="panel mt"><div class="ph"><h3>Security analysis</h3><div class="r">${Object.entries(c).map(([k, n]) => `<span class="lvl ${k}">${n} ${LEVEL[k].toLowerCase()}</span>`).join("")}</div></div>
    ${A.findings.length ? `<div class="findings">${A.findings.map((f) => `<div class="finding"><span class="lvl ${f.level}">${LEVEL[f.level].toUpperCase()}</span>
      <div><b>${esc(f.title)}</b><p>${esc(f.detail)}</p><div class="set"><button class="linkish" data-setting="${esc(f.setting)}" title="Open in the YAML editor">${esc(f.setting)}</button> · <em>${esc(show(f.current))}</em>${f.suggested != null ? ` → ${esc(show(f.suggested))}` : ""}</div></div>
      ${f.invariant ? `<a class="tag" href="#/guarantees">${esc(f.invariant)}</a>` : "<span></span>"}</div>`).join("")}</div>` : '<p class="pb t3">No findings: every checked setting is at its hardened value.</p>'}</section>`;
}

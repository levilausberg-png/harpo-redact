import { esc, fmt, icon } from "../core/dom.js";
import { head, panel, kv, mx, table, st } from "../ui/kit.js";
import { $ } from "../core/dom.js";

const val = (v) => (typeof v === "boolean" ? (v ? "on" : "off") : Array.isArray(v) ? (v.length ? esc(v.join(", ")) : "—") : v && typeof v === "object" ? esc(JSON.stringify(v)) : esc(v ?? "—"));
const generic = (obj) => kv(Object.entries(obj || {}).map(([k, v]) => [k.replace(/_/g, " "), val(v)]));

export default async function detection(view, ctx) {
  if (!ctx.admin) return ctx.needAdmin(view, "Detection settings");
  const d = ctx.system?.detection || (ctx.system = await (await import("../core/api.js")).api("/v1/system")).detection;
  const n = d.ner, s = d.slm;
  view.innerHTML = `${head("Detection", "Each layer, what it is configured to do, and whether it is deterministic or probabilistic.", `<span class="tag det">deterministic</span><span class="tag prob">probabilistic</span><span class="tag ver">verified output</span>`, "MASK")}
    <div class="grid g3">
      ${panel("Normalization", mx([{ icon: "binary", kind: "det", n: "Unicode", d: "NFKC, full-width and Arabic-Indic digits, invisible characters removed", s: st("ok", "on") }, { icon: "languages", kind: "det", n: "Look-alike letters", d: "Cyrillic and Greek folded inside mixed-script words", s: st("ok", "on") }, { icon: "split", kind: "det", n: "Shadow views", d: "values split over lines, spelled out, spaced, leetspeak emails", s: st("ok", "on") }, { icon: "layers", kind: "det", n: "Encoded data", d: `base64 and escapes, ${d.encoded_max_depth} levels deep`, s: st("ok", "on") }]))}
      ${panel("Identifiers & patterns", `${generic(d.identifiers)}${kv([["phone regions", val(d.phone_regions)]])}`, { r: '<span class="tag det">deterministic</span>' })}
      ${panel("Secrets", `${kv([["gitleaks-derived rules", fmt(d.secret_rules)]])}${generic(d.secrets)}`, { r: '<span class="tag det">deterministic</span>' })}
    </div>
    <div class="grid g2 mt">
      ${panel("Named entities (NER)", `${kv([["enabled", val(n.enabled)], ["English and fallback model", `<span class="mono">${esc(n.model)}</span>`], ["other languages", esc(n.other_languages)], ["propagate names", val(n.propagate)], ["name rules", val(n.name_rules)]])}<div id="ner-models"></div><div class="pf">Labels: ${Object.entries(n.labels).map(([k, v]) => `<span class="mono">${esc(k)}→${esc(v)}</span>`).join(" · ")}</div>`, { r: '<span class="tag prob">probabilistic</span>' })}
      ${panel("Local SLM", kv([["enabled", val(s.enabled)], ["model", `<span class="mono">${esc(s.model)}</span>`], ["endpoint", `<span class="mono">${esc(s.endpoint)}</span>`], ["timeout", `${fmt(s.timeout_ms)} ms`], ["on failure", esc(s.on_failure), true], ["concurrency", fmt(s.max_concurrency)], ["input budget", `${fmt(s.max_input_chars)} chars`], ["model digest pinned", s.digest_pinned ? st("ok", "yes") : st("warn", "no")], ["health", s.enabled ? (s.reachable === "ok" ? st("ok", "reachable") : st("bad", s.reachable || "unknown")) : '<span class="t3">not configured</span>']])
        + '<div class="pf">The SLM is untrusted: it can only add findings, each verified against the text; it can never approve egress (INV-03).</div>', { r: '<span class="tag prob">probabilistic</span>' })}
    </div>
    ${panel("Protected registry", kv(Object.entries(d.registry).map(([k, v]) => [k.replace(/_/g, " "), typeof v === "number" ? `${fmt(v)} entries (contents hidden)` : val(v)])), { cls: "mt", r: "your own terms and patterns" })}
    ${d.library ? panel("Detection library", `<p class="pol-lib-sub">Every detector, under the kind of data it protects. Switch the ones marked live on the <a href="#/policy">Policy</a> page; the others say where they are set.</p>
      <div class="lib-grid">${d.library.groups.map((g) => `<div class="pol-group"><div class="pol-gl">${esc(g.name)}</div>${mx(g.families.map((f) => ({
        icon: f.method === "model" ? "bot" : "scan-search", kind: f.method === "model" ? "prob" : "det", n: f.title,
        d: `${esc(f.detail)}<br><span class="mono t3">${esc(f.setting || (f.locked ? "always on" : ""))}</span>`,
        s: (f.locked || "").startsWith("Credentials") ? st("ok", "always on") : f.enabled ? st("ok", f.live ? "on · live" : "on") : st("warn", "off"),
      })))}</div>`).join("")}</div>`, { cls: "mt", r: `${d.library.groups.reduce((n, g) => n + g.families.filter((f) => f.enabled).length, 0)} of ${d.library.groups.reduce((n, g) => n + g.families.length, 0)} on` }) : ""}`;
  table($("#ner-models"), { rows: n.models, cols: [{ k: "name", l: "Model", f: (m) => `<span class="mono">${esc(m.name)}</span>` }, { k: "version", l: "Version", f: (m) => `<span class="mono t2">${esc(m.version || "missing")}</span>` }, { k: "license", l: "Licence", f: (m) => esc(m.license || "—") }] });
}
